// Package commands implements the runpentests subcommands.
//
// Everything a command touches outside its arguments — the terminal, stdin,
// the environment, the clock, the config file — goes through Env, so the tests
// drive a command against an httptest server with no real TTY and no sleeping.
package commands

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"
	"time"

	"golang.org/x/term"

	"runpentests/cli/internal/api"
	"runpentests/cli/internal/config"
)

// Exit codes. A CI step gates on these, so they are part of the interface.
const (
	ExitOK       = 0 // ran, and nothing at or above the threshold
	ExitFindings = 1 // ran, and findings reached --fail-on
	ExitUsage    = 2 // bad flags, bad config, refused, or the server said no
	ExitFailed   = 3 // the scan failed or was cancelled, or the server is unreachable
	ExitTimeout  = 4 // --wait gave up
	// ExitIncomplete: ran, no finding reached --fail-on, but an opted-in
	// quality policy (--require-complete, --min-exercised) failed. Findings
	// (1) win over it: a finding the run did make stands.
	ExitIncomplete = 5
)

// Env is everything a command needs from the outside world.
type Env struct {
	Stdin      io.Reader
	Stdout     io.Writer
	Stderr     io.Writer
	IsTTY      func() bool
	ReadSecret func(prompt string) (string, error)
	Getenv     func(string) string
	// ConfigPath overrides the default config location (tests, --config).
	ConfigPath string
	// PollInterval is how often --wait asks the server. Zero means 2s.
	PollInterval time.Duration
	Now          func() time.Time
	// Docker starts the local-runner container: args follow `docker`, stdin
	// carries the runner's config and secrets (never argv or the environment),
	// and name lets a cancel stop it gracefully. Tests replace it.
	Docker func(ctx context.Context, name string, args []string, stdin io.Reader, stdout, stderr io.Writer) error
	// StartContainer runs a detached sibling container (ZAP, Kali) for the
	// adjunct phase and returns once it is created; StopContainer removes it.
	// Tests replace both.
	StartContainer func(ctx context.Context, name string, args []string) error
	StopContainer  func(name string)
	// ImageExists and PullImage check for, and fetch, a container image before
	// a run is claimed. Nil skips the check (tests).
	ImageExists func(ctx context.Context, image string) (bool, error)
	PullImage   func(ctx context.Context, image string, stderr io.Writer) error
	// ImageRevision reads the commit a local image was built from (its
	// org.opencontainers.image.revision label; "" when it has none). Nil skips
	// the stale-runner check (tests).
	ImageRevision func(ctx context.Context, image string) (string, error)
	// DockerVersion reports the Docker daemon's version (an error when docker
	// is missing or the daemon is down); NetworkExists whether a named network
	// exists. `doctor` uses both; nil skips the check (tests).
	DockerVersion func(ctx context.Context) (string, error)
	NetworkExists func(ctx context.Context, name string) (bool, error)
	// GitHead returns a directory's current commit for the run record; nil
	// asks git. Tests replace it.
	GitHead func(dir string) string
	// Dir overrides the working directory the target form looks for
	// runpentests.yml in (tests); empty means the process's own.
	Dir string

	in  *bufio.Reader
	cmd string // the command being parsed, for "needs a scan ID" errors
}

// DefaultEnv is the real terminal, environment and clock.
func DefaultEnv() Env {
	return Env{
		Stdin:  os.Stdin,
		Stdout: os.Stdout,
		Stderr: os.Stderr,
		IsTTY:  func() bool { return term.IsTerminal(int(os.Stdin.Fd())) },
		ReadSecret: func(prompt string) (string, error) {
			fmt.Fprint(os.Stderr, prompt)
			b, err := term.ReadPassword(int(os.Stdin.Fd()))
			fmt.Fprintln(os.Stderr)
			return string(b), err
		},
		Getenv:         os.Getenv,
		Now:            time.Now,
		Docker:         runDocker,
		ImageExists:    dockerImageExists,
		PullImage:      dockerPull,
		ImageRevision:  dockerImageRevision,
		StartContainer: startContainer,
		StopContainer:  stopContainer,
		DockerVersion:  dockerVersion,
		NetworkExists:  dockerNetworkExists,
	}
}

// dockerVersion asks the daemon its version: proof it is installed and up.
func dockerVersion(ctx context.Context) (string, error) {
	bin, err := exec.LookPath("docker")
	if err != nil {
		return "", errors.New("docker was not found on PATH")
	}
	var stderr bytes.Buffer
	cmd := exec.CommandContext(ctx, bin, "version", "--format", "{{.Server.Version}}")
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil {
		return "", fmt.Errorf("the Docker daemon did not answer: %s", strings.TrimSpace(stderr.String()))
	}
	return strings.TrimSpace(string(out)), nil
}

// dockerNetworkExists reports whether a network exists. The built-in modes
// (host, bridge, none) always do.
func dockerNetworkExists(ctx context.Context, name string) (bool, error) {
	bin, err := exec.LookPath("docker")
	if err != nil {
		return false, errors.New("docker was not found on PATH")
	}
	var stderr bytes.Buffer
	cmd := exec.CommandContext(ctx, bin, "network", "inspect", "--format", "{{.Name}}", name)
	cmd.Stdout, cmd.Stderr = io.Discard, &stderr
	if err := cmd.Run(); err != nil {
		if strings.Contains(strings.ToLower(stderr.String()), "not found") {
			return false, nil
		}
		return false, fmt.Errorf("docker could not be asked about network %s: %s", name, strings.TrimSpace(stderr.String()))
	}
	return true, nil
}

// startContainer runs `docker run --detach …`; args follow `run`.
func startContainer(ctx context.Context, name string, args []string) error {
	bin, err := exec.LookPath("docker")
	if err != nil {
		return errors.New("docker was not found on PATH")
	}
	full := append([]string{"run", "--detach", "--name", name}, args...)
	var stderr bytes.Buffer
	cmd := exec.CommandContext(ctx, bin, full...)
	cmd.Stdout, cmd.Stderr = io.Discard, &stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("%v: %s", err, strings.TrimSpace(stderr.String()))
	}
	return nil
}

// stopContainer removes a sibling, best effort — teardown must never fail a run.
func stopContainer(name string) {
	bin, err := exec.LookPath("docker")
	if err != nil {
		return
	}
	_ = exec.Command(bin, "rm", "--force", name).Run()
}

// dockerImageExists reports whether image is present locally. An error means
// docker itself could not be asked (not installed, daemon down).
func dockerImageExists(ctx context.Context, image string) (bool, error) {
	bin, err := exec.LookPath("docker")
	if err != nil {
		return false, errors.New("docker was not found on PATH; every run starts its runner in a container")
	}
	var stderr bytes.Buffer
	cmd := exec.CommandContext(ctx, bin, "image", "inspect", "--format", "{{.Id}}", image)
	cmd.Stdout, cmd.Stderr = io.Discard, &stderr
	if err := cmd.Run(); err != nil {
		if strings.Contains(strings.ToLower(stderr.String()), "no such image") {
			return false, nil
		}
		return false, fmt.Errorf("docker could not be asked about %s: %s", image, strings.TrimSpace(stderr.String()))
	}
	return true, nil
}

// revisionLabel is the label `make runner-image` stamps with the checkout's
// version — the same string `make cli` builds into Version.
const revisionLabel = "org.opencontainers.image.revision"

// dockerImageRevision returns image's revision label, or "" when it has none.
func dockerImageRevision(ctx context.Context, image string) (string, error) {
	bin, err := exec.LookPath("docker")
	if err != nil {
		return "", err
	}
	out, err := exec.CommandContext(ctx, bin, "image", "inspect", "--format",
		`{{index .Config.Labels "`+revisionLabel+`"}}`, image).Output()
	if err != nil {
		return "", err
	}
	rev := strings.TrimSpace(string(out))
	if rev == "<no value>" {
		return "", nil
	}
	return rev, nil
}

// dockerPull fetches image, streaming docker's progress to stderr.
func dockerPull(ctx context.Context, image string, stderr io.Writer) error {
	bin, err := exec.LookPath("docker")
	if err != nil {
		return errors.New("docker was not found on PATH")
	}
	cmd := exec.CommandContext(ctx, bin, "pull", image)
	cmd.Stdout, cmd.Stderr = stderr, stderr
	return cmd.Run()
}

// runDocker runs `docker <args>`. On cancel it stops the container with SIGTERM
// so the runner can tell the server it was cancelled, rather than killing the
// client and orphaning the container.
func runDocker(ctx context.Context, name string, args []string, stdin io.Reader, stdout, stderr io.Writer) error {
	bin, err := exec.LookPath("docker")
	if err != nil {
		return errors.New("docker was not found on PATH; every run starts its runner in a container")
	}
	cmd := exec.CommandContext(ctx, bin, args...)
	cmd.Stdin, cmd.Stdout, cmd.Stderr = stdin, stdout, stderr
	cmd.Cancel = func() error {
		return exec.Command(bin, "stop", "-t", "15", name).Run()
	}
	cmd.WaitDelay = 25 * time.Second
	return cmd.Run()
}

func (e *Env) reader() *bufio.Reader {
	if e.in == nil {
		e.in = bufio.NewReader(e.Stdin)
	}
	return e.in
}

// readLine reads one line from stdin, without its newline.
func (e *Env) readLine() (string, error) {
	s, err := e.reader().ReadString('\n')
	if err != nil && !(errors.Is(err, io.EOF) && s != "") {
		return "", err
	}
	return strings.TrimRight(s, "\r\n"), nil
}

func (e *Env) printf(format string, a ...any) { fmt.Fprintf(e.Stdout, format, a...) }
func (e *Env) errorf(format string, a ...any) { fmt.Fprintf(e.Stderr, format, a...) }
func (e *Env) poll() time.Duration {
	if e.PollInterval > 0 {
		return e.PollInterval
	}
	return 2 * time.Second
}

// configPath is the config location: the test override wins, then
// RUNPENTESTS_CONFIG, then the user config directory.
func (e *Env) configPath() (string, error) {
	if e.ConfigPath != "" {
		return config.Path(e.ConfigPath)
	}
	if p := e.Getenv("RUNPENTESTS_CONFIG"); p != "" {
		return p, nil
	}
	return config.Path("")
}

// client builds an API client from the saved config and environment.
func (e *Env) client() (*api.Client, error) {
	path, err := e.configPath()
	if err != nil {
		return nil, err
	}
	cfg, err := config.Load(path, e.Getenv)
	if err != nil {
		return nil, err
	}
	if cfg.Server == "" {
		cfg.Server = config.DefaultServer
	}
	server, err := config.NormalizeServer(cfg.Server, e.Getenv("RUNPENTESTS_INSECURE_HTTP") == "1")
	if err != nil {
		return nil, err
	}
	return api.New(server, cfg.APIKey), nil
}

// newFlagSet builds a quiet flag set. The flag package would print its own
// usage dump (single-dash flags, guessed descriptions) and the parse error, so
// both are silenced: parseFailed reports errors and help.go prints the real
// usage.
func (e *Env) newFlagSet(name string) *flag.FlagSet {
	e.cmd = name
	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	fs.Usage = func() {}
	return fs
}

// parseFailed turns a flag parse error into an exit code. -h/--help is a
// request for the command's help, not an error; anything else is a usage
// error, printed once and without the whole flag list.
func (e *Env) parseFailed(cmd string, fs *flag.FlagSet, err error) int {
	if errors.Is(err, flag.ErrHelp) {
		return e.printCommandHelp(cmd, fs)
	}
	for old, now := range renamedPasses {
		if err.Error() == "flag provided but not defined: -"+old {
			e.errorf("error: --%s is now --%s\n", old, now)
			return ExitUsage
		}
	}
	e.errorf("error: %v\nrun 'runpentests help %s' for usage\n", err, cmd)
	return ExitUsage
}

// parse parses flags that may come before or after positional arguments
// (`run ID --wait` and `run --wait ID` both work), returning the positionals.
func parse(fs *flag.FlagSet, args []string) ([]string, error) {
	var positional []string
	for {
		if err := fs.Parse(args); err != nil {
			return nil, err
		}
		if fs.NArg() == 0 {
			return positional, nil
		}
		positional = append(positional, fs.Arg(0))
		args = fs.Args()[1:]
	}
}

// exitFor turns an error into an exit code and prints it. A 4xx answer means
// the request was refused (usage); a network or 5xx failure means the server
// could not be used (failed).
func (e *Env) exitFor(err error) int {
	var apiErr *api.APIError
	if errors.As(err, &apiErr) {
		switch {
		case apiErr.Status == 401:
			e.errorf("error: %v\nhint: the API key is missing or wrong — run `runpentests login`\n", err)
			return ExitUsage
		case (apiErr.Status == 404 && apiErr.Detail == "Not Found") || apiErr.Status == 405:
			// FastAPI's bare "Not Found" is an unknown route, not a missing
			// scan (those say "scan not found"): this CLI is newer than the server.
			e.errorf("error: %v\nhint: the server does not have this endpoint — it is probably "+
				"older than this CLI (%s); upgrade the server or use a matching CLI\n", err, Version)
			return ExitUsage
		case apiErr.Status >= 400 && apiErr.Status < 500:
			e.errorf("error: %v\n", err)
			return ExitUsage
		}
		e.errorf("error: %v\n", err)
		return ExitFailed
	}
	if errors.Is(err, context.Canceled) {
		e.errorf("interrupted\n")
		return ExitFailed
	}
	e.errorf("error: %v\n", err)
	return ExitFailed
}

// usage reports a usage error and returns ExitUsage.
func (e *Env) usage(format string, a ...any) int {
	e.errorf("error: "+format+"\n", a...)
	return ExitUsage
}
