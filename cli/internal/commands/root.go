package commands

import (
	"context"
	"os"
	"strings"

	"runpentests/cli/internal/api"
	"runpentests/cli/internal/config"
	"runpentests/cli/internal/project"
)

const helpText = `runpentests — drive a runpentests server from the terminal.

usage: runpentests [URL] [DIR] [flags]      scan an API; the everyday form
       runpentests <command> [flags]

  URL        scan this API: reuses the scan for it, or creates one, and
             finds the spec (--spec, runpentests.yml, the project, or the target)
  DIR        also read the code in DIR — the scan runs on this machine and
             findings point at file:line
  (nothing)  run what ./runpentests.yml describes

  common flags: --authorized --fail-on SEV --verified-only --new-only
                --output table|json|github|junit
                --level quick|standard|deep   how hard to look (default quick)
                --writes   allow tests that change target data
                --ai   use AI passes (spends tokens)
                --spec FILE --new --config FILE --no-config

  a scan ID may be the full UUID or its first 4+ hex characters; where an ID
  is optional, runpentests.yml's scan: (or target:) picks the scan

commands:
  init       [URL] [--spec FILE] [--force] [--yes]   write runpentests.yml
  login      --server URL [--profile NAME] [--key-stdin | --no-key] [--insecure-http]
  logout     remove the current profile
  status
  profile    list | use NAME | rm NAME [--yes]
  scans      list [--json] [--target URL] [--full-ids] | show [ID] | rm ID --yes
  scan       create --target URL --spec FILE
  cred       add ID --name N --role R --auth-type T [--header-name H] [--secret-stdin]
             | list [ID] [--json] | rm ID NAME|ID --yes
  run        ID [--authorized] [--level L] [--writes] [--ai] [pass flags]
             [--fail-on SEV] [--new-only] [--output table|json|github|junit]
  wait       ID [--timeout D] [--fail-on SEV] [--new-only] [--output FMT]
             attach to the current run
  cancel     ID
  findings   [ID] [--check KEY] [--min-severity SEV] [--verified] [--json]
             show [ID] FINDING [--json]   one finding by ID or fingerprint prefix
             dismiss|confirm|reopen [SCAN] FINDING...   triage findings
  cost       [ID] [--json]               AI spend: total, per model, per phase
  coverage   [ID] [--json] [--untested]  what the latest run did to each endpoint
  diff       [ID] [--json]
  runs       [ID] [--limit N] [--json]   run history: status, passes, gaps
             trace [ID] [RUN] [--check KEY] [--identity N] [--status S] [--seq N]
  report     [ID] --format pdf|html|pentest|sarif|json [-o FILE]
             (default file: runpentests-<id8>.<ext>)
  completion bash|zsh|fish   print a shell completion script
  mcp        serve the setup tools and guides to a coding agent (MCP over stdio)
  version    print the build's version

profiles:
  RUNPENTESTS_PROFILE picks a saved profile (default: the file's current one);
  RUNPENTESTS_SERVER / RUNPENTESTS_API_KEY still override the selected profile.
  'runpentests profile list' shows every saved profile and never a key.

exit codes: 0 clean, 1 findings reached --fail-on, 2 usage/auth, 3 failed, 4 timeout

Secrets are never taken from flags (they land in shell history and ps): use a
prompt, --key-stdin / --secret-stdin, or RUNPENTESTS_API_KEY.

run 'runpentests help <command>' for a command's flags and examples
`

// Run executes one command line and returns the process exit code.
func Run(ctx context.Context, args []string, env Env) int {
	env.Getenv = config.CompatibleEnv(env.Getenv)
	e := &env
	api.UserAgent = "aidetector-cli/" + Version + " runpentests-cli/" + Version
	if len(args) == 0 {
		// Inside a project, a bare `runpentests` runs what its file describes.
		if wd, err := e.workdir(); err == nil {
			if f, _ := project.Find(wd); f != nil {
				return cmdTarget(ctx, e, nil)
			}
		}
		e.printf("%s", helpText)
		return ExitUsage
	}
	switch args[0] {
	case "-h", "--help":
		e.printf("%s", helpText)
		return ExitOK
	case "help":
		if len(args) > 1 {
			return commandHelp(ctx, e, args[1])
		}
		e.printf("%s", helpText)
		return ExitOK
	case "version", "--version", "-v":
		// Before the target-form fallback: -v and --version are not flags of it.
		return cmdVersion(e, args[1:])
	}
	rest := args[1:]
	switch args[0] {
	case "init":
		return cmdInit(ctx, e, rest)
	case "login":
		return cmdLogin(ctx, e, rest)
	case "logout":
		return cmdLogout(e, rest)
	case "status":
		return cmdStatus(ctx, e, rest)
	case "profile":
		return cmdProfile(e, rest)
	case "scans":
		return cmdScans(ctx, e, rest)
	case "scan":
		return cmdScan(ctx, e, rest)
	case "cred":
		return cmdCred(ctx, e, rest)
	case "run":
		return cmdRun(ctx, e, rest)
	case "wait":
		return cmdWait(ctx, e, rest)
	case "cancel":
		return cmdCancel(ctx, e, rest)
	case "findings":
		return cmdFindings(ctx, e, rest)
	case "cost":
		return cmdCost(ctx, e, rest)
	case "coverage":
		return cmdCoverage(ctx, e, rest)
	case "diff":
		return cmdDiff(ctx, e, rest)
	case "runs":
		return cmdRuns(ctx, e, rest)
	case "report":
		return cmdReport(ctx, e, rest)
	case "completion":
		return cmdCompletion(ctx, e, rest)
	case "mcp":
		return cmdMCP(ctx, e, rest)
	}
	if strings.HasPrefix(args[0], "-") || project.LooksLikeTarget(args[0]) || isDir(args[0]) {
		return cmdTarget(ctx, e, args)
	}
	return e.usage("unknown command %q (try `runpentests help`)", args[0])
}

func cmdLogin(ctx context.Context, e *Env, args []string) int {
	fs := e.newFlagSet("login")
	server := fs.String("server", config.DefaultServer, "server URL")
	profile := fs.String("profile", "", "save this profile (default: the current one)")
	keyStdin := fs.Bool("key-stdin", false, "read the API key from stdin (one line)")
	noKey := fs.Bool("no-key", false, "the server runs with auth off (local dev)")
	insecure := fs.Bool("insecure-http", false, "allow http:// to a non-loopback host")
	if _, err := parse(fs, args); err != nil {
		return e.parseFailed("login", fs, err)
	}
	norm, err := config.NormalizeServer(*server, *insecure)
	if err != nil {
		return e.usage("%v", err)
	}
	path, err := e.configPath()
	if err != nil {
		return e.usage("%v", err)
	}
	st, err := config.ReadStore(path)
	if err != nil {
		return e.usage("%v", err)
	}
	// Save where the user asked: --profile, else the profile this invocation
	// selects, else "default".
	name := *profile
	if name == "" {
		name = e.Getenv("RUNPENTESTS_PROFILE")
	}
	if name == "" {
		name = st.Current
	}
	if name == "" {
		name = "default"
	}
	if !config.ValidProfileName(name) {
		return e.usage("%q is not a profile name: use 1-32 lowercase letters, digits, '-' or '_', starting with a letter or digit", name)
	}

	key := ""
	switch {
	case *noKey:
	case *keyStdin:
		if key, err = e.readLine(); err != nil || key == "" {
			return e.usage("--key-stdin: expected the API key on one line of stdin")
		}
	case e.IsTTY():
		if key, err = e.ReadSecret("API key (input hidden): "); err != nil || key == "" {
			return e.usage("no API key entered")
		}
	default:
		return e.usage("no terminal to prompt on: pass --key-stdin or --no-key")
	}

	// Prove the server answers and the key works before saving anything.
	candidate := &Env{Stdin: e.Stdin, Stdout: e.Stdout, Stderr: e.Stderr, Getenv: func(k string) string {
		switch k {
		case "RUNPENTESTS_SERVER":
			return norm
		case "RUNPENTESTS_API_KEY":
			return key
		case "RUNPENTESTS_INSECURE_HTTP":
			if *insecure {
				return "1"
			}
		}
		return ""
	}, ConfigPath: path + ".none"}
	c, err := candidate.client()
	if err != nil {
		return e.usage("%v", err)
	}
	if err := c.Ready(ctx); err != nil {
		return e.exitFor(err)
	}
	if _, err := c.ListScans(ctx); err != nil {
		return e.exitFor(err)
	}
	if st.Profiles == nil {
		st.Profiles = map[string]config.Profile{}
	}
	st.Profiles[name] = config.Profile{Server: norm, APIKey: key}
	st.Current = name
	if err := config.Save(path, st); err != nil {
		return e.usage("could not save config: %v", err)
	}
	if name == "default" {
		e.printf("logged in to %s\n", norm)
	} else {
		e.printf("logged in to %s (profile %s)\n", norm, name)
	}
	return ExitOK
}

func cmdLogout(e *Env, args []string) int {
	fs := e.newFlagSet("logout")
	if _, err := parse(fs, args); err != nil {
		return e.parseFailed("logout", fs, err)
	}
	path, err := e.configPath()
	if err != nil {
		return e.usage("%v", err)
	}
	st, err := config.ReadStore(path)
	if err != nil {
		return e.usage("%v", err)
	}
	name := st.Current
	if name == "" {
		e.printf("no profile is current\n")
		return ExitOK
	}
	delete(st.Profiles, name)
	st.Current = ""
	// The last profile gone means no file at all, as logout always did.
	if len(st.Profiles) == 0 {
		if err := config.Clear(path); err != nil {
			return e.usage("%v", err)
		}
	} else if err := config.Save(path, st); err != nil {
		return e.usage("%v", err)
	}
	e.printf("logged out of profile %s\n", name)
	return ExitOK
}

func cmdStatus(ctx context.Context, e *Env, args []string) int {
	fs := e.newFlagSet("status")
	if _, err := parse(fs, args); err != nil {
		return e.parseFailed("status", fs, err)
	}
	e.printf("cli: %s\n", Version)
	path, err := e.configPath()
	if err != nil {
		return e.usage("%v", err)
	}
	cfg, err := config.Load(path, e.Getenv)
	if err != nil {
		return e.usage("%v", err)
	}
	profile := cfg.Profile
	if profile == "" {
		profile = "none"
	}
	fromEnv := ""
	if cfg.ProfileFromEnv {
		fromEnv = " (from RUNPENTESTS_PROFILE)"
	}
	e.printf("profile: %s%s\n", profile, fromEnv)
	if cfg.Server == "" {
		return e.usage("not logged in")
	}
	// Never print the key — only whether one is set.
	keyState := "none (auth off?)"
	if cfg.APIKey != "" {
		keyState = "set"
	}
	serverNote := ""
	if cfg.ServerFromEnv {
		serverNote = " (from RUNPENTESTS_SERVER)"
	}
	e.printf("server: %s%s\napi key: %s\n", cfg.Server, serverNote, keyState)
	c, err := e.client()
	if err != nil {
		return e.usage("%v", err)
	}
	if err := c.Ready(ctx); err != nil {
		e.printf("reachable: no\n")
		return e.exitFor(err)
	}
	e.printf("reachable: yes\n")
	caps, err := c.Capabilities(ctx)
	if err != nil {
		// Advisory: an older server without the route must not fail status.
		e.printf("passes: unknown (server has no /capabilities)\n")
		return ExitOK
	}
	printCapabilities(e, caps)
	return ExitOK
}

// severityRank orders severities for --fail-on and --min-severity.
var severityRank = map[string]int{"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}

func validSeverity(s string) bool {
	_, ok := severityRank[strings.ToLower(s)]
	return ok
}

func isDir(p string) bool {
	info, err := os.Stat(p)
	return err == nil && info.IsDir()
}
