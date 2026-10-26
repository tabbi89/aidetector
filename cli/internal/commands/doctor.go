package commands

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"runpentests/cli/internal/api"
	"runpentests/cli/internal/config"
)

// `doctor` answers "can this machine run a scan?" without claiming a run,
// creating a scan or sending anything to a target: the server is asked who it
// is and what it can do, Docker is asked what it has. Each problem comes with
// the one command that fixes it.

// Check statuses.
const (
	checkOK   = "ok"
	checkWarn = "warn" // the run works, but less than asked or with a caveat
	checkFail = "fail" // a run would fail or be refused
	checkSkip = "skip" // this check could not be made here
)

// readinessCheck is one line of a readiness report, stable for --json.
type readinessCheck struct {
	Name   string `json:"name"`
	Status string `json:"status"`
	Detail string `json:"detail"`
	// Fix is the one command (or step) that resolves a warn or fail.
	Fix string `json:"fix,omitempty"`
}

type readiness struct {
	checks []readinessCheck
}

func (r *readiness) add(name, status, detail, fix string) {
	r.checks = append(r.checks, readinessCheck{Name: name, Status: status, Detail: detail, Fix: fix})
}

func (r *readiness) failed() bool {
	for _, c := range r.checks {
		if c.Status == checkFail {
			return true
		}
	}
	return false
}

// print writes the report as a table; a fix goes under its line.
func (r *readiness) print(e *Env) {
	marks := map[string]string{checkOK: "✓", checkWarn: "!", checkFail: "✗", checkSkip: "-"}
	for _, c := range r.checks {
		e.printf("%s %-22s %s\n", marks[c.Status], c.Name, c.Detail)
		if c.Fix != "" && c.Status != checkOK {
			e.printf("  %-22s fix: %s\n", "", c.Fix)
		}
	}
}

func cmdDoctor(ctx context.Context, e *Env, args []string) int {
	fs := e.newFlagSet("doctor")
	asJSON := fs.Bool("json", false, "print the checks as JSON")
	image := fs.String("image", defaultRunnerImage(e), "runner image to check")
	var networks dockerNetworks
	fs.Var(&networks, "docker-network", "docker network a run will join; repeat or comma-separate for several")
	zap := fs.Bool("zap", false, "also check what ZAP needs (its image, a shared network)")
	kali := fs.Bool("kali", false, "also check what Kali needs (its image, a shared network)")
	pos, err := parse(fs, args)
	if err != nil {
		return e.parseFailed("doctor", fs, err)
	}
	if len(pos) != 0 {
		return e.usage("doctor takes no arguments")
	}
	r := &readiness{}
	r.add("cli", checkOK, Version, "")
	checkServer(ctx, e, r)
	checkDocker(ctx, e, r, *image, networks, *zap, *kali)

	ready := !r.failed()
	if *asJSON {
		printJSON(e, map[string]any{"ready": ready, "checks": r.checks})
	} else {
		r.print(e)
		if ready {
			e.printf("ready: this machine can run a scan\n")
		} else {
			e.printf("not ready: fix the ✗ lines first\n")
		}
	}
	if !ready {
		return ExitUsage
	}
	return ExitOK
}

// checkServer adds the profile, reachability, key and capability checks.
// It returns the client and capabilities when they are usable (nil otherwise).
func checkServer(ctx context.Context, e *Env, r *readiness) (*api.Client, *api.Capabilities) {
	path, err := e.configPath()
	if err != nil {
		r.add("profile", checkFail, err.Error(), "runpentests login")
		return nil, nil
	}
	cfg, err := config.Load(path, e.Getenv)
	if err != nil {
		r.add("profile", checkFail, err.Error(), "runpentests login")
		return nil, nil
	}
	if cfg.Server == "" {
		r.add("server", checkFail, "no server configured", "runpentests login")
		return nil, nil
	}
	c, err := e.client()
	if err != nil {
		r.add("server", checkFail, err.Error(), "runpentests login")
		return nil, nil
	}
	var apiErr *api.APIError
	if err := c.Ready(ctx); err != nil {
		if errors.As(err, &apiErr) && apiErr.Status == 401 {
			// It answered: it is the key it refused.
			r.add("server", checkOK, cfg.Server+" answers", "")
			r.add("api key", checkFail, "missing or rejected", "runpentests login")
			return nil, nil
		}
		r.add("server", checkFail, fmt.Sprintf("%s does not answer: %v", cfg.Server, err),
			"check the URL with `runpentests status`, or start the server")
		return nil, nil
	}
	r.add("server", checkOK, cfg.Server+" answers", "")
	caps, capsErr := c.Capabilities(ctx)
	switch {
	case capsErr == nil:
		r.add("api key", checkOK, "accepted", "")
	case errors.As(capsErr, &apiErr) && apiErr.Status == 401:
		r.add("api key", checkFail, "missing or rejected", "runpentests login")
		return nil, nil
	default:
		// An older server without /capabilities: prove the key another way.
		if _, err := c.ListScans(ctx); err != nil {
			if errors.As(err, &apiErr) && apiErr.Status == 401 {
				r.add("api key", checkFail, "missing or rejected", "runpentests login")
				return nil, nil
			}
			r.add("api key", checkFail, err.Error(), "runpentests login")
			return nil, nil
		}
		r.add("api key", checkOK, "accepted", "")
		r.add("capabilities", checkWarn, "unknown: the server has no /capabilities (it is older than this CLI)",
			"upgrade the server to see which passes it can run")
		return c, nil
	}
	var off []string
	for field, pc := range caps.Passes {
		if !pc.Available {
			if name, ok := passFlag(field); ok {
				off = append(off, "--"+name)
			}
		}
	}
	if len(off) > 0 {
		r.add("capabilities", checkWarn, fmt.Sprintf("%d pass(es) unavailable here: %s",
			len(off), printableList(off)), "`runpentests status` says why each is off")
	} else {
		r.add("capabilities", checkOK, "every pass this CLI knows is available", "")
	}
	if caps.Levels == nil {
		r.add("levels", checkWarn, "the server does not publish its level policy (older server)", "")
	}
	return c, &caps
}

// checkDocker adds the daemon, image and network checks a local run needs.
func checkDocker(ctx context.Context, e *Env, r *readiness, image string, networks []string, zap, kali bool) {
	if e.DockerVersion == nil {
		r.add("docker", checkSkip, "not checked by this build", "")
		return
	}
	version, err := e.DockerVersion(ctx)
	if err != nil {
		r.add("docker", checkFail, err.Error(), "install Docker and start it (every run starts its runner in a container)")
		return
	}
	r.add("docker", checkOK, "daemon "+version, "")
	checkImage(ctx, e, r, "runner image", image, imageBuildHint(image))
	if image == runnerImageDefault && e.ImageRevision != nil && Version != "dev" {
		if rev, err := e.ImageRevision(ctx, image); err == nil {
			clean := func(v string) string { return strings.TrimSuffix(v, "-dirty") }
			if clean(rev) != clean(Version) {
				r.add("runner version", checkWarn, fmt.Sprintf("image is %s, CLI is %s", printable(versionLabel(rev)), Version),
					"make runner-image")
			}
		}
	}
	for _, n := range networks {
		if n == "host" || n == "bridge" || n == "none" || strings.HasPrefix(n, "container:") {
			r.add("network "+n, checkOK, "built-in", "")
			continue
		}
		if e.NetworkExists == nil {
			r.add("network "+n, checkSkip, "not checked by this build", "")
			continue
		}
		ok, err := e.NetworkExists(ctx, n)
		switch {
		case err != nil:
			r.add("network "+n, checkFail, err.Error(), "")
		case !ok:
			r.add("network "+n, checkFail, "does not exist", "docker network create "+n)
		default:
			r.add("network "+n, checkOK, "exists", "")
		}
	}
	if zap || kali {
		if len(networks) == 0 {
			r.add("adjunct network", checkFail, "ZAP and Kali need a shared Docker network with the runner",
				"docker network create runpentests, then pass --docker-network runpentests")
		}
		if zap {
			checkImage(ctx, e, r, "zap image", envOr(e, "RUNPENTESTS_ZAP_IMAGE", zapImageDefault), "")
		}
		if kali {
			checkImage(ctx, e, r, "kali image", envOr(e, "RUNPENTESTS_KALI_IMAGE", kaliImageDefault),
				"make kali-image")
		}
	}
}

func checkImage(ctx context.Context, e *Env, r *readiness, name, image, build string) {
	if e.ImageExists == nil {
		r.add(name, checkSkip, image+": not checked by this build", "")
		return
	}
	present, err := e.ImageExists(ctx, image)
	switch {
	case err != nil:
		r.add(name, checkFail, err.Error(), "")
	case present:
		r.add(name, checkOK, image, "")
	case build != "":
		r.add(name, checkFail, image+" is not on this machine", build)
	default:
		r.add(name, checkFail, image+" is not on this machine", "docker pull "+image)
	}
}

func imageBuildHint(image string) string {
	if image == runnerImageDefault {
		return "make runner-image (in the runpentests repository)"
	}
	return ""
}

func versionLabel(s string) string {
	if s == "" {
		return "unversioned"
	}
	return s
}
