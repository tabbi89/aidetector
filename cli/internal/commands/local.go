package commands

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"time"

	"runpentests/cli/internal/api"
	"runpentests/cli/internal/config"
	"runpentests/cli/internal/project"
)

// A local run sends the scan traffic from THIS machine: the CLI claims the run
// from the server (which answers the authorization gate, the target guard and
// the request budget, and issues a per-run token), then starts the engine in a
// throwaway container here and lets it upload its results.
//
// What crosses which boundary, deliberately:
//   - credential secrets are collected here and handed to the container on
//     stdin — never argv or its environment (ps / docker inspect show both) and
//     never to the server;
//   - the container gets the per-run token, not the API key;
//   - the container is read-only, capability-less and resource-limited.

const runnerImageDefault = "runpentests-runner:latest"

// Default images for the adjunct siblings the CLI starts for a local run. ZAP's
// is published; Kali's is built from services/kali (there is no public tag), so
// a missing one is a build hint, never a pull. Override with RUNPENTESTS_*_IMAGE.
const (
	zapImageDefault  = "ghcr.io/zaproxy/zaproxy:stable"
	kaliImageDefault = "runpentests-kali:latest"
	zapPort          = "8090"
	kaliPort         = "8091"
)

func defaultRunnerImage(e *Env) string {
	if v := e.Getenv("RUNPENTESTS_RUNNER_IMAGE"); v != "" {
		return v
	}
	if RunnerImage != "" {
		return RunnerImage
	}
	return runnerImageDefault
}

// dockerNetworks is --docker-network: repeat the flag or separate names with
// commas to join several networks — a target stack's internal network to reach
// it, and one with egress to reach the server.
type dockerNetworks []string

func (n *dockerNetworks) String() string { return strings.Join(*n, ",") }

func (n *dockerNetworks) Set(value string) error {
	if strings.TrimSpace(value) == "" {
		return nil
	}
	for _, name := range strings.Split(value, ",") {
		name = strings.TrimSpace(name)
		if name == "" {
			return fmt.Errorf("empty network name in %q", value)
		}
		if !slices.Contains(*n, name) {
			*n = append(*n, name)
		}
	}
	// Docker refuses these modes beside any other network; say so now, before
	// the run is claimed, rather than as a failed run.
	if len(*n) > 1 {
		for _, name := range *n {
			if name == "host" || name == "none" || strings.HasPrefix(name, "container:") {
				return fmt.Errorf("network mode %q cannot be combined with another network", name)
			}
		}
	}
	return nil
}

type localFlags struct {
	image        string
	networks     []string
	secretsFile  string
	runnerServer string
	// Absolute path to the project to mount read-only for whitebox analysis;
	// empty disables it. Mounted at the fixed container path /src.
	source string
	// Secrets already found on this machine, by identity name — the target
	// form reads them from the environment variables runpentests.yml names.
	secrets map[string]string
	// The project file's schema block, if any. Only a local run reads it.
	schema *project.Schema
	// schemaDir is the project file's directory: sslrootcert resolves against it.
	schemaDir string
	// schemaCA is the host path of the CA certificate mounted read-only into
	// the runner at schemaCAMount; empty when no CA was configured.
	schemaCA string
	// onClaim, when set, learns the run number the server issued, so a caller
	// that gates later gates this run and not whichever is newest by then.
	onClaim func(runNumber int)
	// resourceIDs are known ids for path parameters. They go to the runner on
	// stdin only: never argv, the environment or the server.
	resourceIDs map[string]string
}

// sourceMount is the fixed path the project is mounted at inside the runner.
const sourceMount = "/src"

// schemaCAMount is where a CA certificate is mounted inside the runner.
const schemaCAMount = "/run/runpentests/schema-ca.pem"

func runLocal(ctx context.Context, e *Env, c *api.Client, id string, body map[string]any,
	lf localFlags, gp gatePolicy, output string) int {
	if e.Docker == nil {
		return e.usage("this build cannot start containers")
	}
	// Before the claim: a run the server opened and this machine cannot start
	// would only end as a failed run.
	build := ""
	if lf.image == runnerImageDefault {
		build = "build it with `make runner-image` in the runpentests repository"
	}
	if code := ensureImage(ctx, e, lf.image, build); code != ExitOK {
		return code
	}
	if lf.image == runnerImageDefault {
		warnStaleRunner(ctx, e, lf.image)
	}
	if code := previewResourceIDs(ctx, e, c, id, lf.resourceIDs); code != ExitOK {
		return code
	}
	// ZAP and Kali need a shared network and their images: check before the
	// claim, from the server's own level expansion, so a missing prerequisite
	// is a usage error, not a failed run.
	if code := preclaimAdjuncts(ctx, e, lf, expectedPasses(body, advisoryCapabilities(ctx, c))); code != ExitOK {
		return code
	}
	// The claim is where the server says yes or no: authorization, the target
	// guard, premium, and which passes a local run may use.
	claim, err := c.ClaimLocalRun(ctx, id, body)
	if err != nil {
		var apiErr *api.APIError
		if errors.As(err, &apiErr) && apiErr.Status == 404 {
			e.errorf("hint: local runs are off on this server — set LOCAL_RUNNER_ENABLED=true " +
				"on the API\n")
		}
		code := e.exitFor(err)
		ownershipHint(ctx, e, c, id, err)
		return code
	}
	runID, token := claim.Str("run_id"), claim.Str("token")
	if runID == "" || token == "" {
		return e.exitFor(fmt.Errorf("the server's claim was incomplete"))
	}
	if lf.onClaim != nil {
		lf.onClaim(claim.Int("run_number"))
	}

	// From here a run is open on the server: every exit path must close it.
	// Each call gets its own deadline, from when it is made. One shared from the
	// claim ran out while the container was still scanning, so every run longer
	// than 30s ended with "context deadline exceeded" after uploading fine.
	bounded := func() (context.Context, context.CancelFunc) {
		return context.WithTimeout(context.Background(), serverCallTimeout)
	}
	abandon := func(reason string) {
		bg, stop := bounded()
		defer stop()
		_ = c.FailLocalRun(bg, runID, token, reason, false)
	}

	secrets, err := collectSecrets(e, claim, lf.secretsFile, lf.secrets)
	if err != nil {
		abandon("the CLI could not collect credential secrets")
		return e.usage("%v", err)
	}
	containerSource := ""
	if lf.source != "" {
		containerSource = sourceMount
	}
	var schemaBlock map[string]any
	if lf.schema != nil {
		schemaBlock, lf.schemaCA, err = collectSchema(e, lf.schema, lf.schemaDir)
		if err != nil {
			abandon("the CLI could not read the schema configuration")
			return e.usage("%v", err)
		}
	}
	adjuncts, stopSiblings, code := startAdjunctSiblings(ctx, e, lf, runID, claimedPasses(claim, body))
	if code != ExitOK {
		abandon("the CLI could not start the adjunct tool containers")
		return code
	}
	// Idempotent: the siblings are torn down as soon as the runner container
	// exits (below), and the defer is the safety net for an earlier return.
	stoppedSiblings := false
	stopSiblingsOnce := func() {
		if !stoppedSiblings {
			stoppedSiblings = true
			stopSiblings()
		}
	}
	defer stopSiblingsOnce()
	cfg, err := runnerConfig(
		c.Base(), claim, secrets, lf.runnerServer, containerSource, schemaBlock, adjuncts, lf.resourceIDs,
	)
	if err != nil {
		abandon("the CLI could not build the runner configuration")
		return e.usage("%v", err)
	}

	name := "runpentests-run-" + shortID(runID)
	e.errorf("running locally in %s (the scan traffic comes from this machine)\n", lf.image)
	var stdout bytes.Buffer
	runErr := e.Docker(ctx, name, dockerArgs(name, lf), bytes.NewReader(cfg), &stdout, e.Stderr)
	// The scan traffic is done; the siblings are no longer needed, so stop them
	// now rather than holding them through any AI-analysis wait below.
	stopSiblingsOnce()

	// The container finishes the run itself. A run that asked for AI passes is
	// then analysed on the service before it completes: wait for that. If the
	// container died first, close the run so the scan is not left locked until
	// the reaper notices.
	bg, stop := bounded()
	defer stop()
	scan, getErr := c.GetScan(bg, id)
	if getErr == nil && scan.Status == "running" && newestRunAnalysing(bg, c, id) {
		e.errorf("results uploaded; the service is running the AI analysis\n")
		var interrupted bool
		scan, interrupted, getErr = waitForAnalysis(ctx, e, c, id)
		if interrupted {
			e.errorf("interrupted; the analysis continues on the service (runpentests wait %s)\n", shortID(id))
			return ExitFailed
		}
		if getErr == nil && scan.Status == "running" {
			e.errorf("the AI analysis is still running on the service (runpentests wait %s)\n", shortID(id))
			return ExitTimeout
		}
	}
	if getErr == nil && scan.Status == "running" {
		reason := "the local runner exited before finishing"
		if runErr != nil {
			reason += ": " + oneLine(runErr.Error())
		}
		// Fresh: an analysis wait above can outlast the first deadline.
		closing, stopClosing := bounded()
		defer stopClosing()
		_ = c.FailLocalRun(closing, runID, token, reason, ctx.Err() != nil)
		scan, getErr = c.GetScan(closing, id)
	}
	if getErr != nil {
		return e.exitFor(getErr)
	}
	if scan.Status != "completed" {
		reason := ""
		if scan.FailureReason != nil && *scan.FailureReason != "" {
			reason = ": " + printable(*scan.FailureReason)
		}
		if runErr != nil && reason == "" {
			reason = ": " + oneLine(runErr.Error())
		}
		e.errorf("local run ended %s%s\n", scan.Status, reason)
		return ExitFailed
	}
	if !gp.active() {
		return ExitOK
	}
	// Gate this run, by number: not whichever run is newest by now.
	return gate(ctx, e, c, id, claim.Int("run_number"), gp, output)
}

// ensureImage makes sure a container image the run needs is on this machine,
// before the run is claimed. build, when set, says how to build an image that is
// never pulled: the default runner name is local, and pulling it would fetch
// whatever a registry happens to publish under that name.
func ensureImage(ctx context.Context, e *Env, image, build string) int {
	if e.ImageExists == nil {
		return ExitOK
	}
	present, err := e.ImageExists(ctx, image)
	if err != nil {
		return e.usage("%v", err)
	}
	if present {
		return ExitOK
	}
	if build != "" {
		return e.usage("the image %s is not on this machine: %s", image, build)
	}
	if !e.IsTTY() || e.PullImage == nil {
		return e.usage("the image %s is not on this machine: run `docker pull %s` first", image, image)
	}
	e.errorf("The image %s is not on this machine. Pull it now? [y/N] ", image)
	line, _ := e.readLine()
	if strings.ToLower(strings.TrimSpace(line)) != "y" {
		return e.usage("%s was not pulled; nothing was run", image)
	}
	if err := e.PullImage(ctx, image, e.Stderr); err != nil {
		return e.usage("could not pull %s: %v", image, err)
	}
	return ExitOK
}

// warnStaleRunner says when the locally built runner image is not this CLI's
// version. The image is built by hand and nothing rebuilds it, so after a pull
// the CLI moves on and the runner quietly stays behind: the run then lacks
// whatever changed in between (a request trace, a fix) and nothing says why.
// A warning, not a refusal — an older runner still runs a valid scan.
func warnStaleRunner(ctx context.Context, e *Env, image string) {
	if e.ImageRevision == nil || Version == "dev" {
		return
	}
	rev, err := e.ImageRevision(ctx, image)
	// Uncommitted edits on either side are not a different version: a CLI
	// rebuilt mid-edit would otherwise call a matching image stale.
	clean := func(v string) string { return strings.TrimSuffix(v, "-dirty") }
	if err != nil || clean(rev) == clean(Version) {
		return
	}
	built := "was built before runner images were versioned"
	if rev != "" {
		built = "was built from " + printable(rev)
	}
	e.errorf("warning: the runner image %s %s, and this CLI is %s — the run may lack recent "+
		"fixes; rebuild it with `make runner-image` in the runpentests repository\n", image, built, Version)
}

// serverCallTimeout bounds each server call a local run makes once the run is
// open (closing it, reading its result), measured from that call. A variable so
// a test can show a slow run no longer outlives it.
var serverCallTimeout = 30 * time.Second

// analysisTimeout bounds the wait for the service's post-upload AI passes: both
// at the server's AI timeout, plus margin. The reaper settles a lost analysis.
const analysisTimeout = 15 * time.Minute

// newestRunAnalysing reports whether the scan's newest run has uploaded its
// results and is in the service's AI analysis.
func newestRunAnalysing(ctx context.Context, c *api.Client, id string) bool {
	runs, err := c.Runs(ctx, id, 1)
	return err == nil && len(runs) > 0 && runs[0].Status == "analysing"
}

// waitForAnalysis polls until the scan leaves "running". interrupted is true
// when the user stopped the wait (the analysis carries on without the CLI).
func waitForAnalysis(ctx context.Context, e *Env, c *api.Client, id string) (api.Scan, bool, error) {
	now := e.Now
	if now == nil {
		now = time.Now
	}
	deadline := now().Add(analysisTimeout)
	for {
		scan, err := c.GetScan(ctx, id)
		if ctx.Err() != nil {
			return scan, true, nil
		}
		if err != nil || scan.Status != "running" || now().After(deadline) {
			return scan, false, err
		}
		select {
		case <-ctx.Done():
			return scan, true, nil
		case <-time.After(e.poll()):
		}
	}
}

// dockerArgs is the runner container's command line. It never contains a
// secret: those go on stdin.
func dockerArgs(name string, lf localFlags) []string {
	args := []string{
		"run", "--rm", "-i", "--name", name,
		"--read-only", "--tmpfs", "/tmp",
		"--cap-drop", "ALL", "--security-opt", "no-new-privileges",
		"--user", "65534:65534",
		"--memory", "1g", "--pids-limit", "512",
		// Lets a container reach a service on this machine (a local API under
		// test, or a server on localhost) on Linux as well as Docker Desktop.
		"--add-host", "host.docker.internal:host-gateway",
	}
	// One --network per network: Docker 25+ attaches a container to all of
	// them at create.
	for _, network := range lf.networks {
		args = append(args, "--network", network)
	}
	if lf.source != "" {
		// Read-only: the runner indexes the project for whitebox evidence, it
		// never writes to it. :ro is belt; --read-only on the container is braces.
		args = append(args, "-v", lf.source+":"+sourceMount+":ro")
	}
	if lf.schemaCA != "" {
		// The CA is a file, not a secret; the password stays on stdin. --mount,
		// not -v: a host path may itself contain ':'.
		args = append(args, "--mount",
			"type=bind,src="+lf.schemaCA+",dst="+schemaCAMount+",readonly")
	}
	return append(args, lf.image, "python", "-m", "app.runner")
}

// collectSchema builds the runner's schema block from the project file. The
// password is read here and travels only on stdin; without one the block has no
// password key and the runner reports password_missing.
func collectSchema(e *Env, s *project.Schema, dir string) (map[string]any, string, error) {
	password := e.Getenv(s.PasswordEnv)
	if password == "" && e.IsTTY() {
		typed, err := e.ReadSecret(fmt.Sprintf(
			"Password for schema user %q (input hidden; empty to skip): ", s.Username))
		if err != nil {
			return nil, "", err
		}
		password = typed
	}
	if password == "" {
		// The block still goes to the runner, without a password, so the run
		// records the schema as unavailable (password_missing) instead of the
		// web reading a skipped read as "no schema configured".
		e.errorf("warning: no password in $%s; this run records the schema as unavailable\n", s.PasswordEnv)
	}
	host := s.Host
	if config.IsLoopback(host) {
		// Same reachability rule the target URL follows: localhost inside the
		// container would be the container itself.
		host = "host.docker.internal"
	}
	caPath := ""
	if s.SSLRootCert != "" {
		caPath = s.SSLRootCert
		if !filepath.IsAbs(caPath) {
			caPath = filepath.Join(dir, caPath)
		}
		info, err := os.Stat(caPath)
		if err != nil {
			return nil, "", fmt.Errorf("schema: sslrootcert %q: %w", s.SSLRootCert, err)
		}
		if !info.Mode().IsRegular() {
			return nil, "", fmt.Errorf("schema: sslrootcert %q is not a regular file", s.SSLRootCert)
		}
		if info.Mode().Perm()&0o004 == 0 {
			// The runner is an unprivileged user (65534) inside the container;
			// a CA it cannot read would surface only as "unavailable".
			return nil, "", fmt.Errorf("schema: sslrootcert %q must be readable by others "+
				"(a CA is public; chmod o+r it) — the runner reads it as an unprivileged user", s.SSLRootCert)
		}
	}
	block := map[string]any{
		"host":     host,
		"port":     s.Port,
		"database": s.Database,
		"username": s.Username,
		"sslmode":  s.SSLMode,
		"tables":   s.TableRefs(),
	}
	if password != "" {
		block["password"] = password
	}
	if caPath != "" {
		block["sslrootcert"] = schemaCAMount
	}
	return block, caPath, nil
}

// runnerConfig is what the container reads from stdin: the claim exactly as the
// server sent it (with hosts it must reach rewritten), the secrets, a version.
func runnerConfig(serverBase string, claim api.LocalClaim, secrets map[string]map[string]string, override, containerSource string, schema map[string]any, adjuncts map[string]any, resourceIDs map[string]string) ([]byte, error) {
	server := override
	if server == "" {
		server = rewriteLoopback(serverBase)
	}
	run := map[string]any{}
	for k, v := range claim {
		run[k] = v
	}
	run["target_base_url"] = rewriteLoopback(claim.Str("target_base_url"))
	cfg := map[string]any{
		"server":         server,
		"run":            run,
		"secrets":        secrets,
		"runner_version": "runpentests-cli",
	}
	if containerSource != "" {
		// Where the runner finds the mounted project inside the container.
		cfg["source_dir"] = containerSource
	}
	if schema != nil {
		cfg["schema"] = schema
	}
	if len(resourceIDs) > 0 {
		// Beside the claim, not inside it: the claim is what the server issued,
		// and these never went through the server.
		cfg["predefined_resource_ids"] = resourceIDs
	}
	if len(adjuncts) > 0 {
		// The sibling URLs the runner points ZAP/Kali at, and their per-run API
		// keys (on stdin, never the claim or argv of the runner).
		cfg["adjuncts"] = adjuncts
	}
	return json.Marshal(cfg)
}

// randomHex returns n bytes of randomness, hex-encoded, for a per-run tool key.
func randomHex(n int) string {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return ""
	}
	return hex.EncodeToString(b)
}

// startAdjunctSiblings starts the ZAP/Kali containers a local run asked for, on
// the same Docker network(s) as the runner so it can reach them by name. It
// returns the runner's `adjuncts` config, a teardown func, and an exit code.
// The tools must share a user-defined network with the runner: Docker's default
// bridge has no name resolution, so --docker-network is required here.
func startAdjunctSiblings(
	ctx context.Context, e *Env, lf localFlags, runID string, passes map[string]bool,
) (map[string]any, func(), int) {
	wantZap, wantKali := passes["zap"], passes["kali"]
	if !wantZap && !wantKali {
		return nil, func() {}, ExitOK
	}
	if len(lf.networks) == 0 {
		return nil, func() {}, e.usage(
			"ZAP and Kali run in their own containers and the runner reaches them by " +
				"name, which needs a shared Docker network: pass --docker-network")
	}
	if e.StartContainer == nil {
		return nil, func() {}, e.usage("this build cannot start adjunct containers")
	}
	netArgs := []string{}
	for _, n := range lf.networks {
		netArgs = append(netArgs, "--network", n)
	}
	started := []string{}
	cleanup := func() {
		for _, n := range started {
			if e.StopContainer != nil {
				e.StopContainer(n)
			}
		}
	}
	fail := func(format string, a ...any) (map[string]any, func(), int) {
		cleanup()
		return nil, func() {}, e.usage(format, a...)
	}
	adjuncts := map[string]any{}

	if wantZap {
		image := envOr(e, "RUNPENTESTS_ZAP_IMAGE", zapImageDefault)
		if code := ensureImage(ctx, e, image, ""); code != ExitOK {
			cleanup()
			return nil, func() {}, code
		}
		key := randomHex(16)
		name := "runpentests-zap-" + shortID(runID)
		args := append(append([]string{"--rm"}, netArgs...), image,
			"zap.sh", "-daemon", "-host", "0.0.0.0", "-port", zapPort,
			"-config", "api.key="+key,
			"-config", "api.addrs.addr.name=.*",
			"-config", "api.addrs.addr.regex=true")
		if err := e.StartContainer(ctx, name, args); err != nil {
			return fail("could not start ZAP: %v", err)
		}
		started = append(started, name)
		adjuncts["zap"] = map[string]any{
			"base_url": "http://" + name + ":" + zapPort, "api_key": key,
		}
		e.errorf("started ZAP (%s) on the scan network\n", name)
	}

	if wantKali {
		image := envOr(e, "RUNPENTESTS_KALI_IMAGE", kaliImageDefault)
		// Built locally from services/kali, never pulled.
		if code := ensureImage(ctx, e, image,
			"build it with `make kali-image` in the runpentests repository"); code != ExitOK {
			cleanup()
			return nil, func() {}, code
		}
		key := randomHex(16)
		name := "runpentests-kali-" + shortID(runID)
		args := append(append([]string{"--rm", "--env", "KALI_API_KEY=" + key}, netArgs...), image)
		if err := e.StartContainer(ctx, name, args); err != nil {
			return fail("could not start Kali: %v", err)
		}
		started = append(started, name)
		adjuncts["kali"] = map[string]any{
			"base_url": "http://" + name + ":" + kaliPort, "api_key": key,
		}
		e.errorf("started Kali (%s) on the scan network\n", name)
	}
	return adjuncts, cleanup, ExitOK
}

// advisoryCapabilities is GET /capabilities, or nil when the server cannot say.
func advisoryCapabilities(ctx context.Context, c *api.Client) *api.Capabilities {
	caps, err := c.Capabilities(ctx)
	if err != nil {
		return nil
	}
	return &caps
}

// expectedPasses predicts which run flags a body turns on: its explicit flags
// plus the server's expansion of its level and ai switch. With no level table
// from the server, only the explicit flags are known.
func expectedPasses(body map[string]any, caps *api.Capabilities) map[string]bool {
	out := map[string]bool{}
	for k, v := range body {
		if b, ok := v.(bool); ok && b && k != "authorized" {
			out[k] = true
		}
	}
	level, _ := body["level"].(string)
	ai, _ := body["ai"].(bool)
	if caps == nil || caps.Levels == nil || (level == "" && !ai) {
		return out
	}
	if level == "" {
		level = "quick"
	}
	exp, ok := caps.Levels[level]
	if !ok {
		return out
	}
	if body["level"] != nil {
		for _, p := range exp.Passes {
			out[p] = true
		}
	}
	if ai {
		for _, p := range exp.AI {
			out[p] = true
		}
		if out["mutate"] {
			for _, p := range exp.AIWithWrites {
				out[p] = true
			}
		}
	}
	return out
}

// claimedPasses is what the server actually turned on (the claim's options,
// after it expanded the level), plus the body's explicit flags.
func claimedPasses(claim api.LocalClaim, body map[string]any) map[string]bool {
	out := expectedPasses(body, nil)
	if opts, ok := claim["options"].(map[string]any); ok {
		for k, v := range opts {
			if b, ok := v.(bool); ok && b {
				out[k] = true
			}
		}
	}
	return out
}

// preclaimAdjuncts checks what ZAP and Kali need before a run is claimed.
func preclaimAdjuncts(ctx context.Context, e *Env, lf localFlags, passes map[string]bool) int {
	if !passes["zap"] && !passes["kali"] {
		return ExitOK
	}
	if len(lf.networks) == 0 {
		return e.usage("ZAP and Kali run in their own containers and the runner reaches them by " +
			"name, which needs a shared Docker network: pass --docker-network (create one with " +
			"`docker network create runpentests`)")
	}
	if passes["zap"] {
		if code := ensureImage(ctx, e, envOr(e, "RUNPENTESTS_ZAP_IMAGE", zapImageDefault), ""); code != ExitOK {
			return code
		}
	}
	if passes["kali"] {
		if code := ensureImage(ctx, e, envOr(e, "RUNPENTESTS_KALI_IMAGE", kaliImageDefault),
			"build it with `make kali-image` in the runpentests repository"); code != ExitOK {
			return code
		}
	}
	return ExitOK
}

// envOr returns the environment value for key, or def when unset.
func envOr(e *Env, key, def string) string {
	if v := e.Getenv(key); v != "" {
		return v
	}
	return def
}

// rewriteLoopback makes a URL that names this machine reachable from inside a
// container, where "localhost" would mean the container itself.
func rewriteLoopback(raw string) string {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" || !config.IsLoopback(u.Hostname()) {
		return raw
	}
	host := "host.docker.internal"
	if p := u.Port(); p != "" {
		host = net.JoinHostPort(host, p)
	}
	u.Host = host
	return u.String()
}

var nonAlnum = regexp.MustCompile(`[^A-Z0-9]+`)

func envName(role string) string {
	return strings.Trim(nonAlnum.ReplaceAllString(strings.ToUpper(role), "_"), "_")
}

// collectSecrets finds each credential's secret on this machine, keyed by
// identity name so two identities that share a role keep distinct secrets: a
// 0600 secrets file (name first, role only when unique), then a secret the
// caller already found by identity name (runpentests.yml's secret_env), then
// RUNPENTESTS_SECRET_<NAME> (and RUNPENTESTS_REFRESH_SECRET_<NAME>), with the role
// variable as a fallback only when no other identity has that role, then a
// hidden prompt. An identity with none is dropped by the runner with a named
// reason rather than failing the run.
func collectSecrets(e *Env, claim api.LocalClaim, file string, byName map[string]string) (map[string]map[string]string, error) {
	fromFile := map[string]any{}
	if file != "" {
		if err := config.CheckPrivateFile(file); err != nil {
			return nil, err
		}
		data, err := os.ReadFile(file)
		if err != nil {
			return nil, fmt.Errorf("cannot read --secrets-file: %w", err)
		}
		if err := json.Unmarshal(data, &fromFile); err != nil {
			return nil, fmt.Errorf("--secrets-file is not a JSON object of name -> secret: %w", err)
		}
	}
	// A role is a usable key only when exactly one identity carries it, and a
	// name always owns its key: a role key is a legacy fallback only when no
	// identity is named after it, or `alice(role=user)` would receive the
	// secret belonging to the identity actually named `user`. The file keys
	// are raw names; environment keys are normalised (`user-a` and `user_a`
	// are both USER_A), so ownership of an environment key is decided on the
	// normalised form.
	roleCount := map[string]int{}
	roleNames := map[string][]string{}
	names := map[string]bool{}
	envRoleCount := map[string]int{}
	envRoleNames := map[string][]string{}
	envNameOwners := map[string][]string{}
	for _, cred := range claim.Credentials() {
		role, _ := cred["role"].(string)
		name, _ := cred["name"].(string)
		if authType, _ := cred["auth_type"].(string); authType == "none" || role == "" {
			continue
		}
		if name == "" {
			name = role
		}
		names[name] = true
		roleCount[role]++
		roleNames[role] = append(roleNames[role], name)
		envRoleCount[envName(role)]++
		envRoleNames[envName(role)] = append(envRoleNames[envName(role)], name)
		envNameOwners[envName(name)] = append(envNameOwners[envName(name)], name)
	}
	// fromEnv reads one environment key for one identity, refusing a key that
	// would stand for more than one identity rather than handing all of them
	// the same secret. The runner receives a name-keyed map and cannot undo it.
	fromEnv := func(prefix, name, role string) (string, error) {
		nameKey, roleKey := envName(name), envName(role)
		if nameKey != "" {
			v := e.Getenv(prefix + nameKey)
			if v != "" && len(envNameOwners[nameKey]) > 1 {
				return "", collidingNameError(prefix+nameKey, envNameOwners[nameKey])
			}
			if v != "" {
				return v, nil
			}
		}
		if roleKey == "" || roleKey == nameKey {
			return "", nil
		}
		v := e.Getenv(prefix + roleKey)
		if v == "" || len(envNameOwners[roleKey]) > 0 {
			// Unset, or it is another identity's own name key.
			return "", nil
		}
		if envRoleCount[roleKey] > 1 {
			return "", sharedRoleError(prefix+roleKey, role, envRoleNames[roleKey])
		}
		return v, nil
	}
	out := map[string]map[string]string{}
	for _, cred := range claim.Credentials() {
		role, _ := cred["role"].(string)
		name, _ := cred["name"].(string)
		if authType, _ := cred["auth_type"].(string); authType == "none" || role == "" {
			continue
		}
		if name == "" {
			name = role
		}
		if roleCount[role] > 1 && !names[role] {
			// A role key cannot stand for one identity among several, even when
			// a name key is also present: the user must not think it applies.
			if _, ok := fromFile[role]; ok {
				return nil, sharedRoleError("--secrets-file", role, roleNames[role])
			}
		}
		for _, prefix := range []string{"RUNPENTESTS_SECRET_", "RUNPENTESTS_REFRESH_SECRET_"} {
			roleKey := envName(role)
			if envRoleCount[roleKey] > 1 && len(envNameOwners[roleKey]) == 0 && e.Getenv(prefix+roleKey) != "" {
				return nil, sharedRoleError(prefix+roleKey, role, envRoleNames[roleKey])
			}
		}
		entry := map[string]string{}
		raw, ok := fromFile[name]
		if !ok && roleCount[role] == 1 && !names[role] {
			raw = fromFile[role]
		}
		switch v := raw.(type) {
		case string:
			entry["secret"] = v
		case map[string]any:
			entry["secret"], _ = v["secret"].(string)
			entry["refresh_secret"], _ = v["refresh_secret"].(string)
		}
		if entry["secret"] == "" {
			entry["secret"] = byName[name]
		}
		var err error
		if entry["secret"] == "" {
			if entry["secret"], err = fromEnv("RUNPENTESTS_SECRET_", name, role); err != nil {
				return nil, err
			}
		}
		if entry["refresh_secret"] == "" {
			if entry["refresh_secret"], err = fromEnv("RUNPENTESTS_REFRESH_SECRET_", name, role); err != nil {
				return nil, err
			}
		}
		if entry["secret"] == "" && e.IsTTY() {
			s, err := e.ReadSecret(fmt.Sprintf("Secret for the %q identity %q (input hidden; empty to skip): ", role, name))
			if err != nil {
				return nil, err
			}
			entry["secret"] = s
		}
		if entry["secret"] == "" {
			e.errorf("warning: no secret for the %q identity; it will be dropped from this run\n", role)
			continue
		}
		out[name] = entry
	}
	return out, nil
}

// collidingNameError refuses an environment key that two distinct identity
// names normalise to (`user-a` and `user_a` are both USER_A): either reading
// would hand both identities one secret.
func collidingNameError(source string, names []string) error {
	quoted := make([]string, len(names))
	for i, n := range names {
		quoted[i] = fmt.Sprintf("%q", n)
	}
	return fmt.Errorf("%s: identities %s share this environment key; key their secrets by exact name in --secrets-file or runpentests.yml secret_env instead",
		source, strings.Join(quoted, ", "))
}

// sharedRoleError refuses a role-keyed secret when more than one identity has
// that role: picking one for all of them would silently give them the same
// secret (or the wrong one), so the user must key by identity name.
func sharedRoleError(source, role string, names []string) error {
	quoted := make([]string, len(names))
	for i, n := range names {
		quoted[i] = fmt.Sprintf("%q", n)
	}
	return fmt.Errorf("%s: the %q role is shared by identities %s; key the secret by name instead of by role",
		source, role, strings.Join(quoted, ", "))
}

// resolveSourceDir validates a --source path and returns it absolute, so the
// docker -v bind mount is unambiguous whatever the caller's working directory.
func resolveSourceDir(path string) (string, error) {
	abs, err := filepath.Abs(path)
	if err != nil {
		return "", fmt.Errorf("--source: %w", err)
	}
	info, err := os.Stat(abs)
	if err != nil {
		return "", fmt.Errorf("--source %q: %w", path, err)
	}
	if !info.IsDir() {
		return "", fmt.Errorf("--source %q is not a directory", path)
	}
	return abs, nil
}

func shortID(id string) string {
	if len(id) > 8 {
		return id[:8]
	}
	return id
}

func oneLine(s string) string {
	s = strings.Join(strings.Fields(s), " ")
	if len(s) > 300 {
		s = s[:300]
	}
	return s
}
