package commands

import (
	"context"
	"encoding/xml"
	"errors"
	"flag"
	"fmt"
	"sort"
	"strings"
	"time"

	"runpentests/cli/internal/api"
)

// RunFlags maps each pass flag to the RunRequest field it sets. It is the
// single list the flags are built from, and the contract test compares its
// values with the server's RunRequest booleans: a flag the server grows must
// show up here or the build fails.
var RunFlags = map[string]string{
	// The flag is the product's word; the API field keeps its older name.
	"writes":          "mutate",
	"fuzz":            "fuzz",
	"premium":         "premium",
	"zap":             "zap",
	"kali":            "kali",
	"confirm":         "confirm",
	"testssl":         "testssl",
	"plan":            "plan",
	"adjudicate":      "adjudicate",
	"security-review": "security_review",
	"genai-payloads":  "genai_payloads",
	"adaptive":        "adaptive",
	"resource-refine": "resource_refine",
	// Heavy-lane bounded whitebox agent; only meaningful with --source.
	"agent": "agent",
	// The AI passes that fit --level; the server expands the level.
	"ai": "ai",
}

// renamedPasses are old pass names. Each pass has one name, so the old one is
// refused, but the error says what it is called now.
var renamedPasses = map[string]string{"mutate": "writes"}

// passField resolves a flag name to its RunRequest field.
func passField(name string) (string, bool) {
	field, ok := RunFlags[name]
	return field, ok
}

// PassHelp describes each pass for `runpentests help` and for the flag's own
// usage. A pass that saves time is never described as "enable the X pass": the
// cost to the target or the tokens is the part that matters.
var PassHelp = map[string]string{
	"writes":          "allow tests that change target data: write oracle, mass assignment, race, seeded BOLA, body-field fuzzing (restores/cleans up after itself)",
	"fuzz":            "schema fuzzing of request inputs",
	"premium":         "premium checks (needs entitlement)",
	"zap":             "OWASP ZAP active scan — slow, far more traffic than the request budget",
	"kali":            "Kali tools (ffuf, katana, arjun, nuclei) plus a discovery re-probe — slow",
	"confirm":         "confirm injection leads with sqlmap/dalfox/commix/tplmap — slow",
	"testssl":         "testssl.sh deep TLS audit of an HTTPS target — slow (up to 5 minutes)",
	"plan":            "AI: rank endpoints by risk before the engine runs (spends tokens)",
	"adjudicate":      "AI: review BOLA/BFLA/SSRF findings and set a verdict (spends tokens)",
	"security-review": "AI: security review of the scan (spends tokens)",
	"genai-payloads":  "AI: generate extra payloads (spends tokens)",
	"adaptive":        "AI: adaptive follow-up probing (spends tokens)",
	"resource-refine": "AI: refine resource id discovery (spends tokens)",
	"agent":           "bounded whitebox agent over --source code (local runs only)",
	"ai":              "AI passes that fit the level: risk plan, verdicts, security review (spends tokens)",
}

// RunRequestNotFlags are RunRequest fields that are deliberately not simple
// boolean flags here, each with its reason, so the contract test can tell
// "forgotten" from "decided".
var RunRequestNotFlags = map[string]string{
	"authorized":              "set by --authorized or the interactive prompt, never a pass",
	"seed":                    "--seed",
	"predefined_resource_ids": "--resource-ids / resource_ids: — sent to the runner on stdin, never in the request body",
	"adaptive_attempts":       "not exposed: bounded default",
	"resource_attempts":       "not exposed: bounded default",
	"requests_per_second":     "--rps",
	"checks":                  "--checks",
	"config_source":           "set from runpentests.yml by the target form, never a flag",
	"level":                   "--level",
}

// addPassFlags registers one boolean flag per run pass, built from RunFlags, so
// a pass the server grows cannot be missing from `run`.
func addPassFlags(fs *flag.FlagSet) map[string]*bool {
	passes := map[string]*bool{}
	for flagName := range RunFlags {
		passes[flagName] = fs.Bool(flagName, false, PassHelp[flagName])
	}
	return passes
}

// runLevels are the server's scan levels. Empty sends no level, which the
// server treats as quick; the server, never the CLI, expands a level into passes.
var runLevels = map[string]bool{"quick": true, "standard": true, "deep": true}

func validLevel(level string) bool { return runLevels[level] }

// Gate output formats. A table is for a person; the others feed CI.
const (
	outputTable  = "table"
	outputJSON   = "json"
	outputGitHub = "github"
	outputJUnit  = "junit"
)

// addOutputFlags registers the gate's output flags. --json is the older
// spelling of --output json, kept so existing pipelines do not change.
func addOutputFlags(fs *flag.FlagSet, jsonUsage string) (*bool, *string) {
	asJSON := fs.Bool("json", false, jsonUsage+"; same as --output json")
	output := fs.String("output", outputTable, "gate output: table | json | github | junit")
	return asJSON, output
}

// resolveOutput settles --output against --json. Both may be given only when
// they agree: `--json --output junit` is a typo, not a request.
func (e *Env) resolveOutput(fs *flag.FlagSet, asJSON bool, output string) (string, int) {
	format := strings.ToLower(strings.TrimSpace(output))
	if format == "" {
		format = outputTable
	}
	switch format {
	case outputTable, outputJSON, outputGitHub, outputJUnit:
	default:
		return "", e.usage("--output must be one of table, json, github, junit")
	}
	outputSet := false
	fs.Visit(func(f *flag.Flag) {
		if f.Name == "output" {
			outputSet = true
		}
	})
	if asJSON {
		if outputSet && format != outputJSON {
			return "", e.usage("--json is --output json; it conflicts with --output %s", format)
		}
		return outputJSON, ExitOK
	}
	return format, ExitOK
}

// runBody collects the pass flags, --level, --checks and --rps into a run
// request body. The caller adds "authorized" once the gate is answered.
func (e *Env) runBody(passes map[string]*bool, level, checks string, rps int) (map[string]any, int) {
	body := map[string]any{}
	for flagName, field := range RunFlags {
		if *passes[flagName] {
			body[field] = true
		}
	}
	if level != "" {
		if !validLevel(level) {
			return nil, e.usage("--level must be one of quick, standard, deep")
		}
		body["level"] = level
	}
	if checks != "" {
		var keys []string
		for _, k := range strings.Split(checks, ",") {
			if k = strings.TrimSpace(k); k != "" {
				keys = append(keys, k)
			}
		}
		body["checks"] = keys
	}
	if rps != 0 {
		if rps < 1 || rps > 100 {
			return nil, e.usage("--rps must be between 1 and 100")
		}
		body["requests_per_second"] = rps
	}
	return body, ExitOK
}

func cmdRun(ctx context.Context, e *Env, args []string) int {
	fs := e.newFlagSet("run")
	authorized := fs.Bool("authorized", false, "I own or am authorized to security-test this target")
	passes := addPassFlags(fs)
	level := fs.String("level", "", "how hard to look: quick | standard | deep (default quick)")
	checks := fs.String("checks", "", "comma-separated check keys to scope the run to")
	rps := fs.Int("rps", 0, "requests per second (1-100); 0 keeps the scan's saved rate")
	seed := fs.Int("seed", -1, "payload-rotation seed to reuse (from `runs --json` manifest.seed); default a fresh one")
	failOn, verified, newOnly, baseline, complete, minExercised := addGateFlags(fs)
	asJSON, outputFlag := addOutputFlags(fs, "print the gate result as JSON")
	image := fs.String("image", defaultRunnerImage(e), "runner image")
	var networks dockerNetworks
	fs.Var(&networks, "docker-network", "docker network the runner joins; repeat or comma-separate for several")
	secretsFile := fs.String("secrets-file", "", "JSON {name: secret} file, mode 0600")
	runnerServer := fs.String("runner-server", "", "server URL as the container sees it (default: loopback -> host.docker.internal)")
	source := fs.String("source", "", "project directory to mount read-only for whitebox analysis")
	resourceIDsFile := fs.String("resource-ids", "", "JSON/YAML file of known resource ids {name: id} for path parameters (stays on this machine)")
	pos, err := parse(fs, args)
	if err != nil {
		return e.parseFailed("run", fs, err)
	}
	resourceIDs, err := resolveResourceIDs(nil, *resourceIDsFile)
	if err != nil {
		return e.usage("%v", err)
	}
	output, code := e.resolveOutput(fs, *asJSON, *outputFlag)
	if code != ExitOK {
		return code
	}
	if *level != "" && !validLevel(*level) {
		return e.usage("--level must be one of quick, standard, deep")
	}
	if len(pos) != 1 {
		return e.usage("run needs exactly one scan ID")
	}
	gp := gatePolicy{failOn: *failOn, verifiedOnly: *verified, newOnly: *newOnly, baselineRun: *baseline,
		quality: qualityPolicy{RequireComplete: *complete, MinExercised: *minExercised}}
	if code := e.checkGateFlags(&gp); code != ExitOK {
		return code
	}
	if *seed < -1 || *seed >= 1<<31 {
		return e.usage("--seed must be between 0 and 2147483647")
	}

	c, err := e.client()
	if err != nil {
		return e.usage("%v", err)
	}
	id, code := resolveScan(ctx, e, c, pos[0], false)
	if code != ExitOK {
		return code
	}

	// The authorization gate is a product requirement: an active scan fires
	// real payloads. It is answered before a single request leaves this process,
	// and a pipe with no --authorized is refused rather than assumed.
	if code := e.consent(*authorized, "active security tests", scanTarget(ctx, e, c, id)); code != ExitOK {
		return code
	}

	body, code := e.runBody(passes, *level, *checks, *rps)
	if code != ExitOK {
		return code
	}
	body["authorized"] = true
	if *seed >= 0 {
		body["seed"] = *seed
	}

	sourcePath := ""
	if *source != "" {
		abs, err := resolveSourceDir(*source)
		if err != nil {
			return e.usage("%v", err)
		}
		sourcePath = abs
	}
	ranRun := 0
	code = runLocal(ctx, e, c, id, body,
		localFlags{image: *image, networks: networks, secretsFile: *secretsFile,
			runnerServer: *runnerServer, source: sourcePath, resourceIDs: resourceIDs,
			onClaim: func(n int) { ranRun = n }},
		gp, output)
	if code == ExitOK && !gp.active() && output == outputTable {
		printRunQuality(ctx, e, c, id, ranRun)
	}
	return code
}

// consent answers the authorization gate: nothing reaches the target until
// --authorized was given or a person typed y to a prompt naming it. A pipe
// with no --authorized is refused, never assumed. target is asked for only
// when a prompt needs it. sends says what is about to be sent.
func (e *Env) consent(authorized bool, sends string, target func() (string, int)) int {
	if authorized {
		return ExitOK
	}
	if !e.IsTTY() {
		return e.usage("refusing to continue without --authorized: this sends %s, and there is no "+
			"terminal to confirm on", sends)
	}
	host, code := target()
	if code != ExitOK {
		return code
	}
	e.errorf("This sends %s to %s.\nType y to confirm you own or are authorized to test it: ", sends, host)
	line, _ := e.readLine()
	if strings.ToLower(strings.TrimSpace(line)) != "y" {
		e.errorf("not authorized; nothing was sent\n")
		return ExitUsage
	}
	return ExitOK
}

// scanTarget returns a lookup of a scan's target, for consent's prompt.
func scanTarget(ctx context.Context, e *Env, c *api.Client, id string) func() (string, int) {
	return func() (string, int) {
		scan, err := c.GetScan(ctx, id)
		if err != nil {
			return "", e.exitFor(err)
		}
		return scan.TargetBaseURL, ExitOK
	}
}

// waitForRun polls until the scan leaves queued/running, streaming new events
// to stderr. Ctrl-C asks the server to cancel rather than leaving it running.
// tail is how many already-recorded events to print first (a negative value
// prints the whole log); `wait` attaches with a small one, `run` shows all.
// detach leaves the run going on Ctrl-C instead of cancelling it.
func waitForRun(ctx context.Context, e *Env, c *api.Client, id string, timeout time.Duration, tail int, detach bool) int {
	now := e.Now
	if now == nil {
		now = time.Now
	}
	deadline := now().Add(timeout)
	seen := 0
	first := true
	for {
		if ctx.Err() != nil && detach {
			e.errorf("interrupted; the run continues on the server (runpentests cancel %s stops it)\n", shortID(id))
			return ExitFailed
		}
		if ctx.Err() != nil {
			cancelCtx, stop := context.WithTimeout(context.Background(), 10*time.Second)
			defer stop()
			if err := c.Cancel(cancelCtx, id); err != nil {
				e.errorf("interrupted; could not cancel the run: %v\n", err)
			} else {
				e.errorf("interrupted; asked the server to cancel the run\n")
			}
			return ExitFailed
		}
		scan, err := c.GetScan(ctx, id)
		if err != nil {
			return e.exitFor(err)
		}
		if events, err := c.Events(ctx, id); err == nil {
			if first && tail >= 0 && len(events) > tail {
				seen = len(events) - tail
			}
			first = false
			for ; seen < len(events); seen++ {
				e.errorf("%s\n", eventLine(events[seen]))
			}
		}
		switch scan.Status {
		case "queued", "running":
		case "completed":
			return ExitOK
		default: // failed, cancelled, draft
			reason := ""
			if scan.FailureReason != nil {
				reason = ": " + printable(*scan.FailureReason)
			}
			e.errorf("run ended %s%s\n", scan.Status, reason)
			return ExitFailed
		}
		if now().After(deadline) {
			e.errorf("timed out after %s; the run is still going on the server\n", timeout)
			return ExitTimeout
		}
		select {
		case <-ctx.Done():
		case <-time.After(e.poll()):
		}
	}
}

// cmdWait attaches to whatever run the scan has now — queued by an earlier
// `run`, or already finished — and gates on its findings like `run --wait`.
func cmdWait(ctx context.Context, e *Env, args []string) int {
	fs := e.newFlagSet("wait")
	timeout := fs.Duration("timeout", 30*time.Minute, "give up waiting after this long")
	failOn, verified, newOnly, baseline, complete, minExercised := addGateFlags(fs)
	asJSON, outputFlag := addOutputFlags(fs, "print the gate result as JSON")
	pos, err := parse(fs, args)
	if err != nil {
		return e.parseFailed("wait", fs, err)
	}
	output, code := e.resolveOutput(fs, *asJSON, *outputFlag)
	if code != ExitOK {
		return code
	}
	if len(pos) > 1 {
		return e.usage("wait takes at most one scan ID")
	}
	gp := gatePolicy{failOn: *failOn, verifiedOnly: *verified, newOnly: *newOnly, baselineRun: *baseline,
		quality: qualityPolicy{RequireComplete: *complete, MinExercised: *minExercised}}
	if code := e.checkGateFlags(&gp); code != ExitOK {
		return code
	}
	c, err := e.client()
	if err != nil {
		return e.usage("%v", err)
	}
	id, code := resolveScan(ctx, e, c, argOrEmpty(pos), true)
	if code != ExitOK {
		return code
	}
	scan, err := c.GetScan(ctx, id)
	if err != nil {
		return e.exitFor(err)
	}
	switch scan.Status {
	case "completed":
		// Nothing to wait for: the result is already there to gate on.
	case "queued", "running":
		// Attach quietly: five lines of what already happened is context,
		// the whole log is a re-read.
		// Detach on Ctrl-C: this process did not start the run, so stopping
		// it would cancel someone else's (an earlier CI step's) work.
		if code := waitForRun(ctx, e, c, id, *timeout, 5, true); code != ExitOK {
			return code
		}
	case "failed", "cancelled":
		reason := ""
		if scan.FailureReason != nil && *scan.FailureReason != "" {
			reason = ": " + printable(*scan.FailureReason)
		}
		e.errorf("scan %s is %s%s\n", shortID(id), scan.Status, reason)
		return ExitFailed
	default:
		return e.usage("scan %s has not started a run (status %s): start one with `runpentests run %s`",
			shortID(id), scan.Status, shortID(id))
	}
	if !gp.active() {
		if output == outputTable {
			printRunQuality(ctx, e, c, id, 0)
		}
		return ExitOK
	}
	return gate(ctx, e, c, id, 0, gp, output)
}

// printRunQuality writes the execution-quality summary of a run to stderr, as
// information: no policy, so it never changes the exit code. Best effort.
func printRunQuality(ctx context.Context, e *Env, c *api.Client, id string, runNumber int) {
	q, err := loadQuality(ctx, c, id, runNumber, qualityPolicy{})
	if err != nil || q.Run == 0 {
		return
	}
	e.errorf("\n")
	printQualitySummary(e.errorf, q)
}

type gateRow struct{ ID, Severity, Confidence, Verdict, Check, Title string }

// gatePolicy is everything a pipeline can ask the gate. The finding half is
// --fail-on and its refinements; the execution-quality half is opt-in.
type gatePolicy struct {
	failOn       string
	verifiedOnly bool
	newOnly      bool
	// baselineRun compares against this archived run instead of the one just
	// before the gated run. It implies newOnly.
	baselineRun int
	quality     qualityPolicy
}

func (p gatePolicy) active() bool { return p.failOn != "" || p.quality.active() }

// addGateFlags registers the gate's flags on a command that can end in one.
func addGateFlags(fs *flag.FlagSet) (*string, *bool, *bool, *int, *bool, *int) {
	failOn := fs.String("fail-on", "", "exit 1 if a finding at or above this severity remains")
	verified := fs.Bool("verified-only", false, "with --fail-on, count only verified findings")
	newOnly := fs.Bool("new-only", false, "with --fail-on, count only findings new since the previous run")
	baseline := fs.Int("baseline-run", 0, "with --fail-on, count only findings new since this run number (implies --new-only)")
	complete := fs.Bool("require-complete", false, "exit 5 unless the run did everything it was asked and exercised the API")
	minExercised := fs.Int("min-exercised", 0, "exit 5 unless at least this percent (1-100) of in-scope endpoints answered a 2xx")
	return failOn, verified, newOnly, baseline, complete, minExercised
}

// checkGateFlags validates the gate flags together; it returns ExitOK or the
// usage exit code it already reported.
func (e *Env) checkGateFlags(p *gatePolicy) int {
	if p.failOn != "" && !validSeverity(p.failOn) {
		return e.usage("--fail-on must be one of info, low, medium, high, critical")
	}
	if p.baselineRun < 0 {
		return e.usage("--baseline-run must be a run number")
	}
	if p.baselineRun > 0 {
		p.newOnly = true
	}
	if (p.verifiedOnly || p.newOnly) && p.failOn == "" {
		return e.usage("--verified-only, --new-only and --baseline-run refine --fail-on; set --fail-on too")
	}
	if p.quality.MinExercised < 0 || p.quality.MinExercised > 100 {
		return e.usage("--min-exercised must be a percentage from 1 to 100")
	}
	p.failOn = strings.ToLower(p.failOn)
	return ExitOK
}

// gate decides the exit code from a finished run (runNumber; 0 = the newest).
// A finding a person already dismissed does not fail a pipeline: that is what
// triage is for. Precedence: findings at --fail-on exit 1 before an incomplete
// run exits 5 — a finding the run did make stands whatever it missed.
func gate(ctx context.Context, e *Env, c *api.Client, id string, runNumber int, p gatePolicy, output string) int {
	// Pin the run first, so every half of the answer is about the same run even
	// if another starts meanwhile.
	run, err := fetchRun(ctx, c, id, runNumber)
	if err != nil {
		if p.quality.active() {
			return e.exitFor(err)
		}
		// The finding half stands on its own: a server that cannot say which
		// run this was must not turn a --fail-on gate into a usage error.
		run = nil
	}
	if run != nil {
		runNumber = run.RunNumber
	}
	var quality *runQuality
	if run != nil || p.quality.active() {
		q := assessQuality(run, nil, p.quality)
		if run != nil {
			rows := run.Coverage
			if rows == nil {
				rows, err = c.Coverage(ctx, id, runNumber)
				if err != nil && p.quality.active() {
					return e.exitFor(err)
				}
			}
			q = assessQuality(run, rows, p.quality)
		}
		quality = &q
	}

	var rows []gateRow
	baseline := 0
	var diff *api.Diff
	findingsStatus := qualityNotEvaluated
	if p.failOn != "" {
		newOnly := p.newOnly
		if newOnly {
			d, err := c.Diff(ctx, id, p.baselineRun, runNumber)
			var apiErr *api.APIError
			switch {
			case err == nil:
				diff, baseline = &d, d.FromRun
				for _, f := range d.Added {
					// A diff row has no finding ID; its fingerprint is the stable
					// name both runs use.
					rows = append(rows, gateRow{f.Fingerprint, f.Severity, f.Confidence, f.Verdict, f.Check, f.Title})
				}
			case errors.As(err, &apiErr) && apiErr.Status == 409 && p.baselineRun == 0:
				// A first run has nothing to compare with: everything is new.
				newOnly = false
			default:
				return e.exitFor(err)
			}
		}
		if !newOnly {
			rows, err = pinnedFindings(ctx, c, id, run)
			if err != nil {
				return e.exitFor(err)
			}
		}
	}

	// considered is what the gate actually looks at; failing is the part at or
	// above --fail-on. JUnit reports both, so a suite shows proof, not just red.
	var considered, failing []gateRow
	for _, r := range rows {
		if r.Verdict == "dismissed" {
			continue
		}
		if p.verifiedOnly && r.Confidence != "verified" {
			continue
		}
		considered = append(considered, r)
		if severityRank[strings.ToLower(r.Severity)] >= severityRank[p.failOn] {
			failing = append(failing, r)
		}
	}
	sort.SliceStable(failing, func(i, j int) bool {
		return severityRank[failing[i].Severity] > severityRank[failing[j].Severity]
	})
	if p.failOn != "" {
		findingsStatus = qualityPass
		if len(failing) > 0 {
			findingsStatus = qualityFail
		}
	}
	code := ExitOK
	switch {
	case len(failing) > 0:
		code = ExitFindings
	case quality != nil && quality.Status == qualityFail:
		code = ExitIncomplete
	}

	baselineNote := ""
	if p.newOnly {
		switch {
		case diff != nil:
			baselineNote = fmt.Sprintf("compared with run %d (baseline) -> run %d", diff.FromRun, diff.ToRun)
			if diff.OptionsChanged || diff.ExecutorChanged || diff.ConfigChanged {
				baselineNote += "; the runs differ in options, executor or config, so the comparison is partial"
			}
		default:
			baselineNote = "no baseline: this is the scan's first run, so every finding counts as new"
		}
	}

	switch output {
	case outputJSON:
		doc := map[string]any{
			"fail_on": p.failOn, "failing": len(failing), "findings": failing,
			"findings_status": findingsStatus, "exit_code": code,
		}
		if failing == nil {
			doc["findings"] = []gateRow{}
		}
		if runNumber > 0 {
			doc["run"] = runNumber
		}
		if p.newOnly {
			if baseline > 0 {
				doc["baseline_run"] = baseline
			} else {
				doc["baseline_run"] = nil
			}
		}
		if quality != nil {
			doc["quality"] = quality
		}
		printJSON(e, doc)
	case outputGitHub:
		if p.failOn != "" {
			printGitHubGate(e, p.failOn, failing)
		}
		if baselineNote != "" {
			e.printf("::notice title=baseline::%s\n", githubMessageEscape.Replace(baselineNote))
		}
		if quality != nil && p.quality.active() {
			printGitHubQuality(e, *quality)
		}
	case outputJUnit:
		var q *runQuality
		if p.quality.active() {
			q = quality
		}
		if code := printJUnitGate(e, considered, failing, q); code != ExitOK {
			return code
		}
	default:
		if p.failOn != "" {
			for _, r := range failing {
				e.printf("%-8s %-9s %-24s %s\n", r.Severity, r.Confidence, r.Check, printable(r.Title))
			}
			e.printf("%d finding(s) at or above %s\n", len(failing), p.failOn)
		}
		if baselineNote != "" {
			e.printf("%s\n", baselineNote)
		}
		if quality != nil && p.quality.active() {
			printQualitySummary(e.printf, *quality)
		}
	}
	return code
}

// pinnedFindings is what the gated run found. The live findings are the newest
// run's, and a run that starts at any moment clears them, so they count only
// when the gated run is still the newest *after* they were read: the server
// opens a run's history row no later than it clears the live findings. When it
// is not, or that cannot be confirmed, the run's archived snapshot answers —
// read with the run itself, so it is about that run whatever starts meanwhile.
// Its verdicts are as of the run's end, so a later triage of the same
// fingerprint, still on the live list, overrides them: a race can only empty
// that list, which leaves the snapshot's own (fail-closed) verdicts.
// A nil run (a server that could not say which run) keeps the live findings.
func pinnedFindings(ctx context.Context, c *api.Client, id string, run *api.ScanRun) ([]gateRow, error) {
	findings, err := c.Findings(ctx, id)
	if err != nil {
		return nil, err
	}
	if run != nil {
		newest, err := fetchRun(ctx, c, id, 0)
		if err != nil || newest == nil || newest.RunNumber != run.RunNumber {
			triage := make(map[string]string, len(findings))
			for _, f := range findings {
				if f.Fingerprint != "" {
					triage[f.Fingerprint] = f.Verdict
				}
			}
			rows := make([]gateRow, 0, len(run.FindingsSnapshot))
			for _, f := range run.FindingsSnapshot {
				verdict := f.Verdict
				if v, ok := triage[f.Fingerprint]; ok && f.Fingerprint != "" {
					verdict = v
				}
				// A snapshot row has no finding ID; its fingerprint is the stable name.
				rows = append(rows, gateRow{f.Fingerprint, f.Severity, f.Confidence, verdict, f.Check, f.Title})
			}
			return rows, nil
		}
	}
	rows := make([]gateRow, 0, len(findings))
	for _, f := range findings {
		rows = append(rows, gateRow{f.ID, f.Severity, f.Confidence, f.Verdict, f.Check, f.Title})
	}
	return rows, nil
}

// printGitHubQuality annotates the job with the execution-quality verdict.
func printGitHubQuality(e *Env, q runQuality) {
	if q.Status == qualityFail {
		for _, f := range q.Failures {
			e.printf("::error title=scan quality::%s\n", githubMessageEscape.Replace(f))
		}
	}
	for _, m := range q.Incomplete {
		e.printf("::warning title=scan quality::%s\n", githubMessageEscape.Replace(m))
	}
	e.printf("scan quality: %s — %s endpoints exercised\n", q.Status, shareLabel(q.Share))
}

// GitHub's workflow-command escaping. Nothing is rescanned, so % first is safe.
var (
	githubMessageEscape  = strings.NewReplacer("%", "%25", "\r", "%0D", "\n", "%0A")
	githubPropertyEscape = strings.NewReplacer("%", "%25", "\r", "%0D", "\n", "%0A", ":", "%3A", ",", "%2C")
)

// printGitHubGate writes one workflow command per failing finding, so GitHub
// annotates the diff or the job's summary instead of a log line a person must
// read. Text from the target is stripped of terminal escapes first, then
// escaped for GitHub's message/property grammar.
func printGitHubGate(e *Env, failOn string, failing []gateRow) {
	for _, r := range failing {
		level := "notice"
		switch strings.ToLower(r.Severity) {
		case "critical", "high":
			level = "error"
		case "medium":
			level = "warning"
		}
		property := printable(r.Check) + ": " + printable(r.Severity)
		e.printf("::%s title=%s::%s\n", level,
			githubPropertyEscape.Replace(property),
			githubMessageEscape.Replace(printable(r.Title)))
	}
	e.printf("%d finding(s) at or above %s\n", len(failing), failOn)
}

// The JUnit document is a small subset: one suite, one case per finding the
// gate considered, a failure child only for the ones that fail the threshold.
type junitFailure struct {
	Message string `xml:"message,attr"`
	Type    string `xml:"type,attr"`
	Text    string `xml:",chardata"`
}

type junitCase struct {
	Classname string         `xml:"classname,attr"`
	Name      string         `xml:"name,attr"`
	Failures  []junitFailure `xml:"failure,omitempty"`
}

type junitSuite struct {
	Name     string      `xml:"name,attr"`
	Tests    int         `xml:"tests,attr"`
	Failures int         `xml:"failures,attr"`
	Cases    []junitCase `xml:"testcase"`
}

type junitDoc struct {
	XMLName xml.Name   `xml:"testsuites"`
	Suite   junitSuite `xml:"testsuite"`
}

// printJUnitGate writes a JUnit XML document to stdout, the format CI systems
// read as a test report. A marshal failure is the server's data, not a usage
// error, so it exits failed.
func printJUnitGate(e *Env, considered, failing []gateRow, quality *runQuality) int {
	isFailing := make(map[string]bool, len(failing))
	for _, r := range failing {
		isFailing[r.ID] = true
	}
	suite := junitSuite{Name: "runpentests", Tests: len(considered), Failures: len(failing)}
	if quality != nil {
		// One case for the run itself: a suite of zero findings must not read
		// green when the run never exercised the API.
		qc := junitCase{Classname: "runpentests.quality", Name: "execution quality: " + shareLabel(quality.Share) + " endpoints exercised"}
		if quality.Status == qualityFail {
			qc.Failures = []junitFailure{{
				Message: strings.Join(quality.Failures, "; "),
				Type:    "incomplete",
				Text:    strings.Join(append(append([]string{}, quality.Incomplete...), quality.Caveat), "\n"),
			}}
			suite.Failures++
		}
		suite.Tests++
		suite.Cases = append(suite.Cases, qc)
	}
	for _, r := range considered {
		c := junitCase{Classname: printable(r.Check), Name: printable(r.Title)}
		if isFailing[r.ID] {
			c.Failures = []junitFailure{{
				Message: printable(r.Severity) + " " + printable(r.Title),
				Type:    printable(r.Severity),
				Text:    fmt.Sprintf("confidence: %s\nfinding: %s", printable(r.Confidence), printable(r.ID)),
			}}
		}
		suite.Cases = append(suite.Cases, c)
	}
	data, err := xml.MarshalIndent(junitDoc{Suite: suite}, "", "  ")
	if err != nil {
		e.errorf("error: could not build the JUnit report: %v\n", err)
		return ExitFailed
	}
	e.printf("%s%s\n", xml.Header, data)
	return ExitOK
}

func cmdCancel(ctx context.Context, e *Env, args []string) int {
	fs := e.newFlagSet("cancel")
	pos, err := parse(fs, args)
	if err != nil {
		return e.parseFailed("cancel", fs, err)
	}
	if len(pos) != 1 {
		return e.usage("cancel needs exactly one scan ID")
	}
	c, err := e.client()
	if err != nil {
		return e.usage("%v", err)
	}
	id, code := resolveScan(ctx, e, c, pos[0], false)
	if code != ExitOK {
		return code
	}
	if err := c.Cancel(ctx, id); err != nil {
		return e.exitFor(err)
	}
	e.printf("cancel requested\n")
	return ExitOK
}

// eventLine is one progress line. A check that raised part-way is marked with
// "!": it did not finish, and must not scroll past looking like a completion.
func eventLine(ev api.Event) string {
	mark := " "
	if ev.Stage == "check_failed" {
		mark = "!"
	}
	return fmt.Sprintf("%s %3d%%  %s", mark, ev.Pct, printable(ev.Message))
}
