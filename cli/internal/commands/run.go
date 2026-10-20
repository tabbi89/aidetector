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

	"aidetector/cli/internal/api"
)

// RunFlags maps each pass flag to the RunRequest field it sets. It is the
// single list the flags are built from, and the contract test compares its
// values with the server's RunRequest booleans: a flag the server grows must
// show up here or the build fails.
var RunFlags = map[string]string{
	"mutate":          "mutate",
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

// passAliases are alternative spellings of a pass flag. They set the same
// RunRequest field but stay out of RunFlags, whose field names are unique.
var passAliases = map[string]string{
	"writes": "mutate",
}

var passAliasHelp = map[string]string{
	"writes": "allow tests that change target data; same as --mutate",
}

// passField resolves a flag name, alias included, to its RunRequest field.
func passField(name string) (string, bool) {
	if field, ok := RunFlags[name]; ok {
		return field, true
	}
	field, ok := passAliases[name]
	return field, ok
}

// PassHelp describes each pass for `aidetector help` and for the flag's own
// usage. A pass that saves time is never described as "enable the X pass": the
// cost to the target or the tokens is the part that matters.
var PassHelp = map[string]string{
	"mutate":          "write to the target: write oracle, mass assignment, race, seeded BOLA, body-field fuzzing (restores/cleans up after itself)",
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
	"seed":                    "not exposed: reproducibility is a web/advanced concern",
	"predefined_resource_ids": "not exposed: needs a structured map",
	"adaptive_attempts":       "not exposed: bounded default",
	"resource_attempts":       "not exposed: bounded default",
	"requests_per_second":     "--rps",
	"checks":                  "--checks",
	"config_source":           "set from aidetector.yml by the target form, never a flag",
	"level":                   "--level",
}

// addPassFlags registers one boolean flag per run pass, built from RunFlags, so
// a pass the server grows cannot be missing from `run`.
func addPassFlags(fs *flag.FlagSet) map[string]*bool {
	passes := map[string]*bool{}
	for flagName := range RunFlags {
		passes[flagName] = fs.Bool(flagName, false, PassHelp[flagName])
	}
	for flagName := range passAliases {
		passes[flagName] = fs.Bool(flagName, false, passAliasHelp[flagName])
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
	for flagName, field := range passAliases {
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
	failOn := fs.String("fail-on", "", "exit 1 if a finding at or above this severity remains")
	verified := fs.Bool("verified-only", false, "with --fail-on, count only verified findings")
	newOnly := fs.Bool("new-only", false, "with --fail-on, count only findings new since the previous run")
	asJSON, outputFlag := addOutputFlags(fs, "print the gate result as JSON")
	image := fs.String("image", defaultRunnerImage(e), "runner image")
	var networks dockerNetworks
	fs.Var(&networks, "docker-network", "docker network the runner joins; repeat or comma-separate for several")
	secretsFile := fs.String("secrets-file", "", "JSON {name: secret} file, mode 0600")
	runnerServer := fs.String("runner-server", "", "server URL as the container sees it (default: loopback -> host.docker.internal)")
	source := fs.String("source", "", "project directory to mount read-only for whitebox analysis")
	pos, err := parse(fs, args)
	if err != nil {
		return e.parseFailed("run", fs, err)
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
	if *failOn != "" {
		if !validSeverity(*failOn) {
			return e.usage("--fail-on must be one of info, low, medium, high, critical")
		}
	}
	if (*verified || *newOnly) && *failOn == "" {
		return e.usage("--verified-only and --new-only refine --fail-on; set --fail-on too")
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
	if !*authorized {
		if !e.IsTTY() {
			return e.usage("refusing to run without --authorized: active scanning fires real " +
				"payloads, and there is no terminal to confirm on")
		}
		scan, err := c.GetScan(ctx, id)
		if err != nil {
			return e.exitFor(err)
		}
		e.errorf("This sends active security tests to %s.\nType y to confirm you own or are authorized to test it: ", scan.TargetBaseURL)
		line, _ := e.readLine()
		if strings.ToLower(strings.TrimSpace(line)) != "y" {
			e.errorf("not authorized; nothing was run\n")
			return ExitUsage
		}
	}

	body, code := e.runBody(passes, *level, *checks, *rps)
	if code != ExitOK {
		return code
	}
	body["authorized"] = true

	sourcePath := ""
	if *source != "" {
		abs, err := resolveSourceDir(*source)
		if err != nil {
			return e.usage("%v", err)
		}
		sourcePath = abs
	}
	return runLocal(ctx, e, c, id, body,
		localFlags{image: *image, networks: networks, secretsFile: *secretsFile,
			runnerServer: *runnerServer, source: sourcePath},
		*failOn, *verified, *newOnly, output)
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
			e.errorf("interrupted; the run continues on the server (aidetector cancel %s stops it)\n", shortID(id))
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
	failOn := fs.String("fail-on", "", "exit 1 if a finding at or above this severity remains")
	verified := fs.Bool("verified-only", false, "with --fail-on, count only verified findings")
	newOnly := fs.Bool("new-only", false, "with --fail-on, count only findings new since the previous run")
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
	if *failOn != "" && !validSeverity(*failOn) {
		return e.usage("--fail-on must be one of info, low, medium, high, critical")
	}
	if (*verified || *newOnly) && *failOn == "" {
		return e.usage("--verified-only and --new-only refine --fail-on; set --fail-on too")
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
		return e.usage("scan %s has not started a run (status %s): start one with `aidetector run %s`",
			shortID(id), scan.Status, shortID(id))
	}
	if *failOn == "" {
		return ExitOK
	}
	return gate(ctx, e, c, id, strings.ToLower(*failOn), *verified, *newOnly, output)
}

type gateRow struct{ ID, Severity, Confidence, Verdict, Check, Title string }

// gate decides the exit code from the finished run. A finding a person already
// dismissed does not fail a pipeline: that is what triage is for.
func gate(ctx context.Context, e *Env, c *api.Client, id, failOn string, verifiedOnly, newOnly bool, output string) int {
	var rows []gateRow
	if newOnly {
		d, err := c.Diff(ctx, id)
		var apiErr *api.APIError
		switch {
		case err == nil:
			for _, f := range d.Added {
				// A diff row has no finding ID; its fingerprint is the stable
				// name both runs use.
				rows = append(rows, gateRow{f.Fingerprint, f.Severity, f.Confidence, f.Verdict, f.Check, f.Title})
			}
		case errors.As(err, &apiErr) && apiErr.Status == 409:
			// A first run has nothing to compare with: everything is new.
			newOnly = false
		default:
			return e.exitFor(err)
		}
	}
	if !newOnly {
		findings, err := c.Findings(ctx, id)
		if err != nil {
			return e.exitFor(err)
		}
		for _, f := range findings {
			rows = append(rows, gateRow{f.ID, f.Severity, f.Confidence, f.Verdict, f.Check, f.Title})
		}
	}

	// considered is what the gate actually looks at; failing is the part at or
	// above --fail-on. JUnit reports both, so a suite shows proof, not just red.
	var considered, failing []gateRow
	for _, r := range rows {
		if r.Verdict == "dismissed" {
			continue
		}
		if verifiedOnly && r.Confidence != "verified" {
			continue
		}
		considered = append(considered, r)
		if severityRank[strings.ToLower(r.Severity)] >= severityRank[failOn] {
			failing = append(failing, r)
		}
	}
	sort.SliceStable(failing, func(i, j int) bool {
		return severityRank[failing[i].Severity] > severityRank[failing[j].Severity]
	})

	switch output {
	case outputJSON:
		printJSON(e, map[string]any{"fail_on": failOn, "failing": len(failing), "findings": failing})
	case outputGitHub:
		printGitHubGate(e, failOn, failing)
	case outputJUnit:
		if code := printJUnitGate(e, considered, failing); code != ExitOK {
			return code
		}
	default:
		for _, r := range failing {
			e.printf("%-8s %-9s %-24s %s\n", r.Severity, r.Confidence, r.Check, printable(r.Title))
		}
		e.printf("%d finding(s) at or above %s\n", len(failing), failOn)
	}
	if len(failing) > 0 {
		return ExitFindings
	}
	return ExitOK
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
func printJUnitGate(e *Env, considered, failing []gateRow) int {
	isFailing := make(map[string]bool, len(failing))
	for _, r := range failing {
		isFailing[r.ID] = true
	}
	suite := junitSuite{Name: "aidetector", Tests: len(considered), Failures: len(failing)}
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
