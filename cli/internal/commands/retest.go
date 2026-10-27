package commands

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"

	"runpentests/cli/internal/api"
)

// A retest runs the check behind one finding again — after a fix, to see
// whether it is gone — instead of the whole scan. It is a real run (consent,
// the ownership gate and the request budget all apply), and it is honest about
// its reach: the engine scopes by check, not by endpoint, so a retest of one
// BOLA finding re-runs BOLA everywhere. It never replays recorded requests.

// retestCarried are the original run's passes a retest repeats as they were:
// they shape what an engine check sends and spend no tokens. Writes and AI
// passes need their own flag; adjunct tools are left out, since they run
// whatever the check scope says.
var retestCarried = []string{"fuzz", "premium"}

// confirmSignals are evidence signals only the confirm pass produces, under a
// check key the engine also reports without it (the arithmetic template oracle
// files a verified SSTI as reflected_injection). Mirrors CONFIRM_SIGNALS in
// services/api/app/scans/run_options.py.
var confirmSignals = map[string]bool{"independent_arithmetic": true}

// needsConfirm reports whether only the confirm pass can find this again.
func needsConfirm(f api.Finding) bool {
	signal, _ := f.Evidence["signal"].(string)
	return confirmSignals[signal]
}

// retestAIPasses are the token-spending passes --ai repeats from the original.
var retestAIPasses = []string{"plan", "adjudicate", "security_review", "genai_payloads", "adaptive", "resource_refine"}

// Retest outcomes, and their exit codes.
const (
	retestStillPresent = "still_present" // exit 1: the check found it again
	retestGone         = "gone"          // exit 0: not reproduced, and its endpoint was exercised
	retestNotRetested  = "not_retested"  // exit 5: the retest could not have found it
)

func cmdRetest(ctx context.Context, e *Env, args []string) int {
	fs := e.newFlagSet("retest")
	authorized := fs.Bool("authorized", false, "I own or am authorized to security-test this target")
	writes := fs.Bool("writes", false, PassHelp["writes"])
	readOnly := fs.Bool("read-only", false, "retest without writes even though the original run had them (its write findings come back not retested)")
	withConfirm := fs.Bool("confirm", false, "repeat the confirmation pass a confirmed finding needs (slow: runs the confirm tools too)")
	withAI := fs.Bool("ai", false, "repeat the original run's AI passes (spends tokens)")
	asJSON := fs.Bool("json", false, "print the outcome as JSON")
	image := fs.String("image", defaultRunnerImage(e), "runner image")
	var networks dockerNetworks
	fs.Var(&networks, "docker-network", "docker network the runner joins; repeat or comma-separate for several")
	secretsFile := fs.String("secrets-file", "", "JSON {name: secret} file, mode 0600")
	runnerServer := fs.String("runner-server", "", "server URL as the runner container sees it")
	resourceIDsFile := fs.String("resource-ids", "", "JSON/YAML file of known resource ids {name: id} (stays on this machine)")
	pos, err := parse(fs, args)
	if err != nil {
		return e.parseFailed("retest", fs, err)
	}
	if len(pos) < 1 || len(pos) > 2 {
		return e.usage("retest needs a finding: retest [SCAN] FINDING")
	}
	if *writes && *readOnly {
		return e.usage("--writes and --read-only contradict each other")
	}
	scanRef, findingRef := "", pos[len(pos)-1]
	if len(pos) == 2 {
		scanRef = pos[0]
	}
	// The project file's resource ids and secret_env secrets, as the run that
	// found the finding had them: without them item routes 404 and identities
	// drop, and the retest could only answer "not retested".
	file, secrets, code := projectContext(e)
	if code != ExitOK {
		return code
	}
	resourceIDs, err := resolveResourceIDs(file, *resourceIDsFile)
	if err != nil {
		return e.usage("%v", err)
	}
	c, err := e.client()
	if err != nil {
		return e.usage("%v", err)
	}
	id, code := resolveScan(ctx, e, c, scanRef, true)
	if code != ExitOK {
		return code
	}

	// --- what is being retested, and how the original run looked for it ------
	all, err := c.Findings(ctx, id)
	if err != nil {
		return e.exitFor(err)
	}
	matches := matchFindings(all, findingRef)
	switch {
	case len(matches) == 0:
		return e.usage("no finding %q on scan %s's latest run (see `runpentests findings %s`)", findingRef, shortID(id), shortID(id))
	case len(matches) > 1:
		return e.usage("%q matches %d findings; give more of its ID or fingerprint", findingRef, len(matches))
	}
	finding := matches[0]
	if finding.Fingerprint == "" {
		return e.usage("finding %s has no fingerprint, so a later run cannot be matched to it", shortID(finding.ID))
	}
	original, err := fetchRun(ctx, c, id, 0)
	if err != nil {
		return e.exitFor(err)
	}
	if original == nil {
		return e.usage("scan %s has no run to retest from", shortID(id))
	}
	opts := original.Options
	if on, _ := opts["mutate"].(bool); on && !*writes && !*readOnly {
		return e.usage("run %d had --writes on, and this check may need it: pass --writes to retest the same "+
			"way, or --read-only to retest without (a write finding then comes back not retested)", original.RunNumber)
	}

	// Without the pass that proved it, a retest could only answer "not retested"
	// (the diff says so too): ask before spending a run on that.
	if needsConfirm(finding) && !*withConfirm {
		return e.usage("run %d proved this finding with --confirm, and only that pass can find it again: "+
			"pass --confirm to retest the same way", original.RunNumber)
	}

	body := map[string]any{"authorized": true, "checks": []string{finding.Check}}
	for _, field := range retestCarried {
		if on, _ := opts[field].(bool); on {
			body[field] = true
		}
	}
	if *writes {
		body["mutate"] = true
	}
	if *withConfirm {
		body["confirm"] = true
	}
	if *withAI {
		for _, field := range retestAIPasses {
			if on, _ := opts[field].(bool); on {
				body[field] = true
			}
		}
	}
	seed, hasSeed := manifestSeed(original)
	if hasSeed {
		body["seed"] = seed
	}

	// --- say what will run before anything does ------------------------------
	var passes []string
	for k, v := range body {
		if b, ok := v.(bool); ok && b && k != "authorized" {
			name := k
			if flagName, ok := passFlag(k); ok {
				name = flagName
			}
			passes = append(passes, name)
		}
	}
	sort.Strings(passes)
	seedNote := "a fresh seed (the original run recorded none)"
	if hasSeed {
		seedNote = fmt.Sprintf("seed %d from run %d", seed, original.RunNumber)
	}
	passNote := "no extra passes"
	if len(passes) > 0 {
		passNote = "passes: " + strings.Join(passes, ", ")
	}
	e.errorf("retest %s — %s (%s)\n", shortID(finding.Fingerprint), printable(finding.Title), printable(finding.Severity))
	e.errorf("  scope: the whole %s check on every in-scope endpoint — the engine scopes by check, "+
		"not by endpoint, so this is not a single-request replay\n", printable(finding.Check))
	e.errorf("  %s; %s; at most the run's request budget\n", seedNote, passNote)
	e.errorf("  compared with run %d when it finishes\n", original.RunNumber)

	if code := e.consent(*authorized, "active security tests", scanTarget(ctx, e, c, id)); code != ExitOK {
		return code
	}

	ranRun := 0
	code = runLocal(ctx, e, c, id, body,
		localFlags{image: *image, networks: networks, secretsFile: *secretsFile,
			runnerServer: *runnerServer, resourceIDs: resourceIDs, secrets: secrets,
			onClaim: func(n int) { ranRun = n }},
		gatePolicy{}, outputTable)
	if code != ExitOK {
		return code
	}
	return reportRetest(ctx, e, c, id, finding, original.RunNumber, ranRun, *asJSON)
}

// manifestSeed is the payload-rotation seed a run recorded, when it did.
func manifestSeed(run *api.ScanRun) (int, bool) {
	if run == nil || run.Manifest == nil {
		return 0, false
	}
	f, ok := run.Manifest["seed"].(float64)
	if !ok || f < 0 || f >= 1<<31 {
		return 0, false
	}
	return int(f), true
}

// reportRetest compares the retest with the run the finding came from and
// says what became of the finding, without calling it fixed when the retest
// could not have found it.
func reportRetest(ctx context.Context, e *Env, c *api.Client, id string, finding api.Finding, from, to int, asJSON bool) int {
	d, err := c.Diff(ctx, id, from, to)
	if err != nil {
		var apiErr *api.APIError
		if errors.As(err, &apiErr) {
			e.errorf("could not compare run %d with the retest: %s\n", from, apiErr.Detail)
		}
		return e.exitFor(err)
	}
	outcome, reason := retestOutcome(d, finding.Fingerprint)
	if outcome == retestGone {
		// "Gone" means the endpoint answered and the check ran; say so only when
		// the retest's own coverage shows the endpoint exercised.
		if note := unexercisedNote(ctx, c, id, to, finding); note != "" {
			outcome, reason = retestNotRetested, note
		}
	}
	code := map[string]int{retestStillPresent: ExitFindings, retestGone: ExitOK, retestNotRetested: ExitIncomplete}[outcome]
	if asJSON {
		printJSON(e, map[string]any{
			"finding": finding.Fingerprint, "check": finding.Check, "outcome": outcome, "reason": reason,
			"original_run": from, "retest_run": d.ToRun, "partial": d.OptionsChanged || d.ExecutorChanged || d.ConfigChanged,
			"exit_code": code,
		})
		return code
	}
	switch outcome {
	case retestStillPresent:
		e.printf("still present: run %d found %s again\n", d.ToRun, printable(finding.Title))
	case retestGone:
		e.printf("not reproduced: run %d ran %s and its endpoint answered, but did not find it — likely fixed\n",
			d.ToRun, printable(finding.Check))
	default:
		e.printf("not retested: %s — this is not a fix\n", reason)
	}
	if d.ExecutorChanged || d.ConfigChanged {
		e.printf("note: the runs used different executors or project files, so the comparison is partial\n")
	}
	return code
}

// retestOutcome reads the finding's fate from the diff.
func retestOutcome(d api.Diff, fingerprint string) (string, string) {
	has := func(rows []api.RunFinding) bool {
		for _, r := range rows {
			if r.Fingerprint == fingerprint {
				return true
			}
		}
		return false
	}
	switch {
	case has(d.Unchanged):
		return retestStillPresent, ""
	case has(d.NotRetested):
		return retestNotRetested, "the retest could not have found it again (a pass, identity or endpoint it did not cover)"
	case has(d.Resolved):
		return retestGone, ""
	}
	return retestNotRetested, "the finding is not in the compared runs"
}

// unexercisedNote returns why a "gone" finding is unproven: its endpoint was
// not exercised by the retest. "" when it was, or when that cannot be told.
func unexercisedNote(ctx context.Context, c *api.Client, id string, run int, finding api.Finding) string {
	if finding.OperationID == nil {
		return ""
	}
	rows, err := c.Coverage(ctx, id, run)
	if err != nil {
		return ""
	}
	for _, r := range rows {
		if r.OperationID == nil || *r.OperationID != *finding.OperationID {
			continue
		}
		// A no-2xx endpoint is the server diff's call (a refusal is the answer
		// for an authorization fix); one that got no answer proves nothing.
		if state := endpointState(r); state == endpointNoResponse || state == endpointUntested {
			return fmt.Sprintf("its endpoint %s %s was %s in the retest", printable(r.Method), printable(r.Path),
				strings.ReplaceAll(state, "_", " "))
		}
	}
	return ""
}
