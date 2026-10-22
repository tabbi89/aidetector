package commands

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"runpentests/cli/internal/api"
)

func cmdFindings(ctx context.Context, e *Env, args []string) int {
	if len(args) > 0 {
		switch args[0] {
		case "show":
			return findingsShow(ctx, e, args[1:])
		case "dismiss", "confirm", "reopen":
			return findingsVerdict(ctx, e, args[0], args[1:])
		}
	}
	fs := e.newFlagSet("findings")
	minSev := fs.String("min-severity", "info", "hide findings below this severity")
	check := fs.String("check", "", "show only findings of this check")
	verified := fs.Bool("verified", false, "show only verified (proven) findings")
	asJSON := fs.Bool("json", false, "print JSON")
	pos, err := parse(fs, args)
	if err != nil {
		return e.parseFailed("findings", fs, err)
	}
	if len(pos) > 1 {
		return e.usage("findings takes at most one scan ID")
	}
	if !validSeverity(*minSev) {
		return e.usage("--min-severity must be one of info, low, medium, high, critical")
	}
	c, err := e.client()
	if err != nil {
		return e.usage("%v", err)
	}
	id, code := resolveScan(ctx, e, c, argOrEmpty(pos), true)
	if code != ExitOK {
		return code
	}
	all, err := c.Findings(ctx, id)
	if err != nil {
		return e.exitFor(err)
	}
	var shown []api.Finding
	floor := severityRank[strings.ToLower(*minSev)]
	for _, f := range all {
		if severityRank[strings.ToLower(f.Severity)] < floor {
			continue
		}
		if *verified && f.Confidence != "verified" {
			continue
		}
		if *check != "" && !strings.EqualFold(f.Check, *check) {
			continue
		}
		shown = append(shown, f)
	}
	sort.SliceStable(shown, func(i, j int) bool {
		return severityRank[shown[i].Severity] > severityRank[shown[j].Severity]
	})
	if *asJSON {
		return printJSON(e, shown)
	}
	e.printf("%-8s  %-8s  %-9s  %-24s  %s\n", "ID", "SEVERITY", "EVIDENCE", "CHECK", "TITLE")
	for _, f := range shown {
		mark := ""
		switch f.Verdict {
		case "dismissed":
			mark = "  [dismissed]"
		case "confirmed":
			mark = "  [confirmed]"
		}
		e.printf("%-8s  %-8s  %-9s  %-24s  %s%s\n", shortID(f.ID), f.Severity, f.Confidence, f.Check, printable(f.Title), mark)
	}
	e.printf("%d finding(s)\n", len(shown))
	if len(shown) > 0 {
		e.errorf("detail: runpentests findings show %s <ID>\n", shortID(id))
	}
	return ExitOK
}

// findingsShow prints one finding in full. The reference is an ID or
// fingerprint prefix, since a full UUID is tedious to paste from the table.
func findingsShow(ctx context.Context, e *Env, args []string) int {
	fs := e.newFlagSet("findings show")
	asJSON := fs.Bool("json", false, "print the finding as the server sent it")
	pos, err := parse(fs, args)
	if err != nil {
		return e.parseFailed("findings", fs, err)
	}
	// One positional is the finding, on the project's scan; two are scan, finding.
	var scanRef, ref string
	switch len(pos) {
	case 1:
		ref = pos[0]
	case 2:
		scanRef, ref = pos[0], pos[1]
	default:
		return e.usage("findings show needs a finding ID or fingerprint prefix (after the scan ID, outside a project)")
	}
	if len(ref) < 4 {
		return e.usage("finding reference %q is too short: use at least 4 characters of the ID or fingerprint", ref)
	}
	c, err := e.client()
	if err != nil {
		return e.usage("%v", err)
	}
	scanID, code := resolveScan(ctx, e, c, scanRef, true)
	if code != ExitOK {
		return code
	}
	all, err := c.Findings(ctx, scanID)
	if err != nil {
		return e.exitFor(err)
	}
	matches := matchFindings(all, ref)
	switch len(matches) {
	case 0:
		return e.usage("no finding on scan %s matches %q", scanID, ref)
	case 1:
	default:
		e.errorf("%d findings on scan %s match %q; use a longer prefix:\n", len(matches), scanID, ref)
		for _, f := range matches {
			e.errorf("  %-8s  %-8s  %s\n", shortID(f.ID), f.Severity, printable(f.Title))
		}
		return ExitUsage
	}
	f := matches[0]
	if *asJSON {
		if f.Raw != nil {
			return printJSON(e, f.Raw)
		}
		return printJSON(e, f)
	}
	printFinding(e, f)
	return ExitOK
}

// maxVerdictFindings bounds one triage command. Dismissal is a human judgement
// per finding, so there is no bulk-by-filter form; this only stops a paste
// accident.
const maxVerdictFindings = 50

// findingsVerdict implements dismiss, confirm and reopen. Every reference is
// resolved before the first PATCH: a typo or an ambiguous prefix must fail the
// whole command rather than half-apply it.
func findingsVerdict(ctx context.Context, e *Env, verb string, args []string) int {
	fs := e.newFlagSet("findings " + verb)
	asJSON := fs.Bool("json", false, "print the updated findings as JSON")
	var yes *bool
	if verb == "dismiss" {
		yes = fs.Bool("yes", false, "do not ask for confirmation")
	}
	pos, err := parse(fs, args)
	if err != nil {
		return e.parseFailed("findings", fs, err)
	}
	// Two or more positionals are scan then findings; a single one is a
	// finding on the project's scan (runpentests.yml picks it).
	scanRef := ""
	refs := pos
	switch {
	case len(pos) >= 2:
		scanRef, refs = pos[0], pos[1:]
	case len(pos) == 0:
		return e.usage("findings %s needs at least one finding ID or fingerprint prefix", verb)
	}
	if len(refs) > maxVerdictFindings {
		return e.usage("findings %s takes at most %d findings per command", verb, maxVerdictFindings)
	}
	c, err := e.client()
	if err != nil {
		return e.usage("%v", err)
	}
	scanID, code := resolveScan(ctx, e, c, scanRef, true)
	if code != ExitOK {
		return code
	}
	all, err := c.Findings(ctx, scanID)
	if err != nil {
		return e.exitFor(err)
	}
	var chosen []api.Finding
	seen := map[string]bool{}
	for _, ref := range refs {
		if len(ref) < 4 {
			return e.usage("finding reference %q is too short: use at least 4 characters of the ID or fingerprint", ref)
		}
		matches := matchFindings(all, ref)
		switch len(matches) {
		case 0:
			return e.usage("no finding on scan %s matches %q", scanID, ref)
		case 1:
		default:
			e.errorf("%d findings on scan %s match %q; use a longer prefix:\n", len(matches), scanID, ref)
			for _, f := range matches {
				e.errorf("  %-8s  %-8s  %s\n", shortID(f.ID), f.Severity, printable(f.Title))
			}
			return ExitUsage
		}
		// Two references can name one finding (its ID and its fingerprint).
		if !seen[matches[0].ID] {
			seen[matches[0].ID] = true
			chosen = append(chosen, matches[0])
		}
	}

	verdict, done := verdictFor(verb)
	if verb == "dismiss" && !*yes {
		if !e.IsTTY() {
			return e.usage("refusing to dismiss without --yes: dismissal is a person's call, and there is no terminal to confirm on")
		}
		for _, f := range chosen {
			e.errorf("  %-8s  %-16s  %s\n", f.Severity, f.Check, printable(f.Title))
		}
		e.errorf("Dismiss %d finding(s)? A dismissed finding stops failing --fail-on gates on every later run. Type y to confirm: ", len(chosen))
		line, _ := e.readLine()
		if strings.ToLower(strings.TrimSpace(line)) != "y" {
			e.errorf("not dismissed\n")
			return ExitUsage
		}
	}

	updated := make([]api.Finding, 0, len(chosen))
	for _, f := range chosen {
		out, err := c.SetVerdict(ctx, scanID, f.ID, verdict)
		if err != nil {
			return e.exitFor(err)
		}
		updated = append(updated, out)
	}
	if *asJSON {
		raw := make([]any, 0, len(updated))
		for _, f := range updated {
			if f.Raw != nil {
				raw = append(raw, f.Raw)
			} else {
				raw = append(raw, f)
			}
		}
		return printJSON(e, raw)
	}
	for _, f := range updated {
		e.printf("%s  %s  %s  %s\n", done, shortID(f.ID), f.Severity, printable(f.Title))
	}
	if verb == "dismiss" {
		ids := make([]string, 0, len(updated))
		for _, f := range updated {
			ids = append(ids, shortID(f.ID))
		}
		e.errorf("undo: runpentests findings reopen %s %s\n", shortID(scanID), strings.Join(ids, " "))
	}
	return ExitOK
}

// verdictFor maps a triage verb to the verdict it sends and the word the
// result line uses.
func verdictFor(verb string) (verdict, done string) {
	switch verb {
	case "confirm":
		return "confirmed", "confirmed"
	case "reopen":
		return "unreviewed", "reopened"
	}
	return "dismissed", "dismissed"
}

// matchFindings finds the findings whose ID or fingerprint starts with ref.
// Both are hex, so the comparison ignores case.
func matchFindings(all []api.Finding, ref string) []api.Finding {
	ref = strings.ToLower(ref)
	var out []api.Finding
	for _, f := range all {
		if strings.HasPrefix(strings.ToLower(f.ID), ref) ||
			(f.Fingerprint != "" && strings.HasPrefix(strings.ToLower(f.Fingerprint), ref)) {
			out = append(out, f)
		}
	}
	return out
}

func printFinding(e *Env, f api.Finding) {
	owasp := "-"
	if f.OwaspID != nil && *f.OwaspID != "" {
		owasp = *f.OwaspID
	}
	e.printf("%s\n", printable(f.Title))
	e.printf("%s · %s · %s · %s · %s\n", f.Severity, f.Confidence, f.Check, owasp, f.Verdict)
	e.printf("fingerprint: %s\n", f.Fingerprint)
	if f.Description != "" {
		e.printf("\n%s\n", printable(f.Description))
	}
	if f.Remediation != "" {
		e.printf("\nremediation:\n%s", indentBlock(printable(f.Remediation)))
	}
	if len(f.References) > 0 {
		e.printf("\nreferences:\n")
		for _, ref := range f.References {
			e.printf("  %s\n", printable(ref))
		}
	}
	if f.AIRationale != nil && *f.AIRationale != "" {
		e.printf("\nai rationale:\n%s", indentBlock(printable(*f.AIRationale)))
	}
	evidence := f.Evidence
	if evidence == nil {
		evidence = map[string]any{}
	}
	data, err := json.MarshalIndent(evidence, "", "  ")
	if err != nil {
		data = []byte("{}")
	}
	e.printf("\nevidence:\n%s", indentBlock(string(data)))
}

// indentBlock indents every line of s by two spaces, for the blocks below a
// one-line header.
func indentBlock(s string) string {
	lines := strings.Split(strings.TrimRight(s, "\n"), "\n")
	for i, line := range lines {
		lines[i] = "  " + line
	}
	return strings.Join(lines, "\n") + "\n"
}

func cmdDiff(ctx context.Context, e *Env, args []string) int {
	fs := e.newFlagSet("diff")
	asJSON := fs.Bool("json", false, "print JSON")
	pos, err := parse(fs, args)
	if err != nil {
		return e.parseFailed("diff", fs, err)
	}
	if len(pos) > 1 {
		return e.usage("diff takes at most one scan ID")
	}
	c, err := e.client()
	if err != nil {
		return e.usage("%v", err)
	}
	id, code := resolveScan(ctx, e, c, argOrEmpty(pos), true)
	if code != ExitOK {
		return code
	}
	d, err := c.Diff(ctx, id)
	if err != nil {
		var apiErr *api.APIError
		if errors.As(err, &apiErr) && apiErr.Status == 409 {
			return e.usage("a diff needs two runs of this scan")
		}
		return e.exitFor(err)
	}
	if *asJSON {
		return printJSON(e, d)
	}
	e.printf("run %d -> run %d\n", d.FromRun, d.ToRun)
	e.printf("  new:          %d\n  fixed:        %d\n  not retested: %d\n  unchanged:    %d\n",
		len(d.Added), len(d.Resolved), len(d.NotRetested), len(d.Unchanged))
	if d.Unmatchable != 0 {
		e.printf("unmatchable: %d\n", d.Unmatchable)
	}
	if d.OptionsChanged {
		e.printf("note: the runs used different options, so the comparison is partial\n")
	}
	if d.ExecutorChanged {
		e.printf("note: the runs used different executors, so the comparison is partial\n")
	}
	for _, f := range d.Added {
		e.printf("  + %-8s %s\n", f.Severity, printable(f.Title))
	}
	for _, f := range d.Resolved {
		e.printf("  - %-8s %s\n", f.Severity, printable(f.Title))
	}
	// Neither added nor fixed: a gap in the run (a skipped tool or an exhausted
	// budget) could have hidden it, so it gets its own mark.
	for _, f := range d.NotRetested {
		e.printf("  ? %-8s %s\n", f.Severity, printable(f.Title))
	}
	return ExitOK
}

// reportExt is the filename extension for a default-named report. The pentest
// report is Markdown on the server, so it is not .html.
var reportExt = map[string]string{
	"pdf": "pdf", "html": "html", "pentest": "md", "sarif": "sarif", "json": "json",
}

func cmdReport(ctx context.Context, e *Env, args []string) int {
	fs := e.newFlagSet("report")
	format := fs.String("format", "", "pdf | html | pentest | sarif | json")
	out := fs.String("o", "", "file to write, or - for stdout (text formats only); default runpentests-<id8>.<ext>")
	pos, err := parse(fs, args)
	if err != nil {
		return e.parseFailed("report", fs, err)
	}
	if len(pos) > 1 {
		return e.usage("report takes at most one scan ID")
	}
	if _, ok := api.ReportFormats[*format]; !ok {
		return e.usage("--format must be one of pdf, html, pentest, sarif, json")
	}
	if *out == "-" && *format == "pdf" {
		return e.usage("refusing to write a PDF to stdout; use -o FILE")
	}
	c, err := e.client()
	if err != nil {
		return e.usage("%v", err)
	}
	id, code := resolveScan(ctx, e, c, argOrEmpty(pos), true)
	if code != ExitOK {
		return code
	}
	data, err := c.Report(ctx, id, *format)
	if err != nil {
		return e.exitFor(err)
	}
	if *out == "-" {
		_, _ = e.Stdout.Write(data)
		return ExitOK
	}
	if *out == "" {
		wd, err := e.workdir()
		if err != nil {
			return e.usage("%v", err)
		}
		*out = filepath.Join(wd, "runpentests-"+shortID(id)+"."+reportExt[*format])
		// Never overwrite a report the user did not ask to replace.
		f, err := os.OpenFile(*out, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
		if err != nil {
			if os.IsExist(err) {
				return e.usage("%s exists; pass -o FILE to overwrite", *out)
			}
			return e.usage("could not write %s: %v", *out, err)
		}
		_, werr := f.Write(data)
		cerr := f.Close()
		if werr != nil {
			return e.usage("could not write %s: %v", *out, werr)
		}
		if cerr != nil {
			return e.usage("could not write %s: %v", *out, cerr)
		}
		e.errorf("wrote %s (%d bytes)\n", *out, len(data))
		return ExitOK
	}
	// A report is a list of weaknesses in someone's API: keep it owner-only.
	if err := os.WriteFile(*out, data, 0o600); err != nil {
		return e.usage("could not write %s: %v", *out, err)
	}
	e.errorf("wrote %s (%d bytes)\n", *out, len(data))
	return ExitOK
}

func cmdRuns(ctx context.Context, e *Env, args []string) int {
	if len(args) > 0 && args[0] == "trace" {
		return cmdRunTrace(ctx, e, args[1:])
	}
	fs := e.newFlagSet("runs")
	limit := fs.Int("limit", 20, "how many runs to show (1-200)")
	asJSON := fs.Bool("json", false, "print JSON")
	pos, err := parse(fs, args)
	if err != nil {
		return e.parseFailed("runs", fs, err)
	}
	if len(pos) > 1 {
		return e.usage("runs takes at most one scan ID")
	}
	// The server caps a page at 200; asking for more is a typo, not a request.
	if *limit < 1 || *limit > 200 {
		return e.usage("--limit must be between 1 and 200")
	}
	c, err := e.client()
	if err != nil {
		return e.usage("%v", err)
	}
	id, code := resolveScan(ctx, e, c, argOrEmpty(pos), true)
	if code != ExitOK {
		return code
	}
	runs, err := c.Runs(ctx, id, *limit)
	if err != nil {
		return e.exitFor(err)
	}
	if *asJSON {
		raw := make([]map[string]any, 0, len(runs))
		for _, r := range runs {
			raw = append(raw, r.Raw)
		}
		return printJSON(e, raw)
	}
	sort.SliceStable(runs, func(i, j int) bool {
		return runs[i].RunNumber > runs[j].RunNumber
	})
	e.printf("%-4s  %-9s  %-16s  %-8s  %-8s  %-8s  %-8s  %s\n",
		"RUN", "STATUS", "STARTED", "DURATION", "FINDINGS", "REQUESTS", "EXECUTOR", "PASSES")
	for _, r := range runs {
		e.printf("%-4d  %-9s  %-16s  %-8s  %-8d  %-8d  %-8s  %s\n",
			r.RunNumber, r.Status, localStamp(r.StartedAt), runDuration(r),
			r.FindingsCount, r.Requests, executorLabel(r.Executor), passesLabel(r.Options))
	}
	for _, r := range runs {
		if line := gapLine(r); line != "" {
			e.printf("%s\n", line)
		}
	}
	return ExitOK
}

// localStamp renders a server timestamp in the reader's local time, to the
// minute: that is as precise as a run history needs.
func localStamp(ts string) string {
	t, err := time.Parse(time.RFC3339, ts)
	if err != nil {
		return "-"
	}
	return t.Local().Format("2006-01-02 15:04")
}

// runDuration is how long the run took, rounded to seconds; "-" while it has
// not finished.
func runDuration(r api.ScanRun) string {
	if r.FinishedAt == nil || *r.FinishedAt == "" {
		return "-"
	}
	start, err := time.Parse(time.RFC3339, r.StartedAt)
	if err != nil {
		return "-"
	}
	end, err := time.Parse(time.RFC3339, *r.FinishedAt)
	if err != nil {
		return "-"
	}
	d := end.Sub(start).Round(time.Second)
	if d < 0 {
		d = 0
	}
	return d.String()
}

// executorLabel names who sent the traffic. The server's own worker records an
// empty executor; a local run records a "local_runner" kind.
func executorLabel(executor map[string]any) string {
	kind, _ := executor["kind"].(string)
	switch kind {
	case "", "server":
		return "server"
	case "local_runner":
		return "local"
	}
	return kind
}

// passesLabel lists the run options that were on, in a stable order. The
// authorization answer is not a pass and never shows here.
func passesLabel(options map[string]any) string {
	var on []string
	for key, value := range options {
		if key == "authorized" {
			continue
		}
		if v, ok := value.(bool); ok && v {
			// Name the pass by its flag (mutate → writes), as the user typed it.
			if flagName, ok := passFlag(key); ok {
				key = flagName
			}
			on = append(on, key)
		}
	}
	if len(on) == 0 {
		return "-"
	}
	sort.Strings(on)
	return strings.Join(on, ",")
}

// gapLine says what a run was asked to do and did not, or "" when it did all.
func gapLine(r api.ScanRun) string {
	var parts []string
	if len(r.Gaps.NotRun) > 0 {
		parts = append(parts, "did not run: "+strings.Join(r.Gaps.NotRun, ", "))
	}
	if len(r.Gaps.FailedChecks) > 0 {
		parts = append(parts, "did not finish: "+strings.Join(r.Gaps.FailedChecks, ", "))
	}
	if r.Gaps.BudgetExhausted {
		parts = append(parts, "request budget exhausted")
	}
	if len(parts) == 0 {
		return ""
	}
	return fmt.Sprintf("run %d: %s", r.RunNumber, strings.Join(parts, "; "))
}
