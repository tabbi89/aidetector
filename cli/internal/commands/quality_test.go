package commands

import (
	"encoding/json"
	"encoding/xml"
	"net/http/httptest"
	"strings"
	"testing"

	"runpentests/cli/internal/api"
)

func intp(n int) *int    { return &n }
func boolp(b bool) *bool { return &b }

// row is one coverage row with response outcomes recorded.
func row(path string, requests, responses, ok int) api.CoverageRow {
	return api.CoverageRow{Method: "GET", Path: path, Enabled: true, Requests: requests,
		Responses: intp(responses), OK: intp(ok), Exercised: boolp(ok > 0)}
}

func completedRun(gaps api.RunGaps) *api.ScanRun {
	return &api.ScanRun{RunNumber: 3, Status: "completed", Gaps: gaps}
}

func TestQualityRejectsRunsThatNeverExercisedTheAPI(t *testing.T) {
	strict := qualityPolicy{RequireComplete: true, MinExercised: 50}
	cases := []struct {
		name  string
		rows  []api.CoverageRow
		state string
	}{
		{"every request answered 401", []api.CoverageRow{row("/a", 4, 4, 0), row("/b", 2, 2, 0)}, endpointNo2xx},
		{"every request answered 404", []api.CoverageRow{row("/items/{id}", 6, 6, 0)}, endpointNo2xx},
		{"nothing answered", []api.CoverageRow{row("/a", 3, 0, 0)}, endpointNoResponse},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			q := assessQuality(completedRun(api.RunGaps{}), c.rows, strict)
			if q.Status != qualityFail {
				t.Fatalf("status = %s, want fail: %+v", q.Status, q)
			}
			if q.Complete == nil || *q.Complete {
				t.Fatalf("a run that exercised nothing is not complete: %+v", q)
			}
			if q.Endpoints[c.state] != len(c.rows) {
				t.Fatalf("endpoints = %v, want all %s", q.Endpoints, c.state)
			}
			if q.Share.Percent == nil || *q.Share.Percent != 0 {
				t.Fatalf("share = %+v, want 0%%", q.Share)
			}
		})
	}
}

func TestQualityMixedSuccessIsMeasuredWithItsParts(t *testing.T) {
	rows := []api.CoverageRow{
		row("/a", 3, 3, 2), row("/b", 2, 2, 0), row("/c", 0, 0, 0), row("/d", 5, 5, 5),
		{Method: "POST", Path: "/admin", Enabled: false},
	}
	q := assessQuality(completedRun(api.RunGaps{}), rows, qualityPolicy{MinExercised: 50})
	if q.Status != qualityPass {
		t.Fatalf("2 of 4 is 50%%, which meets 50: %+v", q)
	}
	if q.Share.Exercised != 2 || q.Share.InScope != 4 || q.Share.Excluded != 1 {
		t.Fatalf("share = %+v", q.Share)
	}
	if got := shareLabel(q.Share); got != "2/4 (50%)" {
		t.Fatalf("label = %q", got)
	}
	q = assessQuality(completedRun(api.RunGaps{}), rows, qualityPolicy{MinExercised: 80})
	if q.Status != qualityFail || !strings.Contains(strings.Join(q.Failures, ";"), "below the required 80%") {
		t.Fatalf("50%% must fail 80: %+v", q)
	}
}

func TestQualityCompletenessNamesWhatTheRunMissed(t *testing.T) {
	good := []api.CoverageRow{row("/a", 3, 3, 3)}
	cases := []struct {
		name string
		gaps api.RunGaps
		want string
	}{
		{"budget exhausted", api.RunGaps{BudgetExhausted: true}, "request budget ran out"},
		{"failed check", api.RunGaps{FailedChecks: []string{"bola"}}, "did not finish: bola"},
		{"tool did not run", api.RunGaps{NotRun: []string{"zap"}}, "did not run: zap"},
		{"identity missing", api.RunGaps{IdentitiesMissing: []string{"alice"}}, "left out of the run: alice"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			q := assessQuality(completedRun(c.gaps), good, qualityPolicy{RequireComplete: true})
			if q.Status != qualityFail || !strings.Contains(strings.Join(q.Incomplete, ";"), c.want) {
				t.Fatalf("want fail naming %q: %+v", c.want, q)
			}
		})
	}
	// A check with nothing to test in this API is legitimate: a note, not a failure.
	q := assessQuality(completedRun(api.RunGaps{SkippedChecks: []string{"ssrf"}}), good,
		qualityPolicy{RequireComplete: true})
	if q.Status != qualityPass || len(q.Notes) != 1 {
		t.Fatalf("an inapplicable check must not fail completeness: %+v", q)
	}
	// A run that ended badly is incomplete whatever its gaps say.
	failed := &api.ScanRun{RunNumber: 2, Status: "failed"}
	if q := assessQuality(failed, good, qualityPolicy{RequireComplete: true}); q.Status != qualityFail {
		t.Fatalf("a failed run is incomplete: %+v", q)
	}
}

func TestQualityNeverCountsUnknownAsCovered(t *testing.T) {
	// An older server or run: no response outcomes at all.
	old := []api.CoverageRow{{Method: "GET", Path: "/a", Enabled: true, Requests: 4}}
	q := assessQuality(completedRun(api.RunGaps{}), old, qualityPolicy{MinExercised: 1})
	if q.Status != qualityFail || q.Share.Percent != nil || q.Endpoints[endpointUnknown] != 1 {
		t.Fatalf("unknown outcomes must fail a strict share: %+v", q)
	}
	// Without a policy it is described, not judged.
	q = assessQuality(completedRun(api.RunGaps{}), old, qualityPolicy{})
	if q.Status != qualityNotEvaluated {
		t.Fatalf("status = %s", q.Status)
	}
	// An empty denominator is unknown, never 100%.
	q = assessQuality(completedRun(api.RunGaps{}), []api.CoverageRow{{Path: "/x", Enabled: false}},
		qualityPolicy{MinExercised: 10, RequireComplete: true})
	if q.Share.Percent != nil || q.Status != qualityFail {
		t.Fatalf("no in-scope endpoint must not read as covered: %+v", q)
	}
	// Unknown outcomes and nothing known to be exercised: never complete.
	q = assessQuality(completedRun(api.RunGaps{}), old, qualityPolicy{RequireComplete: true})
	if q.Status != qualityFail || q.Complete == nil || *q.Complete {
		t.Fatalf("an older run's unknown outcomes must not pass --require-complete: %+v", q)
	}
	// No run at all.
	if q := assessQuality(nil, nil, qualityPolicy{RequireComplete: true}); q.Status != qualityFail {
		t.Fatalf("no run cannot be complete: %+v", q)
	}
}

// qualityFake is a server whose latest run exercised nothing: every request 401.
func qualityFake(findings []map[string]any) *fake {
	return &fake{
		findings: findings,
		runs:     []map[string]any{{"run_number": 1, "status": "completed", "gaps": map[string]any{}}},
		coverage: []map[string]any{{
			"operation_id": "o1", "method": "GET", "path": "/me", "enabled": true,
			"requests": 5, "responses": 5, "ok": 0, "exercised": false, "checks": []any{"bola"}, "findings": 0,
		}},
	}
}

func TestGateExitCodePrecedenceAndDefaults(t *testing.T) {
	high := map[string]any{"severity": "high", "confidence": "verified", "check": "bola", "title": "BOLA", "verdict": "unreviewed"}
	cases := []struct {
		name     string
		findings []map[string]any
		args     []string
		want     int
	}{
		{"default gate stays compatible", nil, []string{"--fail-on", "high"}, ExitOK},
		{"quality policy fails an all-401 run", nil, []string{"--require-complete"}, ExitIncomplete},
		{"min exercised fails it too", nil, []string{"--fail-on", "high", "--min-exercised", "10"}, ExitIncomplete},
		{"findings win over quality", []map[string]any{high}, []string{"--fail-on", "high", "--require-complete"}, ExitFindings},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			srv := httptest.NewServer(qualityFake(c.findings).handler())
			defer srv.Close()
			h := newHarness(t, srv, "", false)
			if got := h.run(append([]string{"wait", fakeScanID}, c.args...)...); got != c.want {
				t.Fatalf("exit = %d, want %d\nstdout: %s\nstderr: %s", got, c.want, h.out.String(), h.errOut.String())
			}
		})
	}
}

func TestGateQualityInEveryMachineFormat(t *testing.T) {
	srv := httptest.NewServer(qualityFake(nil).handler())
	defer srv.Close()

	h := newHarness(t, srv, "", false)
	if got := h.run("wait", fakeScanID, "--require-complete", "--output", "json"); got != ExitIncomplete {
		t.Fatalf("exit = %d\n%s", got, h.errOut.String())
	}
	var doc struct {
		ExitCode int        `json:"exit_code"`
		Run      int        `json:"run"`
		Quality  runQuality `json:"quality"`
	}
	if err := json.Unmarshal(h.out.Bytes(), &doc); err != nil {
		t.Fatalf("stdout is not JSON: %v\n%s", err, h.out.String())
	}
	if doc.ExitCode != ExitIncomplete || doc.Run != 1 || doc.Quality.Status != qualityFail ||
		doc.Quality.Endpoints[endpointNo2xx] != 1 || doc.Quality.Caveat == "" {
		t.Fatalf("doc = %+v", doc)
	}

	h = newHarness(t, srv, "", false)
	h.run("wait", fakeScanID, "--require-complete", "--output", "github")
	if !strings.Contains(h.out.String(), "::error title=scan quality::") {
		t.Fatalf("github output lacks the quality annotation:\n%s", h.out.String())
	}

	h = newHarness(t, srv, "", false)
	h.run("wait", fakeScanID, "--require-complete", "--output", "junit")
	var report junitDoc
	if err := xml.Unmarshal(h.out.Bytes(), &report); err != nil {
		t.Fatalf("junit is not XML: %v\n%s", err, h.out.String())
	}
	if report.Suite.Tests != 1 || report.Suite.Failures != 1 || report.Suite.Cases[0].Classname != "runpentests.quality" {
		t.Fatalf("junit = %+v", report.Suite)
	}
}

func TestWaitPrintsTheQualitySummaryOnStderrOnly(t *testing.T) {
	srv := httptest.NewServer(qualityFake(nil).handler())
	defer srv.Close()
	h := newHarness(t, srv, "", false)
	if got := h.run("wait", fakeScanID); got != ExitOK {
		t.Fatalf("no policy: the summary is information, exit = %d", got)
	}
	if h.out.Len() != 0 {
		t.Fatalf("stdout must stay clean: %q", h.out.String())
	}
	if !strings.Contains(h.errOut.String(), "endpoints exercised: 0/1 (0%)") {
		t.Fatalf("stderr lacks the summary:\n%s", h.errOut.String())
	}
}

func TestBaselineRunIsSentAndShown(t *testing.T) {
	diff := map[string]any{"from_run": 1, "to_run": 3, "added": []any{}, "resolved": []any{},
		"not_retested": []any{}, "unchanged": []any{}}
	f := &fake{diff: &diff, runs: []map[string]any{{"run_number": 3, "status": "completed"}}}
	srv := httptest.NewServer(f.handler())
	defer srv.Close()
	h := newHarness(t, srv, "", false)
	if got := h.run("wait", fakeScanID, "--fail-on", "high", "--baseline-run", "1"); got != ExitOK {
		t.Fatalf("exit = %d\n%s", got, h.errOut.String())
	}
	if !strings.Contains(h.out.String(), "compared with run 1 (baseline) -> run 3") {
		t.Fatalf("the baseline must be visible:\n%s", h.out.String())
	}
	// The gated run is named, not left to "whichever is newest".
	if q := f.queries["GET "+fakeScanPath+"/diff"]; q != "from_run=1&to_run=3" {
		t.Fatalf("diff query = %q", q)
	}
	if code := h.run("wait", fakeScanID, "--baseline-run", "1"); code != ExitUsage {
		t.Fatalf("--baseline-run without --fail-on is a usage error, got %d", code)
	}
}

func TestGateJudgesTheRunItRanNotANewerOne(t *testing.T) {
	high := map[string]any{"fingerprint": "fp-high", "check": "bola", "severity": "high",
		"confidence": "verified", "title": "BOLA", "verdict": "unreviewed"}
	// The claim issued run 1; a teammate's narrow run 2 finished meanwhile and
	// its live findings are empty. Run 1's archived high must still fail.
	f := &fake{runs: []map[string]any{
		{"run_number": 2, "status": "completed"},
		{"run_number": 1, "status": "completed", "findings_snapshot": []any{high}},
	}}
	h, _ := localHarness(t, f, "completed", nil, nil)
	if got := h.run("run", fakeScanID, "--authorized", "--fail-on", "high"); got != ExitFindings {
		t.Fatalf("exit = %d\n%s", got, h.out.String())
	}
}
