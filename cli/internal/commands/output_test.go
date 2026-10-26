package commands

import (
	"encoding/json"
	"encoding/xml"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func gateFinding(id, severity, confidence, check, title string) map[string]any {
	return map[string]any{
		"id": id, "severity": severity, "confidence": confidence,
		"check": check, "title": title, "verdict": "unreviewed",
	}
}

func TestGitHubGateOutputEscapesAndPicksTheLevel(t *testing.T) {
	f := &fake{findings: []map[string]any{
		gateFinding("f1", "high", "verified", "bola", "a,b:c\n%"),
		gateFinding("f2", "medium", "heuristic", "inj", "medium lead"),
		gateFinding("f3", "low", "heuristic", "hdr", "header missing"),
		gateFinding("f4", "info", "heuristic", "meta", "informational"),
	}}
	srv := httptest.NewServer(f.handler())
	defer srv.Close()
	h := newHarness(t, srv, "", false)
	if got := h.run("run", fakeScanID, "--authorized", "--fail-on", "info", "--output", "github"); got != ExitFindings {
		t.Fatalf("exit = %d, want %d\n%s", got, ExitFindings, h.errOut.String())
	}
	out := h.out.String()
	for _, want := range []string{
		// The comma and colon in the message are not property separators.
		"::error title=bola%3A high::a,b:c%0A%25",
		"::warning title=inj%3A medium::medium lead",
		"::notice title=hdr%3A low::header missing",
		"::notice title=meta%3A info::informational",
		"4 finding(s) at or above info",
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("github output is missing %q:\n%s", want, out)
		}
	}
}

type junitXMLFailure struct {
	Message string `xml:"message,attr"`
	Type    string `xml:"type,attr"`
	Text    string `xml:",chardata"`
}

type junitXMLCase struct {
	Classname string           `xml:"classname,attr"`
	Name      string           `xml:"name,attr"`
	Failure   *junitXMLFailure `xml:"failure"`
}

type junitXMLSuite struct {
	Name     string         `xml:"name,attr"`
	Tests    int            `xml:"tests,attr"`
	Failures int            `xml:"failures,attr"`
	Cases    []junitXMLCase `xml:"testcase"`
}

type junitXMLDoc struct {
	XMLName xml.Name        `xml:"testsuites"`
	Suites  []junitXMLSuite `xml:"testsuite"`
}

func TestJUnitGateOutputIsValidXMLWithTheFailureCount(t *testing.T) {
	f := &fake{findings: []map[string]any{
		gateFinding("f-high", "high", "verified", "bola", "BOLA on /orders"),
		gateFinding("f-low", "low", "heuristic", "hdr", "Header missing"),
		{
			"id": "f-dismissed", "severity": "critical", "confidence": "verified",
			"check": "x", "title": "known false positive", "verdict": "dismissed",
		},
	}}
	srv := httptest.NewServer(f.handler())
	defer srv.Close()
	h := newHarness(t, srv, "", false)
	if got := h.run("run", fakeScanID, "--authorized", "--fail-on", "high", "--output", "junit"); got != ExitFindings {
		t.Fatalf("exit = %d, want %d\n%s", got, ExitFindings, h.errOut.String())
	}

	var doc junitXMLDoc
	if err := xml.Unmarshal(h.out.Bytes(), &doc); err != nil {
		t.Fatalf("junit output does not parse: %v\n%s", err, h.out.String())
	}
	if len(doc.Suites) != 1 {
		t.Fatalf("want one testsuite, got %d", len(doc.Suites))
	}
	suite := doc.Suites[0]
	// The dismissed finding is not considered; the high and low are.
	if suite.Name != "runpentests" || suite.Tests != 2 || suite.Failures != 1 {
		t.Fatalf("suite = %+v; want 2 tests, 1 failure", suite)
	}
	if len(suite.Cases) != 2 {
		t.Fatalf("want 2 testcases, got %d", len(suite.Cases))
	}
	var failing *junitXMLFailure
	for _, c := range suite.Cases {
		if c.Name == "BOLA on /orders" {
			failing = c.Failure
		}
	}
	if failing == nil {
		t.Fatal("the high finding should carry a failure")
	}
	if failing.Type != "high" || !strings.HasPrefix(failing.Message, "high ") {
		t.Fatalf("failure = %+v", failing)
	}
	if !strings.Contains(failing.Text, "confidence: verified") || !strings.Contains(failing.Text, "finding: f-high") {
		t.Fatalf("failure text should name the confidence and finding id: %q", failing.Text)
	}
}

func TestJSONAndOutputJSONAgree(t *testing.T) {
	f := &fake{findings: []map[string]any{gateFinding("f1", "high", "verified", "bola", "BOLA")}}
	srv := httptest.NewServer(f.handler())
	defer srv.Close()

	for _, extra := range [][]string{
		{"--json"},
		{"--output", "json"},
		{"--json", "--output", "json"},
	} {
		h := newHarness(t, srv, "", false)
		args := append([]string{"wait", fakeScanID, "--fail-on", "high"}, extra...)
		if got := h.run(args...); got != ExitFindings {
			t.Fatalf("%v: exit = %d, want %d\n%s", extra, got, ExitFindings, h.errOut.String())
		}
		var got map[string]any
		if err := json.Unmarshal(h.out.Bytes(), &got); err != nil {
			t.Fatalf("%v: output is not JSON: %v\n%s", extra, err, h.out.String())
		}
		if got["fail_on"] != "high" || got["failing"] != float64(1) {
			t.Fatalf("%v: json = %v", extra, got)
		}
	}
}

func TestJSONConflictingWithASecondOutputIsAUsageError(t *testing.T) {
	srv := httptest.NewServer((&fake{}).handler())
	defer srv.Close()
	h := newHarness(t, srv, "", false)
	if got := h.run("wait", fakeScanID, "--fail-on", "high", "--json", "--output", "junit"); got != ExitUsage {
		t.Fatalf("exit = %d, want %d", got, ExitUsage)
	}
	if !strings.Contains(h.errOut.String(), "conflicts") {
		t.Fatalf("stderr should name the conflict: %q", h.errOut.String())
	}
	h = newHarness(t, srv, "", false)
	if got := h.run("wait", fakeScanID, "--fail-on", "high", "--output", "yaml"); got != ExitUsage {
		t.Fatalf("an unknown format: exit = %d, want %d", got, ExitUsage)
	}
}

func TestCostAggregatesByPhase(t *testing.T) {
	f := &fake{cost: map[string]any{
		"scan_id": fakeScanID, "total_usd": 0.0035,
		"models": []any{map[string]any{
			"model": "gpt-x", "phases": []any{"engine", "plan"}, "calls": 3,
			"tokens_in": 35, "tokens_out": 16, "cost_usd": 0.0035,
		}},
		"entries": []any{
			map[string]any{"phase": "plan", "model": "gpt-x", "tokens_in": 10, "tokens_out": 5, "cost_micros": 1000},
			map[string]any{"phase": "engine", "model": "gpt-x", "tokens_in": 20, "tokens_out": 10, "cost_micros": 2000},
			map[string]any{"phase": "engine", "model": "gpt-x", "tokens_in": 5, "tokens_out": 1, "cost_micros": 500},
		},
	}}
	srv := httptest.NewServer(f.handler())
	defer srv.Close()
	h := newHarness(t, srv, "", false)
	if got := h.run("cost", fakeScanID); got != ExitOK {
		t.Fatalf("exit = %d\n%s", got, h.errOut.String())
	}
	out := h.out.String()
	if !strings.Contains(out, "total: $0.0035") || !strings.Contains(out, "gpt-x") {
		t.Fatalf("cost output is missing the total or model:\n%s", out)
	}
	engine := strings.Fields(lineStartingWith(out, "engine"))
	if len(engine) < 5 || engine[1] != "2" || engine[2] != "25" || engine[3] != "11" || engine[4] != "$0.0025" {
		t.Fatalf("engine phase should aggregate two calls, 25/11 tokens and $0.0025: %v\n%s", engine, out)
	}
	plan := strings.Fields(lineStartingWith(out, "plan"))
	if len(plan) < 5 || plan[1] != "1" || plan[4] != "$0.0010" {
		t.Fatalf("plan phase row = %v\n%s", plan, out)
	}
}

func lineStartingWith(out, prefix string) string {
	for _, line := range strings.Split(out, "\n") {
		if strings.HasPrefix(strings.TrimSpace(line), prefix+" ") {
			return line
		}
	}
	return ""
}

func TestCostWithNoSpendSaysSo(t *testing.T) {
	srv := httptest.NewServer((&fake{}).handler())
	defer srv.Close()
	h := newHarness(t, srv, "", false)
	if got := h.run("cost", fakeScanID); got != ExitOK {
		t.Fatalf("exit = %d\n%s", got, h.errOut.String())
	}
	if !strings.Contains(h.out.String(), "no AI spend on this scan") {
		t.Fatalf("out = %q", h.out.String())
	}
}

func TestCoverageSortsByPathAndUntestedFilters(t *testing.T) {
	f := &fake{coverage: []map[string]any{
		{
			"operation_id": "o1", "method": "GET", "path": "/b", "enabled": true,
			"requests": 3, "checks": []any{"bola"}, "findings": 1,
		},
		{
			"operation_id": "o2", "method": "GET", "path": "/a", "enabled": true,
			"requests": 0, "checks": []any{}, "findings": 0,
		},
		{
			"operation_id": "o3", "method": "POST", "path": "/c", "enabled": false,
			"requests": 0, "checks": []any{}, "findings": 0,
		},
	}}
	srv := httptest.NewServer(f.handler())
	defer srv.Close()

	h := newHarness(t, srv, "", false)
	if got := h.run("coverage", fakeScanID); got != ExitOK {
		t.Fatalf("exit = %d\n%s", got, h.errOut.String())
	}
	out := h.out.String()
	if a, b, c := strings.Index(out, "/a"), strings.Index(out, "/b"), strings.Index(out, "/c"); a < 0 || b < 0 || c < 0 || !(a < b && b < c) {
		t.Fatalf("endpoints should be sorted by path:\n%s", out)
	}
	// /b predates response outcomes: unknown, never "no response".
	if !strings.Contains(out, "3 endpoint(s) shown; of 2 in scope: 0 exercised, 0 no 2xx, 0 no response, 1 never probed, 1 unknown") {
		t.Fatalf("footer missing:\n%s", out)
	}
	if !strings.Contains(out, "(excluded)") {
		t.Fatalf("an excluded endpoint should be marked:\n%s", out)
	}

	h = newHarness(t, srv, "", false)
	if got := h.run("coverage", fakeScanID, "--untested"); got != ExitOK {
		t.Fatalf("exit = %d\n%s", got, h.errOut.String())
	}
	out = h.out.String()
	if strings.Contains(out, "/b") || !strings.Contains(out, "/a") || !strings.Contains(out, "/c") {
		t.Fatalf("--untested should keep only the never-probed endpoints:\n%s", out)
	}
	if !strings.Contains(out, "2 endpoint(s) shown") {
		t.Fatalf("footer should count what was shown:\n%s", out)
	}
}

func TestScansShowPrintsTheFindingsSummaryAndSpend(t *testing.T) {
	f := &fake{scanCost: 0.0123}
	f.credentials = []map[string]any{
		{"id": "c1", "name": "alice", "role": "user", "auth_type": "bearer"},
		{"id": "c2", "name": "admin", "role": "admin", "auth_type": "bearer"},
	}
	f.summary = map[string]any{
		"total": 17, "active": 15, "dismissed": 2,
		"verified_critical": 0, "verified_high": 6,
		"severity": map[string]int{"critical": 0, "high": 6, "medium": 3, "low": 6, "info": 2},
	}
	srv := httptest.NewServer(f.handler())
	defer srv.Close()
	h := newHarness(t, srv, "", false)
	if got := h.run("scans", "show", fakeScanID); got != ExitOK {
		t.Fatalf("exit = %d\n%s", got, h.errOut.String())
	}
	out := h.out.String()
	for _, want := range []string{
		"findings:   17 (15 active, 2 dismissed) · critical 0 high 6 medium 3 low 6 info 2 · verified critical/high 0/6",
		"identities: 2",
		"ai spend:   $0.0123",
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("scans show is missing %q:\n%s", want, out)
		}
	}
}

func TestScansShowSurvivesASummaryError(t *testing.T) {
	f := &fake{status: map[string]int{"GET " + fakeScanPath + "/findings/summary": http.StatusInternalServerError}}
	srv := httptest.NewServer(f.handler())
	defer srv.Close()
	h := newHarness(t, srv, "", false)
	if got := h.run("scans", "show", fakeScanID); got != ExitOK {
		t.Fatalf("a failed summary must not fail scans show; exit = %d\n%s", got, h.errOut.String())
	}
	if !strings.Contains(h.out.String(), "id:         "+fakeScanID) {
		t.Fatalf("the scan itself should still print:\n%s", h.out.String())
	}
	if !strings.Contains(h.errOut.String(), "findings summary unavailable") {
		t.Fatalf("the failed summary should be noted on stderr: %q", h.errOut.String())
	}
}
