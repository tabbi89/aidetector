package commands

import (
	"fmt"
	"net/http/httptest"
	"strings"
	"testing"

	"aidetector/cli/internal/api"
)

// traceRow builds one MutationRow the fake server can page through.
func traceRow(seq int, method, route, identity, check string, status int, body string) map[string]any {
	return map[string]any{
		"sequence": seq, "method": method, "route": route,
		"identity": identity, "pass": "engine", "elapsed_ms": 12.5, "check": check,
		"request": map[string]any{
			"headers":       map[string]any{"Accept": "application/json"},
			"query_fields":  []any{"q"},
			"json_shape":    nil,
			"json_body":     `{"a":1}`,
			"content_bytes": 7,
		},
		"response": map[string]any{
			"status":       status,
			"headers":      map[string]any{"Content-Type": "application/json"},
			"content_type": "application/json",
			"body_bytes":   len(body),
			"body":         body,
			"truncated":    false,
			"body_omitted": false,
			"json_shape":   nil,
		},
	}
}

func TestRunTraceTableFiltersByStatusAndIdentity(t *testing.T) {
	f := &fake{traceRows: []map[string]any{
		traceRow(1, "GET", "/orders/1", "alice", "bola", 403, "forbidden"),
		traceRow(2, "GET", "/public", "bob", "headers", 403, "forbidden"),
		traceRow(3, "GET", "/reports", "alice", "headers", 200, "ok"),
	}}
	srv := httptest.NewServer(f.handler())
	defer srv.Close()
	h := newHarness(t, srv, "", false)

	code := h.run("runs", "trace", fakeScanID, "1", "--status", "4xx", "--identity", "alice")
	if code != ExitOK {
		t.Fatalf("exit = %d\n%s", code, h.errOut.String())
	}
	out := h.out.String()
	if !strings.Contains(out, "/orders/1") {
		t.Fatalf("the matching row should be printed:\n%s", out)
	}
	if strings.Contains(out, "/public") || strings.Contains(out, "/reports") {
		t.Fatalf("filters must be AND-ed:\n%s", out)
	}
	if !strings.Contains(out, "1 shown · 1 match · 3 request(s) in the run") {
		t.Fatalf("footer should count shown and total:\n%s", out)
	}
	if !strings.Contains(h.errOut.String(), "detail: aidetector runs trace 11111111 1 --seq <N>") {
		t.Fatalf("stderr should point at --seq: %q", h.errOut.String())
	}
}

func TestRunTraceSingleNumberIsTheRunOnTheProjectScan(t *testing.T) {
	f := &fake{traceRows: []map[string]any{traceRow(1, "GET", "/a", "anonymous", "bola", 200, "ok")}}
	srv := httptest.NewServer(f.handler())
	defer srv.Close()
	h := newHarness(t, srv, "", false)
	h.env.Dir = t.TempDir()
	writeFile(t, h.env.Dir, "aidetector.yml", "target: http://t\n")

	if code := h.run("runs", "trace", "2"); code != ExitOK {
		t.Fatalf("exit = %d\n%s", code, h.errOut.String())
	}
	if !f.sawRequest("GET " + fakeScanPath + "/runs/2/trace") {
		t.Fatalf("a lone number is the run, on the project's scan; requests = %v", f.requests)
	}
}

func TestRunTraceReadsEveryPage(t *testing.T) {
	rows := make([]map[string]any, 501)
	for i := range rows {
		rows[i] = traceRow(i+1, "GET", fmt.Sprintf("/r/%d", i+1), "anonymous", "bola", 200, "ok")
	}
	f := &fake{traceRows: rows}
	srv := httptest.NewServer(f.handler())
	defer srv.Close()
	h := newHarness(t, srv, "", false)

	if code := h.run("runs", "trace", fakeScanID, "1"); code != ExitOK {
		t.Fatalf("exit = %d\n%s", code, h.errOut.String())
	}
	pages := f.tracePages()
	if len(pages) != 2 || pages[0] != 0 || pages[1] != 500 {
		t.Fatalf("pages = %v, want offsets 0 and 500", pages)
	}
}

func TestRunTraceSeqPrintsTheWholeRow(t *testing.T) {
	f := &fake{traceRows: []map[string]any{
		traceRow(1, "GET", "/first", "alice", "bola", 200, "one"),
		traceRow(7, "POST", "/orders", "alice", "write_authz", 403, "you found it\nline two"),
	}}
	srv := httptest.NewServer(f.handler())
	defer srv.Close()
	h := newHarness(t, srv, "", false)

	if code := h.run("runs", "trace", fakeScanID, "1", "--seq", "7"); code != ExitOK {
		t.Fatalf("exit = %d\n%s", code, h.errOut.String())
	}
	out := h.out.String()
	for _, want := range []string{"#7 POST /orders", "request:", "headers: Accept", "response:", "status: 403", "you found it", "line two"} {
		if !strings.Contains(out, want) {
			t.Fatalf("--seq output is missing %q:\n%s", want, out)
		}
	}
	if strings.Contains(out, "/first") {
		t.Fatalf("--seq must print one row only:\n%s", out)
	}
}

func TestPrintableStripsTerminalEscapesAndKeepsLayout(t *testing.T) {
	got := printable("\x1b]0;evil\x07keep\nnext\tend\x9b31m")
	if strings.ContainsRune(got, 0x1b) || strings.ContainsRune(got, 0x07) || strings.ContainsRune(got, 0x9b) {
		t.Fatalf("control characters survived: %q", got)
	}
	if !strings.Contains(got, "keep\nnext\tend") {
		t.Fatalf("newline and tab must survive: %q", got)
	}
}

func TestTraceStatusNamesTheTransportErrorOfARowWithNoResponse(t *testing.T) {
	timeout := "ReadTimeout"
	r := api.MutationRow{Error: &timeout}
	if got := traceStatus(r); got != "ReadTimeout" {
		t.Fatalf("traceStatus = %q, want ReadTimeout", got)
	}
	if got := traceStatus(api.MutationRow{}); got != "-" {
		t.Fatalf("traceStatus without an error = %q, want -", got)
	}
	match, err := traceStatusMatcher("error")
	if err != nil {
		t.Fatal(err)
	}
	ok := 200
	if !match(nil) || match(&ok) {
		t.Fatal(`--status error must match only rows with no response`)
	}
}

func TestEventLineMarksACheckThatDidNotFinish(t *testing.T) {
	failed := eventLine(api.Event{Stage: "check_failed", Pct: 40, Message: "bola did not finish: ReadTimeout"})
	if !strings.HasPrefix(failed, "!  40%") {
		t.Fatalf("failed check line = %q, want a leading !", failed)
	}
	done := eventLine(api.Event{Stage: "cors", Pct: 40, Message: "completed cors"})
	if strings.HasPrefix(done, "!") {
		t.Fatalf("completed check line = %q, must not be marked", done)
	}
}

func TestGapLineNamesChecksThatDidNotFinish(t *testing.T) {
	line := gapLine(api.ScanRun{RunNumber: 2, Gaps: api.RunGaps{FailedChecks: []string{"bola", "broken_auth"}}})
	if !strings.Contains(line, "did not finish: bola, broken_auth") {
		t.Fatalf("gapLine = %q", line)
	}
}
