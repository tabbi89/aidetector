package commands

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"aidetector/cli/internal/config"
)

const (
	secretKey    = "sk-live-NEVER-PRINT-ME"
	fakeScanID   = "11111111-1111-1111-1111-111111111111"
	fakeScanPath = "/scans/" + fakeScanID
)

// fake is a stand-in aidetector server that records what it was asked.
type fake struct {
	mu       sync.Mutex
	requests []string          // "METHOD /path"
	bodies   map[string][]byte // "METHOD /path" -> last body
	statuses []string          // scan statuses to return, one per GET /scans/{id}
	failure  string
	findings []map[string]any
	runs     []map[string]any
	diff     *map[string]any // nil => 409
	events   []map[string]any
	status   map[string]int // "METHOD /path" -> forced status
	apiKey   string         // when set, requests must carry it
	getCalls int

	scanList     []map[string]any // when set, the answer to GET /scans
	credentials  []map[string]any // identities on GET /scans/{id}
	summary      map[string]any   // answer to GET /scans/{id}/findings/summary
	coverage     []map[string]any // answer to GET /scans/{id}/coverage
	cost         map[string]any   // answer to GET /scans/{id}/cost
	scanCost     float64          // cost_usd on GET /scans/{id}
	capabilities map[string]any   // when set, the answer to GET /capabilities

	traceRows    []map[string]any // the run's trace, returned a page at a time
	traceOffsets []int            // offsets the client asked for

	// local runner
	localStatus      string // when set, GET /scans/{id} reports this
	claimTarget      string
	claimCredentials []any // when set, the credentials the local-run claim returns
	headers          map[string]http.Header
}

func (f *fake) handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		defer f.mu.Unlock()
		key := r.Method + " " + r.URL.Path
		f.requests = append(f.requests, key)
		if f.bodies == nil {
			f.bodies = map[string][]byte{}
		}
		var buf bytes.Buffer
		_, _ = buf.ReadFrom(r.Body)
		f.bodies[key] = buf.Bytes()
		if f.headers == nil {
			f.headers = map[string]http.Header{}
		}
		f.headers[key] = r.Header.Clone()

		// The runner routes authenticate by the per-run token, never the API key.
		if f.apiKey != "" && !strings.HasPrefix(r.URL.Path, "/runner/") &&
			r.Header.Get("X-API-Key") != f.apiKey {
			w.WriteHeader(401)
			_, _ = w.Write([]byte(`{"detail":"missing or invalid API key"}`))
			return
		}
		if code, ok := f.status[key]; ok {
			w.WriteHeader(code)
			_, _ = w.Write([]byte(`{"detail":"forced"}`))
			return
		}
		w.Header().Set("Content-Type", "application/json")
		path := r.URL.Path
		switch {
		case path == "/health/ready":
			_, _ = w.Write([]byte(`{"status":"ok"}`))
		case path == "/capabilities" && r.Method == "GET":
			// A nil map is the old-server answer: 404, which callers must tolerate.
			if f.capabilities == nil {
				w.WriteHeader(404)
				_, _ = w.Write([]byte(`{"detail":"not found"}`))
				return
			}
			_ = json.NewEncoder(w).Encode(f.capabilities)
		case path == "/scans" && r.Method == "GET":
			if f.scanList != nil {
				_ = json.NewEncoder(w).Encode(f.scanList)
				return
			}
			_ = json.NewEncoder(w).Encode([]map[string]any{{
				"id": fakeScanID, "target_base_url": "http://t", "status": "completed", "progress": 100,
				"finding_counts": map[string]int{"critical": 1, "high": 0, "medium": 0, "low": 0, "info": 0},
				"last_run_at":    nil,
			}})
		case path == fakeScanPath+"/run":
			w.WriteHeader(202)
			_, _ = w.Write([]byte(`{"scan_id":"` + fakeScanID + `","status":"queued"}`))
		case path == fakeScanPath+"/events":
			_ = json.NewEncoder(w).Encode(f.events)
		case path == fakeScanPath+"/findings":
			_ = json.NewEncoder(w).Encode(f.findings)
		case strings.HasPrefix(path, fakeScanPath+"/findings/") && r.Method == "PATCH":
			findingID := strings.TrimPrefix(path, fakeScanPath+"/findings/")
			var in struct {
				Verdict string `json:"verdict"`
			}
			_ = json.Unmarshal(buf.Bytes(), &in)
			for _, finding := range f.findings {
				if finding["id"] == findingID {
					finding["verdict"] = in.Verdict
					_ = json.NewEncoder(w).Encode(finding)
					return
				}
			}
			w.WriteHeader(404)
			_, _ = w.Write([]byte(`{"detail":"not found"}`))
		case path == fakeScanPath+"/findings/summary":
			summary := f.summary
			if summary == nil {
				summary = map[string]any{
					"total": 0, "active": 0, "dismissed": 0,
					"verified_critical": 0, "verified_high": 0,
					"severity": map[string]int{"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0},
				}
			}
			_ = json.NewEncoder(w).Encode(summary)
		case path == fakeScanPath+"/coverage":
			rows := f.coverage
			if rows == nil {
				rows = []map[string]any{}
			}
			_ = json.NewEncoder(w).Encode(rows)
		case path == fakeScanPath+"/cost":
			cost := f.cost
			if cost == nil {
				cost = map[string]any{
					"scan_id": fakeScanID, "total_usd": 0.0,
					"entries": []any{}, "models": []any{},
				}
			}
			_ = json.NewEncoder(w).Encode(cost)
		case path == fakeScanPath+"/runs":
			runs := f.runs
			if runs == nil {
				runs = []map[string]any{}
			}
			_ = json.NewEncoder(w).Encode(runs)
		case strings.HasPrefix(path, fakeScanPath+"/runs/") && strings.HasSuffix(path, "/trace"):
			// One page of the trace, sliced the way the server slices it.
			run, _ := strconv.Atoi(strings.TrimSuffix(strings.TrimPrefix(path, fakeScanPath+"/runs/"), "/trace"))
			offset, _ := strconv.Atoi(r.URL.Query().Get("offset"))
			limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
			if limit < 1 {
				limit = 100
			}
			f.traceOffsets = append(f.traceOffsets, offset)
			rows := f.traceRows
			if offset > len(rows) {
				offset = len(rows)
			}
			end := offset + limit
			if end > len(rows) {
				end = len(rows)
			}
			_ = json.NewEncoder(w).Encode(map[string]any{
				"run_number": run, "total": len(rows), "offset": offset, "rows": rows[offset:end],
			})
		case path == fakeScanPath+"/diff":
			if f.diff == nil {
				w.WriteHeader(409)
				_, _ = w.Write([]byte(`{"detail":"a diff needs two runs of this scan"}`))
				return
			}
			_ = json.NewEncoder(w).Encode(f.diff)
		case path == fakeScanPath+"/sarif":
			_, _ = w.Write([]byte(`{"version":"2.1.0"}`))
		case path == fakeScanPath+"/export":
			_, _ = w.Write([]byte(`{"findings":[]}`))
		case path == fakeScanPath+"/local-runs":
			target := f.claimTarget
			if target == "" {
				target = "http://localhost:9000"
			}
			creds := f.claimCredentials
			if creds == nil {
				creds = []any{
					map[string]any{"name": "alice", "role": "user", "auth_type": "header", "header_name": "Authorization"},
					map[string]any{"name": "admin", "role": "admin", "auth_type": "header", "header_name": "Authorization"},
				}
			}
			w.WriteHeader(201)
			_ = json.NewEncoder(w).Encode(map[string]any{
				"run_id": "r1aaaaaa-bbbb", "run_number": 1, "token": "run-token-xyz",
				"options": map[string]any{}, "max_requests": 750, "requests_per_second": 10,
				"target_base_url": target, "spec_text": "{}", "operations": []any{},
				"credentials": creds,
			})
		case strings.HasPrefix(path, "/runner/runs/") && strings.HasSuffix(path, "/fail"):
			var in struct {
				Cancelled bool `json:"cancelled"`
			}
			_ = json.Unmarshal(buf.Bytes(), &in)
			f.localStatus = "failed"
			if in.Cancelled {
				f.localStatus = "cancelled"
			}
			_, _ = w.Write([]byte(`{"scan_id":"` + fakeScanID + `","status":"failed"}`))
		case path == fakeScanPath+"/credentials" && r.Method == "POST":
			w.WriteHeader(201)
			_, _ = w.Write([]byte(`{}`))
		case strings.HasPrefix(path, fakeScanPath+"/credentials/") && r.Method == "DELETE":
			_, _ = w.Write([]byte(`{"status":"deleted"}`))
		case path == fakeScanPath+"/cancel":
			_, _ = w.Write([]byte(`{}`))
		case path == fakeScanPath && r.Method == "GET":
			status := "completed"
			if f.localStatus != "" {
				status = f.localStatus
			} else if len(f.statuses) > 0 {
				i := f.getCalls
				if i >= len(f.statuses) {
					i = len(f.statuses) - 1
				}
				status = f.statuses[i]
				f.getCalls++
			}
			var reason any
			if f.failure != "" {
				reason = f.failure
			}
			creds := f.credentials
			if creds == nil {
				creds = []map[string]any{}
			}
			out := map[string]any{
				"id": fakeScanID, "target_base_url": "http://t", "status": status,
				"progress": 50, "failure_reason": reason, "operations": []any{},
				"credential_profiles": creds, "cost_usd": f.scanCost,
			}
			_ = json.NewEncoder(w).Encode(out)
		default:
			w.WriteHeader(404)
			_, _ = w.Write([]byte(`{"detail":"not found"}`))
		}
	})
}

func (f *fake) sawRequest(key string) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, r := range f.requests {
		if r == key {
			return true
		}
	}
	return false
}

// indexOf is where a request appears in the log, or -1. Tests use it to check
// ordering (the capabilities probe must precede the run).
func (f *fake) indexOf(key string) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	for i, r := range f.requests {
		if r == key {
			return i
		}
	}
	return -1
}

func (f *fake) count() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.requests)
}

func (f *fake) countRequests(key string) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	n := 0
	for _, r := range f.requests {
		if r == key {
			n++
		}
	}
	return n
}

func (f *fake) tracePages() []int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]int(nil), f.traceOffsets...)
}

type harness struct {
	env    Env
	out    *bytes.Buffer
	errOut *bytes.Buffer
	cfg    string
}

func newHarness(t *testing.T, srv *httptest.Server, stdin string, tty bool) *harness {
	t.Helper()
	h := &harness{out: &bytes.Buffer{}, errOut: &bytes.Buffer{}, cfg: filepath.Join(t.TempDir(), "c.json")}
	h.env = Env{
		Stdin:      strings.NewReader(stdin),
		Stdout:     h.out,
		Stderr:     h.errOut,
		IsTTY:      func() bool { return tty },
		ReadSecret: func(string) (string, error) { return "typed-secret", nil },
		Getenv: func(k string) string {
			switch k {
			case "AIDETECTOR_SERVER":
				return srv.URL
			case "AIDETECTOR_API_KEY":
				return secretKey
			}
			return ""
		},
		ConfigPath:   h.cfg,
		PollInterval: time.Millisecond,
		Now:          time.Now,
		// Every run is local: by default the runner "finishes" at once and the
		// fake server reports the scan's status as the test configured it.
		Docker: func(context.Context, string, []string, io.Reader, io.Writer, io.Writer) error {
			return nil
		},
	}
	return h
}

func (h *harness) run(args ...string) int {
	return Run(context.Background(), args, h.env)
}

func (h *harness) assertNoSecretPrinted(t *testing.T) {
	t.Helper()
	for name, s := range map[string]string{"stdout": h.out.String(), "stderr": h.errOut.String()} {
		if strings.Contains(s, secretKey) || strings.Contains(s, "typed-secret") {
			t.Fatalf("a secret leaked to %s:\n%s", name, s)
		}
	}
}

func TestRunRefusesWithoutAuthorizationAndSendsNothing(t *testing.T) {
	f := &fake{}
	srv := httptest.NewServer(f.handler())
	defer srv.Close()
	h := newHarness(t, srv, "", false) // a pipe: no terminal to confirm on

	if code := h.run("run", fakeScanID); code != ExitUsage {
		t.Fatalf("exit = %d, want %d", code, ExitUsage)
	}
	if !strings.Contains(h.errOut.String(), "--authorized") {
		t.Fatalf("stderr should explain the gate: %q", h.errOut.String())
	}
	if n := f.count(); n != 0 {
		t.Fatalf("a refused run sent %d request(s); the gate must answer before any network call", n)
	}
}

func TestRunPromptsOnATerminalAndHonoursNo(t *testing.T) {
	f := &fake{}
	srv := httptest.NewServer(f.handler())
	defer srv.Close()
	h := newHarness(t, srv, "n\n", true)
	if code := h.run("run", fakeScanID); code != ExitUsage {
		t.Fatalf("exit = %d, want %d", code, ExitUsage)
	}
	if f.sawRequest("POST " + fakeScanPath + "/local-runs") {
		t.Fatal("declining the prompt must not start a run")
	}

	h = newHarness(t, srv, "y\n", true)
	if code := h.run("run", fakeScanID); code != ExitOK {
		t.Fatalf("confirmed run: exit = %d, want 0\n%s", code, h.errOut.String())
	}
	if !f.sawRequest("POST " + fakeScanPath + "/local-runs") {
		t.Fatal("confirming the prompt should start the run")
	}
}

// Writes have one name. --mutate was an alias for --writes; it is gone, so a
// pipeline still passing it fails loudly instead of quietly running read-only.
func TestMutateIsNoLongerAFlag(t *testing.T) {
	f := &fake{}
	srv := httptest.NewServer(f.handler())
	defer srv.Close()
	h := newHarness(t, srv, "", false)
	if code := h.run("run", fakeScanID, "--authorized", "--mutate"); code != ExitUsage {
		t.Fatalf("exit = %d, want %d\n%s", code, ExitUsage, h.errOut.String())
	}
	if _, sent := f.bodies["POST "+fakeScanPath+"/local-runs"]; sent {
		t.Fatal("a refused flag must not claim a run")
	}
	if !strings.Contains(h.errOut.String(), "--mutate is now --writes") {
		t.Fatalf("the error should name the new flag:\n%s", h.errOut.String())
	}
}

func TestRunSendsOnlyTheRequestedPasses(t *testing.T) {
	f := &fake{}
	srv := httptest.NewServer(f.handler())
	defer srv.Close()
	h := newHarness(t, srv, "", false)
	withSiblingDocker(h)
	code := h.run("run", fakeScanID, "--authorized", "--writes", "--kali",
		"--docker-network", "testnet", "--checks", "bola, bfla", "--rps", "5")
	if code != ExitOK {
		t.Fatalf("exit = %d\n%s", code, h.errOut.String())
	}
	var body map[string]any
	if err := json.Unmarshal(f.bodies["POST "+fakeScanPath+"/local-runs"], &body); err != nil {
		t.Fatal(err)
	}
	if body["authorized"] != true || body["mutate"] != true || body["kali"] != true {
		t.Fatalf("body = %v", body)
	}
	if _, set := body["zap"]; set {
		t.Fatalf("a pass the user did not ask for must stay off: %v", body)
	}
	if body["requests_per_second"] != float64(5) {
		t.Fatalf("rps = %v", body["requests_per_second"])
	}
	checks, _ := body["checks"].([]any)
	if len(checks) != 2 || checks[0] != "bola" || checks[1] != "bfla" {
		t.Fatalf("checks = %v", body["checks"])
	}
}

func TestFailOnGatesTheExitCode(t *testing.T) {
	high := map[string]any{"severity": "high", "confidence": "verified", "check": "bola", "title": "BOLA", "verdict": "unreviewed"}
	low := map[string]any{"severity": "low", "confidence": "heuristic", "check": "hdr", "title": "Header", "verdict": "unreviewed"}
	dismissed := map[string]any{"severity": "critical", "confidence": "verified", "check": "x", "title": "FP", "verdict": "dismissed"}
	heurHigh := map[string]any{"severity": "high", "confidence": "heuristic", "check": "inj", "title": "Lead", "verdict": "unreviewed"}

	cases := []struct {
		name     string
		findings []map[string]any
		args     []string
		want     int
	}{
		{"high reaches high", []map[string]any{high, low}, []string{"--fail-on", "high"}, ExitFindings},
		{"only low stays clean", []map[string]any{low}, []string{"--fail-on", "high"}, ExitOK},
		{"dismissed never fails a pipeline", []map[string]any{dismissed}, []string{"--fail-on", "low"}, ExitOK},
		{"verified-only ignores a heuristic lead", []map[string]any{heurHigh}, []string{"--fail-on", "high", "--verified-only"}, ExitOK},
		{"verified-only still fails on proof", []map[string]any{high}, []string{"--fail-on", "high", "--verified-only"}, ExitFindings},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			f := &fake{findings: c.findings}
			srv := httptest.NewServer(f.handler())
			defer srv.Close()
			h := newHarness(t, srv, "", false)
			args := append([]string{"run", fakeScanID, "--authorized"}, c.args...)
			if got := h.run(args...); got != c.want {
				t.Fatalf("exit = %d, want %d\nstdout: %s\nstderr: %s", got, c.want, h.out.String(), h.errOut.String())
			}
		})
	}
}

func TestNewOnlyJudgesOnlyWhatIsNewSincePreviousRun(t *testing.T) {
	old := map[string]any{"severity": "critical", "confidence": "verified", "check": "a", "title": "old debt", "verdict": "unreviewed"}
	diff := map[string]any{"from_run": 1, "to_run": 2, "added": []any{}, "resolved": []any{}, "not_retested": []any{}, "unchanged": []any{old}}
	f := &fake{findings: []map[string]any{old}, diff: &diff}
	srv := httptest.NewServer(f.handler())
	defer srv.Close()
	h := newHarness(t, srv, "", false)
	if got := h.run("run", fakeScanID, "--authorized", "--fail-on", "high", "--new-only"); got != ExitOK {
		t.Fatalf("known debt must not fail --new-only; exit = %d\n%s", got, h.out.String())
	}

	// With a regression in `added`, it fails.
	diff["added"] = []any{map[string]any{"severity": "high", "confidence": "verified", "check": "b", "title": "new", "verdict": "unreviewed"}}
	h = newHarness(t, srv, "", false)
	if got := h.run("run", fakeScanID, "--authorized", "--fail-on", "high", "--new-only"); got != ExitFindings {
		t.Fatalf("a new high must fail; exit = %d", got)
	}

	// A first run has no diff (409): everything is new.
	f.diff = nil
	h = newHarness(t, srv, "", false)
	if got := h.run("run", fakeScanID, "--authorized", "--fail-on", "high", "--new-only"); got != ExitFindings {
		t.Fatalf("a first run has nothing to compare with, so its criticals count; exit = %d", got)
	}
}

func TestFlagCombinationsAreRefused(t *testing.T) {
	srv := httptest.NewServer((&fake{}).handler())
	defer srv.Close()
	for _, args := range [][]string{
		{"run", fakeScanID, "--authorized", "--fail-on", "urgent"}, // bad severity
		{"run", fakeScanID, "--authorized", "--verified-only"},     // needs --fail-on
		{"run", fakeScanID, "--authorized", "--rps", "500"},        // out of range
		{"run", "--authorized"},                                    // no ID
	} {
		h := newHarness(t, srv, "", false)
		if got := h.run(args...); got != ExitUsage {
			t.Errorf("%v: exit = %d, want %d", args, got, ExitUsage)
		}
	}
}

func TestWaitEndsWithTheRightCode(t *testing.T) {
	t.Run("failed run", func(t *testing.T) {
		f := &fake{statuses: []string{"running", "failed"}, failure: "worker lost"}
		srv := httptest.NewServer(f.handler())
		defer srv.Close()
		h := newHarness(t, srv, "", false)
		if got := h.run("run", fakeScanID, "--authorized"); got != ExitFailed {
			t.Fatalf("exit = %d, want %d", got, ExitFailed)
		}
		if !strings.Contains(h.errOut.String(), "worker lost") {
			t.Fatalf("the failure reason should reach the user: %q", h.errOut.String())
		}
	})
	t.Run("timeout", func(t *testing.T) {
		f := &fake{statuses: []string{"running"}}
		srv := httptest.NewServer(f.handler())
		defer srv.Close()
		h := newHarness(t, srv, "", false)
		clock := time.Now()
		h.env.Now = func() time.Time { clock = clock.Add(time.Minute); return clock }
		if got := h.run("wait", fakeScanID, "--timeout", "3m"); got != ExitTimeout {
			t.Fatalf("exit = %d, want %d", got, ExitTimeout)
		}
	})
}

func TestAnUnauthorizedKeyGetsAHint(t *testing.T) {
	f := &fake{apiKey: "a-different-key"}
	srv := httptest.NewServer(f.handler())
	defer srv.Close()
	h := newHarness(t, srv, "", false)
	if got := h.run("scans", "list"); got != ExitUsage {
		t.Fatalf("exit = %d, want %d", got, ExitUsage)
	}
	if !strings.Contains(h.errOut.String(), "aidetector login") {
		t.Fatalf("a 401 should point at login: %q", h.errOut.String())
	}
	h.assertNoSecretPrinted(t)
}

func TestLoginSavesOwnerOnlyAndNeverEchoesTheKey(t *testing.T) {
	f := &fake{apiKey: secretKey}
	srv := httptest.NewServer(f.handler())
	defer srv.Close()
	h := newHarness(t, srv, secretKey+"\n", false)
	h.env.Getenv = func(string) string { return "" } // login must not rely on env
	if got := h.run("login", "--server", srv.URL, "--key-stdin"); got != ExitOK {
		t.Fatalf("login exit = %d\n%s", got, h.errOut.String())
	}
	if runtime.GOOS != "windows" {
		info, err := os.Stat(h.cfg)
		if err != nil || info.Mode().Perm() != 0o600 {
			t.Fatalf("config = %v, %v; want 0600", info, err)
		}
	}
	h.assertNoSecretPrinted(t)

	// status reports that a key is set — never the key.
	h.out.Reset()
	h.errOut.Reset()
	if got := h.run("status"); got != ExitOK {
		t.Fatalf("status exit = %d\n%s", got, h.errOut.String())
	}
	if !strings.Contains(h.out.String(), "api key: set") {
		t.Fatalf("status = %q", h.out.String())
	}
	h.assertNoSecretPrinted(t)

	if got := h.run("logout"); got != ExitOK {
		t.Fatal("logout failed")
	}
	if _, err := os.Stat(h.cfg); !os.IsNotExist(err) {
		t.Fatal("logout should delete the saved key")
	}
}

func TestLoginRefusesABadKeyAndSavesNothing(t *testing.T) {
	f := &fake{apiKey: "the-real-key"}
	srv := httptest.NewServer(f.handler())
	defer srv.Close()
	h := newHarness(t, srv, "wrong-key\n", false)
	h.env.Getenv = func(string) string { return "" }
	if got := h.run("login", "--server", srv.URL, "--key-stdin"); got != ExitUsage {
		t.Fatalf("exit = %d, want %d", got, ExitUsage)
	}
	if _, err := os.Stat(h.cfg); !os.IsNotExist(err) {
		t.Fatal("a rejected key must not be saved")
	}
}

func TestLoginRefusesPlainHTTPToARemoteHost(t *testing.T) {
	srv := httptest.NewServer((&fake{}).handler())
	defer srv.Close()
	h := newHarness(t, srv, "k\n", false)
	if got := h.run("login", "--server", "http://scan.example.com", "--key-stdin"); got != ExitUsage {
		t.Fatalf("exit = %d, want %d", got, ExitUsage)
	}
	if !strings.Contains(h.errOut.String(), "clear text") {
		t.Fatalf("stderr = %q", h.errOut.String())
	}
}

func TestCredAddTakesTheSecretFromStdinOnly(t *testing.T) {
	f := &fake{}
	srv := httptest.NewServer(f.handler())
	defer srv.Close()
	h := newHarness(t, srv, "cred-secret-value\n", false)
	if got := h.run("cred", "add", fakeScanID, "--name", "alice", "--role", "user", "--secret-stdin"); got != ExitOK {
		t.Fatalf("exit = %d\n%s", got, h.errOut.String())
	}
	var sent map[string]any
	_ = json.Unmarshal(f.bodies["POST "+fakeScanPath+"/credentials"], &sent)
	if sent["secret"] != "cred-secret-value" || sent["role"] != "user" {
		t.Fatalf("sent = %v", sent)
	}
	if strings.Contains(h.out.String()+h.errOut.String(), "cred-secret-value") {
		t.Fatal("the credential secret was echoed")
	}

	// No flag exists to pass the secret on the command line.
	h = newHarness(t, srv, "", false)
	if got := h.run("cred", "add", fakeScanID, "--name", "a", "--role", "r", "--secret", "oops"); got != ExitUsage {
		t.Fatalf("a --secret flag must not exist; exit = %d", got)
	}
	// And a pipe with no --secret-stdin is refused rather than guessed.
	h = newHarness(t, srv, "", false)
	if got := h.run("cred", "add", fakeScanID, "--name", "a", "--role", "r"); got != ExitUsage {
		t.Fatalf("exit = %d, want %d", got, ExitUsage)
	}
}

func TestScansRmNeedsYesWithoutATerminal(t *testing.T) {
	f := &fake{}
	srv := httptest.NewServer(f.handler())
	defer srv.Close()
	h := newHarness(t, srv, "", false)
	if got := h.run("scans", "rm", fakeScanID); got != ExitUsage {
		t.Fatalf("exit = %d, want %d", got, ExitUsage)
	}
	if f.sawRequest("DELETE " + fakeScanPath) {
		t.Fatal("nothing may be deleted without confirmation")
	}
}

func TestReportWritesAnOwnerOnlyFile(t *testing.T) {
	f := &fake{}
	srv := httptest.NewServer(f.handler())
	defer srv.Close()
	h := newHarness(t, srv, "", false)
	out := filepath.Join(t.TempDir(), "r.sarif")
	if got := h.run("report", fakeScanID, "--format", "sarif", "-o", out); got != ExitOK {
		t.Fatalf("exit = %d\n%s", got, h.errOut.String())
	}
	data, err := os.ReadFile(out)
	if err != nil || !strings.Contains(string(data), "2.1.0") {
		t.Fatalf("report = %q, %v", data, err)
	}
	if runtime.GOOS != "windows" {
		info, _ := os.Stat(out)
		if info.Mode().Perm() != 0o600 {
			t.Fatalf("report mode = %#o, want 0600", info.Mode().Perm())
		}
	}
	if got := h.run("report", fakeScanID, "--format", "pdf", "-o", "-"); got != ExitUsage {
		t.Fatalf("a PDF to stdout must be refused; exit = %d", got)
	}
	if got := h.run("report", fakeScanID, "--format", "docx", "-o", out); got != ExitUsage {
		t.Fatalf("an unknown format must be refused; exit = %d", got)
	}
}

func TestUnknownCommandAndHelp(t *testing.T) {
	srv := httptest.NewServer((&fake{}).handler())
	defer srv.Close()
	h := newHarness(t, srv, "", false)
	if got := h.run("frobnicate"); got != ExitUsage {
		t.Fatalf("exit = %d, want %d", got, ExitUsage)
	}
	h = newHarness(t, srv, "", false)
	if got := h.run("help"); got != ExitOK || !strings.Contains(h.out.String(), "exit codes") {
		t.Fatalf("help: exit = %d, out = %q", got, h.out.String())
	}
}

// detailedFinding is a FindingOut with every field `findings show` renders.
func detailedFinding() map[string]any {
	return map[string]any{
		"id":           "11111111-aaaa-bbbb-cccc-dddddddddddd",
		"operation_id": nil,
		"check":        "bola",
		"fingerprint":  "fpBOLA0001",
		"owasp_id":     "API1:2023",
		"severity":     "high",
		"confidence":   "verified",
		"title":        "BOLA on /orders",
		"description":  "Another user's order can be read.",
		"evidence":     map[string]any{"request": map[string]any{"path": "/orders/42"}},
		"remediation":  "Check the order owner before returning it.",
		"references":   []any{"https://owasp.org/API-Security"},
		"verdict":      "unreviewed",
		"ai_rationale": "The response body belongs to another user.",
		"created_at":   "2026-01-02T03:04:05Z",
		"premium":      false,
	}
}

func TestFindingsTableShowsShortIDAndFiltersByCheck(t *testing.T) {
	hdr := map[string]any{"id": "22222222-aaaa-bbbb-cccc-dddddddddddd", "check": "headers", "severity": "low", "confidence": "heuristic", "title": "CSP missing", "verdict": "unreviewed"}
	f := &fake{findings: []map[string]any{detailedFinding(), hdr}}
	srv := httptest.NewServer(f.handler())
	defer srv.Close()

	h := newHarness(t, srv, "", false)
	if got := h.run("findings", fakeScanID); got != ExitOK {
		t.Fatalf("exit = %d\n%s", got, h.errOut.String())
	}
	out := h.out.String()
	for _, want := range []string{"ID", "11111111", "22222222", "2 finding(s)"} {
		if !strings.Contains(out, want) {
			t.Fatalf("findings table is missing %q:\n%s", want, out)
		}
	}
	if !strings.Contains(h.errOut.String(), "findings show 11111111 <ID>") {
		t.Fatalf("stderr should point at findings show: %q", h.errOut.String())
	}

	h = newHarness(t, srv, "", false)
	if got := h.run("findings", fakeScanID, "--check", "bola"); got != ExitOK {
		t.Fatalf("exit = %d\n%s", got, h.errOut.String())
	}
	if out := h.out.String(); strings.Contains(out, "CSP missing") || !strings.Contains(out, "BOLA on /orders") {
		t.Fatalf("--check should keep only that check:\n%s", out)
	}
	if !strings.Contains(h.out.String(), "1 finding(s)") {
		t.Fatalf("the footer should count what was shown:\n%s", h.out.String())
	}
}

func TestFindingsShowPrintsTheFullFinding(t *testing.T) {
	f := &fake{findings: []map[string]any{detailedFinding()}}
	srv := httptest.NewServer(f.handler())
	defer srv.Close()

	h := newHarness(t, srv, "", false)
	if got := h.run("findings", "show", fakeScanID, "11111111"); got != ExitOK {
		t.Fatalf("exit = %d\n%s", got, h.errOut.String())
	}
	out := h.out.String()
	for _, want := range []string{
		"BOLA on /orders",
		"high · verified · bola · API1:2023 · unreviewed",
		"fingerprint: fpBOLA0001",
		"remediation:",
		"  Check the order owner before returning it.",
		"references:",
		"  https://owasp.org/API-Security",
		"ai rationale:",
		"/orders/42",
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("finding detail is missing %q:\n%s", want, out)
		}
	}

	// A fingerprint prefix names the same finding.
	h = newHarness(t, srv, "", false)
	if got := h.run("findings", "show", fakeScanID, "fpBOL"); got != ExitOK {
		t.Fatalf("fingerprint lookup: exit = %d\n%s", got, h.errOut.String())
	}

	// --json is the FindingOut as received, not this struct's subset.
	h = newHarness(t, srv, "", false)
	if got := h.run("findings", "show", fakeScanID, "11111111", "--json"); got != ExitOK {
		t.Fatalf("json: exit = %d\n%s", got, h.errOut.String())
	}
	var got map[string]any
	if err := json.Unmarshal(h.out.Bytes(), &got); err != nil {
		t.Fatalf("--json is not JSON: %v\n%s", err, h.out.String())
	}
	if got["id"] != "11111111-aaaa-bbbb-cccc-dddddddddddd" || got["created_at"] != "2026-01-02T03:04:05Z" {
		t.Fatalf("--json should print the server's object: %v", got)
	}
}

func TestFindingsShowRefusesAnAmbiguousPrefix(t *testing.T) {
	a := detailedFinding()
	b := detailedFinding()
	b["id"] = "11111112-aaaa-bbbb-cccc-dddddddddddd"
	b["fingerprint"] = "fpBOLA0002"
	b["title"] = "BOLA on /invoices"
	f := &fake{findings: []map[string]any{a, b}}
	srv := httptest.NewServer(f.handler())
	defer srv.Close()

	h := newHarness(t, srv, "", false)
	if got := h.run("findings", "show", fakeScanID, "1111"); got != ExitUsage {
		t.Fatalf("exit = %d, want %d", got, ExitUsage)
	}
	errOut := h.errOut.String()
	if !strings.Contains(errOut, "11111111") || !strings.Contains(errOut, "11111112") {
		t.Fatalf("an ambiguous prefix should list the matches: %q", errOut)
	}

	h = newHarness(t, srv, "", false)
	if got := h.run("findings", "show", fakeScanID, "zzzz"); got != ExitUsage {
		t.Fatalf("a missing finding: exit = %d, want %d", got, ExitUsage)
	}
	h = newHarness(t, srv, "", false)
	if got := h.run("findings", "show", fakeScanID, "111"); got != ExitUsage {
		t.Fatalf("a too-short prefix: exit = %d, want %d", got, ExitUsage)
	}
}

func TestFindingsDismissWithoutTTYOrYesSendsNoPatch(t *testing.T) {
	f := &fake{findings: []map[string]any{detailedFinding()}}
	srv := httptest.NewServer(f.handler())
	defer srv.Close()

	h := newHarness(t, srv, "", false) // a pipe: no terminal to confirm on
	if got := h.run("findings", "dismiss", fakeScanID, "11111111"); got != ExitUsage {
		t.Fatalf("exit = %d, want %d", got, ExitUsage)
	}
	if n := f.countRequests("PATCH " + fakeScanPath + "/findings/11111111-aaaa-bbbb-cccc-dddddddddddd"); n != 0 {
		t.Fatalf("an unconfirmed dismissal sent %d PATCH(es)", n)
	}
	if !strings.Contains(h.errOut.String(), "person's call") {
		t.Fatalf("the refusal should say dismissal is a person's call: %q", h.errOut.String())
	}
}

func TestFindingsDismissWithYesSendsTheVerdict(t *testing.T) {
	f := &fake{findings: []map[string]any{detailedFinding()}}
	srv := httptest.NewServer(f.handler())
	defer srv.Close()

	h := newHarness(t, srv, "", false)
	if got := h.run("findings", "dismiss", fakeScanID, "11111111", "--yes"); got != ExitOK {
		t.Fatalf("exit = %d\n%s", got, h.errOut.String())
	}
	key := "PATCH " + fakeScanPath + "/findings/11111111-aaaa-bbbb-cccc-dddddddddddd"
	if n := f.countRequests(key); n != 1 {
		t.Fatalf("PATCH count = %d, want 1", n)
	}
	var sent map[string]any
	if err := json.Unmarshal(f.bodies[key], &sent); err != nil {
		t.Fatal(err)
	}
	if sent["verdict"] != "dismissed" {
		t.Fatalf("body = %v, want the dismissed verdict", sent)
	}
	if out := h.out.String(); !strings.Contains(out, "dismissed  11111111  high  BOLA on /orders") {
		t.Fatalf("result line = %q", out)
	}
	if !strings.Contains(h.errOut.String(), "undo: aidetector findings reopen 11111111 11111111") {
		t.Fatalf("dismiss should print the undo line: %q", h.errOut.String())
	}

	// --json is the updated FindingOut, including fields this struct omits.
	h = newHarness(t, srv, "", false)
	if got := h.run("findings", "dismiss", fakeScanID, "11111111", "--yes", "--json"); got != ExitOK {
		t.Fatalf("json: exit = %d\n%s", got, h.errOut.String())
	}
	var got []map[string]any
	if err := json.Unmarshal(h.out.Bytes(), &got); err != nil {
		t.Fatalf("--json is not a JSON list: %v\n%s", err, h.out.String())
	}
	if len(got) != 1 || got[0]["verdict"] != "dismissed" || got[0]["created_at"] != "2026-01-02T03:04:05Z" {
		t.Fatalf("--json should print the server's FindingOut: %v", got)
	}
}

func TestFindingsTriageRefusesAnAmbiguousReferenceBeforeAnyPatch(t *testing.T) {
	a := detailedFinding()
	b := detailedFinding()
	b["id"] = "11111112-aaaa-bbbb-cccc-dddddddddddd"
	b["fingerprint"] = "fpBOLA0002"
	b["title"] = "BOLA on /invoices"
	f := &fake{findings: []map[string]any{a, b}}
	srv := httptest.NewServer(f.handler())
	defer srv.Close()

	h := newHarness(t, srv, "", false)
	if got := h.run("findings", "dismiss", fakeScanID, "1111", "--yes"); got != ExitUsage {
		t.Fatalf("exit = %d, want %d", got, ExitUsage)
	}
	if n := f.countRequests("PATCH "+fakeScanPath+"/findings/11111111-aaaa-bbbb-cccc-dddddddddddd") +
		f.countRequests("PATCH "+fakeScanPath+"/findings/11111112-aaaa-bbbb-cccc-dddddddddddd"); n != 0 {
		t.Fatalf("an ambiguous reference sent %d PATCH(es)", n)
	}
	if errOut := h.errOut.String(); !strings.Contains(errOut, "11111111") || !strings.Contains(errOut, "11111112") {
		t.Fatalf("the refusal should list the matches: %q", errOut)
	}
}

func TestFindingsReopenSendsUnreviewed(t *testing.T) {
	finding := detailedFinding()
	finding["verdict"] = "dismissed"
	f := &fake{findings: []map[string]any{finding}}
	srv := httptest.NewServer(f.handler())
	defer srv.Close()

	h := newHarness(t, srv, "", false) // reopen never prompts
	if got := h.run("findings", "reopen", fakeScanID, "fpBOL"); got != ExitOK {
		t.Fatalf("exit = %d\n%s", got, h.errOut.String())
	}
	key := "PATCH " + fakeScanPath + "/findings/11111111-aaaa-bbbb-cccc-dddddddddddd"
	var sent map[string]any
	if err := json.Unmarshal(f.bodies[key], &sent); err != nil {
		t.Fatal(err)
	}
	if sent["verdict"] != "unreviewed" {
		t.Fatalf("body = %v, want unreviewed", sent)
	}
	if out := h.out.String(); !strings.Contains(out, "reopened  11111111  high  BOLA on /orders") {
		t.Fatalf("result line = %q", out)
	}
}

func TestFindingsDismissPromptNoSendsNothing(t *testing.T) {
	f := &fake{findings: []map[string]any{detailedFinding()}}
	srv := httptest.NewServer(f.handler())
	defer srv.Close()

	h := newHarness(t, srv, "n\n", true)
	if got := h.run("findings", "dismiss", fakeScanID, "11111111"); got != ExitUsage {
		t.Fatalf("exit = %d, want %d", got, ExitUsage)
	}
	if f.sawRequest("PATCH " + fakeScanPath + "/findings/11111111-aaaa-bbbb-cccc-dddddddddddd") {
		t.Fatal("declining the prompt must not send a verdict")
	}
	if !strings.Contains(h.errOut.String(), "not dismissed") {
		t.Fatalf("stderr = %q", h.errOut.String())
	}
}

func TestFindingsDismissCollapsesDuplicateReferences(t *testing.T) {
	f := &fake{findings: []map[string]any{detailedFinding()}}
	srv := httptest.NewServer(f.handler())
	defer srv.Close()

	h := newHarness(t, srv, "", false)
	// The ID and the fingerprint prefix name the same finding.
	if got := h.run("findings", "dismiss", fakeScanID, "11111111", "fpBOL", "--yes"); got != ExitOK {
		t.Fatalf("exit = %d\n%s", got, h.errOut.String())
	}
	if n := f.countRequests("PATCH " + fakeScanPath + "/findings/11111111-aaaa-bbbb-cccc-dddddddddddd"); n != 1 {
		t.Fatalf("duplicate references sent %d PATCH(es), want 1", n)
	}
	if out := h.out.String(); strings.Count(out, "dismissed  11111111") != 1 {
		t.Fatalf("the finding should be reported once:\n%s", out)
	}
}

func TestFindingsTableMarksConfirmed(t *testing.T) {
	finding := detailedFinding()
	finding["verdict"] = "confirmed"
	f := &fake{findings: []map[string]any{finding}}
	srv := httptest.NewServer(f.handler())
	defer srv.Close()

	h := newHarness(t, srv, "", false)
	if got := h.run("findings", fakeScanID); got != ExitOK {
		t.Fatalf("exit = %d\n%s", got, h.errOut.String())
	}
	if !strings.Contains(h.out.String(), "[confirmed]") {
		t.Fatalf("the table should mark a confirmed finding:\n%s", h.out.String())
	}
}

func TestRunsShowsPassesAndGaps(t *testing.T) {
	run2 := map[string]any{
		"id":             "run-2",
		"run_number":     2,
		"status":         "completed",
		"started_at":     "2026-01-02T03:00:00Z",
		"finished_at":    "2026-01-02T03:10:30Z",
		"findings_count": 3,
		"requests":       120,
		"options":        map[string]any{"mutate": true, "authorized": true, "zap": false, "checks": []any{"bola"}},
		"executor":       map[string]any{},
		"gaps":           map[string]any{"not_run": []any{"zap", "kali"}, "budget_exhausted": true},
	}
	run1 := map[string]any{
		"id":          "run-1",
		"run_number":  1,
		"status":      "cancelled",
		"started_at":  "2026-01-02T02:00:00Z",
		"finished_at": nil,
		"options":     map[string]any{},
		"executor":    map[string]any{"kind": "local_runner", "version": "1.0"},
		"gaps":        map[string]any{"not_run": []any{}, "budget_exhausted": false},
	}
	f := &fake{runs: []map[string]any{run2, run1}}
	srv := httptest.NewServer(f.handler())
	defer srv.Close()

	h := newHarness(t, srv, "", false)
	if got := h.run("runs", fakeScanID); got != ExitOK {
		t.Fatalf("exit = %d\n%s", got, h.errOut.String())
	}
	out := h.out.String()
	for _, want := range []string{
		"RUN", "STATUS", "STARTED", "DURATION", "FINDINGS", "REQUESTS", "EXECUTOR", "PASSES",
		"writes", "10m30s", "local",
		"run 2: did not run: zap, kali; request budget exhausted",
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("runs table is missing %q:\n%s", want, out)
		}
	}
	if strings.Contains(out, "authorized") {
		t.Fatalf("the authorization answer is not a pass:\n%s", out)
	}
	if strings.Contains(out, "run 1:") {
		t.Fatalf("a run without gaps gets no line:\n%s", out)
	}

	h = newHarness(t, srv, "", false)
	if got := h.run("runs", fakeScanID, "--json"); got != ExitOK {
		t.Fatalf("json: exit = %d\n%s", got, h.errOut.String())
	}
	var raws []map[string]any
	if err := json.Unmarshal(h.out.Bytes(), &raws); err != nil || len(raws) != 2 {
		t.Fatalf("--json = %q, %v; want the raw list", h.out.String(), err)
	}

	h = newHarness(t, srv, "", false)
	if got := h.run("runs", fakeScanID, "--limit", "0"); got != ExitUsage {
		t.Fatalf("--limit 0: exit = %d, want %d", got, ExitUsage)
	}
}

func TestWaitAttachesToTheCurrentRun(t *testing.T) {
	high := map[string]any{"severity": "high", "confidence": "verified", "check": "bola", "title": "BOLA", "verdict": "unreviewed"}

	t.Run("a completed scan gates without waiting", func(t *testing.T) {
		f := &fake{findings: []map[string]any{high}}
		srv := httptest.NewServer(f.handler())
		defer srv.Close()
		h := newHarness(t, srv, "", false)
		if got := h.run("wait", fakeScanID, "--fail-on", "high"); got != ExitFindings {
			t.Fatalf("exit = %d, want %d\n%s", got, ExitFindings, h.out.String())
		}
		if f.sawRequest("POST " + fakeScanPath + "/local-runs") {
			t.Fatal("wait must attach to a run, never start one")
		}
	})

	t.Run("a running scan streams to completion", func(t *testing.T) {
		f := &fake{
			statuses: []string{"running", "completed"},
			events:   []map[string]any{{"stage": "engine", "pct": 40, "message": "running bola", "created_at": "t"}},
		}
		srv := httptest.NewServer(f.handler())
		defer srv.Close()
		h := newHarness(t, srv, "", false)
		if got := h.run("wait", fakeScanID); got != ExitOK {
			t.Fatalf("exit = %d, want %d\n%s", got, ExitOK, h.errOut.String())
		}
		if !strings.Contains(h.errOut.String(), "running bola") {
			t.Fatalf("events should stream to stderr: %q", h.errOut.String())
		}
	})

	t.Run("flag validation matches run", func(t *testing.T) {
		srv := httptest.NewServer((&fake{}).handler())
		defer srv.Close()
		for _, args := range [][]string{
			{"wait", fakeScanID, "--verified-only"},
			{"wait", fakeScanID, "--fail-on", "urgent"},
			{"wait"},
		} {
			h := newHarness(t, srv, "", false)
			if got := h.run(args...); got != ExitUsage {
				t.Errorf("%v: exit = %d, want %d", args, got, ExitUsage)
			}
		}
	})
}

func TestDiffListsNotRetestedAndUnmatchable(t *testing.T) {
	notRetested := map[string]any{
		"severity":    "medium",
		"confidence":  "heuristic",
		"check":       "zap",
		"fingerprint": "fp1",
		"title":       "ZAP lead",
		"verdict":     "unreviewed",
	}
	diff := map[string]any{
		"from_run":         1,
		"to_run":           2,
		"added":            []any{},
		"resolved":         []any{},
		"not_retested":     []any{notRetested},
		"unchanged":        []any{},
		"options_changed":  false,
		"executor_changed": false,
		"unmatchable":      2,
	}
	f := &fake{diff: &diff}
	srv := httptest.NewServer(f.handler())
	defer srv.Close()
	h := newHarness(t, srv, "", false)
	if got := h.run("diff", fakeScanID); got != ExitOK {
		t.Fatalf("exit = %d\n%s", got, h.errOut.String())
	}
	out := h.out.String()
	if !strings.Contains(out, "  ? medium") || !strings.Contains(out, "ZAP lead") {
		t.Fatalf("not-retested findings should be listed:\n%s", out)
	}
	if !strings.Contains(out, "unmatchable: 2") {
		t.Fatalf("the unmatchable count should show:\n%s", out)
	}
}

// wait attaches to a run this process did not start, so Ctrl-C must leave it
// going; run --wait started its own run and cancels it.
func TestInterruptDetachesWaitButCancelsRun(t *testing.T) {
	for _, tc := range []struct {
		detach     bool
		wantCancel bool
	}{{detach: true, wantCancel: false}, {detach: false, wantCancel: true}} {
		f := &fake{}
		srv := httptest.NewServer(f.handler())
		h := newHarness(t, srv, "", false)
		c, err := h.env.client()
		if err != nil {
			t.Fatal(err)
		}
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		if got := waitForRun(ctx, &h.env, c, fakeScanID, time.Minute, 5, tc.detach); got != ExitFailed {
			t.Fatalf("detach=%v: exit = %d, want %d", tc.detach, got, ExitFailed)
		}
		if got := f.sawRequest("POST " + fakeScanPath + "/cancel"); got != tc.wantCancel {
			t.Fatalf("detach=%v: cancel sent = %v, want %v\n%s", tc.detach, got, tc.wantCancel, h.errOut.String())
		}
		srv.Close()
	}
}

func TestFindingsShowUsesTheProjectScan(t *testing.T) {
	f := &fake{findings: []map[string]any{{
		"id": "9d41aaaa-0000-0000-0000-000000000000", "severity": "high", "confidence": "verified",
		"check": "bola", "title": "BOLA on GET /a/{id}", "verdict": "unreviewed", "remediation": "check ownership",
	}}}
	srv := httptest.NewServer(f.handler())
	defer srv.Close()
	h := newHarness(t, srv, "", false)
	h.env.Dir = t.TempDir()
	writeFile(t, h.env.Dir, "aidetector.yml", "target: http://t\n")
	if got := h.run("findings", "show", "9d41"); got != ExitOK {
		t.Fatalf("exit = %d\n%s", got, h.errOut.String())
	}
	if !strings.Contains(h.out.String(), "check ownership") {
		t.Fatalf("finding detail missing remediation:\n%s", h.out.String())
	}
}

func TestUnattendedDeleteNeedsTheFullScanID(t *testing.T) {
	f := &fake{}
	srv := httptest.NewServer(f.handler())
	defer srv.Close()
	h := newHarness(t, srv, "", false)
	if got := h.run("scans", "rm", "1111", "--yes"); got != ExitUsage {
		t.Fatalf("exit = %d, want %d", got, ExitUsage)
	}
	if f.sawRequest("DELETE " + fakeScanPath) {
		t.Fatal("a prefix with --yes must not delete")
	}
	h.run("scans", "rm", fakeScanID, "--yes")
	if !f.sawRequest("DELETE " + fakeScanPath) {
		t.Fatalf("the full ID with --yes should delete:\n%s", h.errOut.String())
	}
}

// Finding titles and progress messages carry text from the scanned target; a
// hostile one must not be able to drive the user's terminal.
func TestTargetTextCannotEmitTerminalEscapes(t *testing.T) {
	f := &fake{findings: []map[string]any{{
		"id": "9d41aaaa-0000-0000-0000-000000000000", "severity": "high", "confidence": "verified",
		"check": "bola", "title": "BOLA \x1b]0;pwned\x07on \x1b[2J/a", "verdict": "unreviewed",
		"remediation": "fix\x1b[31m it",
	}}}
	srv := httptest.NewServer(f.handler())
	defer srv.Close()
	h := newHarness(t, srv, "", false)
	h.run("findings", fakeScanID)
	h.run("findings", "show", fakeScanID, "9d41")
	if strings.ContainsRune(h.out.String(), '\x1b') || strings.ContainsRune(h.out.String(), '\x07') {
		t.Fatalf("a control character reached the terminal: %q", h.out.String())
	}
}

func TestHelpNamesWhatAFlagTakes(t *testing.T) {
	h := newHarness(t, httptest.NewServer(http.NotFoundHandler()), "", false)
	if got := h.run("run", "-h"); got != ExitOK {
		t.Fatalf("exit = %d", got)
	}
	for _, want := range []string{"--checks KEYS", "--fail-on SEV", "--docker-network NETWORK"} {
		if !strings.Contains(h.out.String(), want) {
			t.Fatalf("help is missing %q:\n%s", want, h.out.String())
		}
	}
	if strings.Contains(h.out.String(), " string ") {
		t.Fatalf("a flag still shows the bare type name:\n%s", h.out.String())
	}
}

// FastAPI answers an unknown route with a bare "Not Found"; that means the
// server predates this CLI, which is a different fix from a missing scan.
func TestUnknownRouteHintsAtAnOlderServer(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(404)
		_, _ = w.Write([]byte(`{"detail":"Not Found"}`))
	}))
	defer srv.Close()
	h := newHarness(t, srv, "", false)
	if got := h.run("runs", fakeScanID); got != ExitUsage {
		t.Fatalf("exit = %d", got)
	}
	if !strings.Contains(h.errOut.String(), "older than this CLI") {
		t.Fatalf("expected the older-server hint: %q", h.errOut.String())
	}
}

func TestSpecFetchSaysWhenTheTargetIsUnreachable(t *testing.T) {
	ln := httptest.NewServer(http.NotFoundHandler())
	addr := ln.URL
	ln.Close() // a port that refuses connections
	_, _, err := fetchSpec(context.Background(), addr)
	if !errors.Is(err, errTargetUnreachable) {
		t.Fatalf("err = %v, want errTargetUnreachable", err)
	}
}

func saveProfiles(t *testing.T, path string, st config.Store) {
	t.Helper()
	if err := config.Save(path, st); err != nil {
		t.Fatal(err)
	}
}

func TestLoginSavesIntoTheNamedProfileAndMakesItCurrent(t *testing.T) {
	f := &fake{apiKey: secretKey}
	srv := httptest.NewServer(f.handler())
	defer srv.Close()
	h := newHarness(t, srv, secretKey+"\n", false)
	h.env.Getenv = func(string) string { return "" } // login must not rely on env
	if got := h.run("login", "--server", srv.URL, "--profile", "staging", "--key-stdin"); got != ExitOK {
		t.Fatalf("login exit = %d\n%s", got, h.errOut.String())
	}
	st, err := config.ReadStore(h.cfg)
	if err != nil {
		t.Fatal(err)
	}
	if st.Current != "staging" || st.Profiles["staging"].Server != srv.URL ||
		st.Profiles["staging"].APIKey != secretKey {
		t.Fatalf("saved = %+v", st)
	}
	if _, ok := st.Profiles["default"]; ok {
		t.Fatalf("--profile must not also write default: %+v", st)
	}

	h.out.Reset()
	h.errOut.Reset()
	if got := h.run("status"); got != ExitOK {
		t.Fatalf("status exit = %d\n%s", got, h.errOut.String())
	}
	if !strings.Contains(h.out.String(), "profile: staging") {
		t.Fatalf("status = %q", h.out.String())
	}
	h.assertNoSecretPrinted(t)
}

func TestProfileListNeverPrintsTheKey(t *testing.T) {
	f := &fake{}
	srv := httptest.NewServer(f.handler())
	defer srv.Close()
	h := newHarness(t, srv, "", false)
	saveProfiles(t, h.cfg, config.Store{Current: "staging", Profiles: map[string]config.Profile{
		"default": {Server: srv.URL, APIKey: secretKey},
		"staging": {Server: srv.URL},
	}})

	if got := h.run("profile", "list"); got != ExitOK {
		t.Fatalf("exit = %d\n%s", got, h.errOut.String())
	}
	out := h.out.String()
	for _, want := range []string{"NAME", "SERVER", "KEY", "default", "staging", "* staging", "set", "none"} {
		if !strings.Contains(out, want) {
			t.Fatalf("profile list is missing %q:\n%s", want, out)
		}
	}
	h.assertNoSecretPrinted(t)
	if strings.Contains(out, "prod-key") || strings.Contains(out, secretKey) {
		t.Fatalf("profile list printed a key:\n%s", out)
	}
}

func TestProfileUseSwitchesTheCurrentProfile(t *testing.T) {
	f := &fake{}
	srv := httptest.NewServer(f.handler())
	defer srv.Close()
	h := newHarness(t, srv, "", false)
	h.env.Getenv = func(string) string { return "" }
	saveProfiles(t, h.cfg, config.Store{Current: "default", Profiles: map[string]config.Profile{
		"default": {Server: srv.URL},
		"staging": {Server: srv.URL},
	}})

	if got := h.run("profile", "use", "staging"); got != ExitOK {
		t.Fatalf("exit = %d\n%s", got, h.errOut.String())
	}
	st, err := config.ReadStore(h.cfg)
	if err != nil {
		t.Fatal(err)
	}
	if st.Current != "staging" {
		t.Fatalf("current = %q, want staging", st.Current)
	}

	h.out.Reset()
	if got := h.run("status"); got != ExitOK {
		t.Fatalf("status exit = %d\n%s", got, h.errOut.String())
	}
	if !strings.Contains(h.out.String(), "profile: staging\n") {
		t.Fatalf("status = %q", h.out.String())
	}

	if got := h.run("profile", "use", "qa"); got != ExitUsage {
		t.Fatalf("unknown profile exit = %d, want %d", got, ExitUsage)
	}
	if errOut := h.errOut.String(); !strings.Contains(errOut, `"qa"`) ||
		!strings.Contains(errOut, "default") || !strings.Contains(errOut, "staging") {
		t.Fatalf("error should name the known profiles: %q", errOut)
	}
}

func TestUnknownEnvProfileIsAUsageError(t *testing.T) {
	f := &fake{}
	srv := httptest.NewServer(f.handler())
	defer srv.Close()
	h := newHarness(t, srv, "", false)
	saveProfiles(t, h.cfg, config.Store{Current: "default", Profiles: map[string]config.Profile{
		"default": {Server: srv.URL},
	}})
	h.env.Getenv = func(k string) string {
		if k == "AIDETECTOR_PROFILE" {
			return "qa"
		}
		return ""
	}
	if got := h.run("status"); got != ExitUsage {
		t.Fatalf("exit = %d, want %d\n%s", got, ExitUsage, h.out.String())
	}
	if errOut := h.errOut.String(); !strings.Contains(errOut, `"qa"`) ||
		!strings.Contains(errOut, "default") {
		t.Fatalf("error should name the known profiles: %q", errOut)
	}
}

func TestLogoutRemovesOnlyTheCurrentProfile(t *testing.T) {
	f := &fake{}
	srv := httptest.NewServer(f.handler())
	defer srv.Close()
	h := newHarness(t, srv, "", false)
	saveProfiles(t, h.cfg, config.Store{Current: "staging", Profiles: map[string]config.Profile{
		"default": {Server: srv.URL},
		"staging": {Server: srv.URL},
	}})

	if got := h.run("logout"); got != ExitOK {
		t.Fatalf("exit = %d\n%s", got, h.errOut.String())
	}
	if !strings.Contains(h.out.String(), "staging") {
		t.Fatalf("logout should say which profile it removed: %q", h.out.String())
	}
	st, err := config.ReadStore(h.cfg)
	if err != nil {
		t.Fatal(err)
	}
	if st.Current != "" {
		t.Fatalf("current = %q after removing the current profile", st.Current)
	}
	if _, ok := st.Profiles["default"]; !ok {
		t.Fatalf("logout removed another profile: %+v", st)
	}
	if _, ok := st.Profiles["staging"]; ok {
		t.Fatalf("logout left the current profile: %+v", st)
	}
}

func TestProfileRmAsksFirstAndRefusesInAPipe(t *testing.T) {
	f := &fake{}
	srv := httptest.NewServer(f.handler())
	defer srv.Close()

	// No terminal and no --yes: refuse and keep the profile.
	h := newHarness(t, srv, "", false)
	saveProfiles(t, h.cfg, config.Store{Current: "default", Profiles: map[string]config.Profile{
		"default": {Server: srv.URL},
		"staging": {Server: srv.URL},
	}})
	if got := h.run("profile", "rm", "staging"); got != ExitUsage {
		t.Fatalf("exit = %d, want %d", got, ExitUsage)
	}
	if st, _ := config.ReadStore(h.cfg); len(st.Profiles) != 2 {
		t.Fatalf("a refused rm changed the file: %+v", st)
	}

	// On a terminal, a no leaves it alone too.
	h = newHarness(t, srv, "n\n", true)
	saveProfiles(t, h.cfg, config.Store{Current: "default", Profiles: map[string]config.Profile{
		"default": {Server: srv.URL},
		"staging": {Server: srv.URL},
	}})
	if got := h.run("profile", "rm", "staging"); got != ExitUsage {
		t.Fatalf("declined rm exit = %d, want %d", got, ExitUsage)
	}
	if st, _ := config.ReadStore(h.cfg); len(st.Profiles) != 2 {
		t.Fatalf("a declined rm changed the file: %+v", st)
	}

	// --yes removes a non-current profile and leaves the current one alone.
	h = newHarness(t, srv, "", false)
	saveProfiles(t, h.cfg, config.Store{Current: "default", Profiles: map[string]config.Profile{
		"default": {Server: srv.URL},
		"staging": {Server: srv.URL},
	}})
	if got := h.run("profile", "rm", "staging", "--yes"); got != ExitOK {
		t.Fatalf("exit = %d\n%s", got, h.errOut.String())
	}
	st, _ := config.ReadStore(h.cfg)
	if st.Current != "default" {
		t.Fatalf("current = %q, want default", st.Current)
	}
	if _, ok := st.Profiles["staging"]; ok {
		t.Fatalf("staging was not removed: %+v", st)
	}

	// Removing the current one makes no profile current, and says so.
	h.out.Reset()
	if got := h.run("profile", "rm", "default", "--yes"); got != ExitOK {
		t.Fatalf("exit = %d\n%s", got, h.errOut.String())
	}
	if !strings.Contains(h.out.String(), "no profile is current") {
		t.Fatalf("output should say no profile is current: %q", h.out.String())
	}
	if _, err := os.Stat(h.cfg); !os.IsNotExist(err) {
		t.Fatal("the last profile gone should delete the file")
	}
}

func TestStatusMarksEnvironmentOverrides(t *testing.T) {
	f := &fake{}
	srv := httptest.NewServer(f.handler())
	defer srv.Close()

	// AIDETECTOR_SERVER beats the saved profile's server.
	h := newHarness(t, srv, "", false)
	saveProfiles(t, h.cfg, config.Store{Current: "default", Profiles: map[string]config.Profile{
		"default": {Server: "https://profile.example", APIKey: "profile-key"},
	}})
	if got := h.run("status"); got != ExitOK {
		t.Fatalf("exit = %d\n%s", got, h.errOut.String())
	}
	if out := h.out.String(); !strings.Contains(out, "server: "+srv.URL+" (from AIDETECTOR_SERVER)") {
		t.Fatalf("status should mark the env server override:\n%s", out)
	}

	// AIDETECTOR_PROFILE selects the profile for this command.
	h = newHarness(t, srv, "", false)
	saveProfiles(t, h.cfg, config.Store{Current: "default", Profiles: map[string]config.Profile{
		"default": {Server: srv.URL},
		"staging": {Server: srv.URL},
	}})
	h.env.Getenv = func(k string) string {
		if k == "AIDETECTOR_PROFILE" {
			return "staging"
		}
		return ""
	}
	h.out.Reset()
	if got := h.run("status"); got != ExitOK {
		t.Fatalf("exit = %d\n%s", got, h.errOut.String())
	}
	if out := h.out.String(); !strings.Contains(out, "profile: staging (from AIDETECTOR_PROFILE)") {
		t.Fatalf("status should mark the env profile:\n%s", out)
	}
}

func TestAIDETECTOR_CONFIGOverridesThePathButTheHarnessWins(t *testing.T) {
	f := &fake{}
	srv := httptest.NewServer(f.handler())
	defer srv.Close()
	other := filepath.Join(t.TempDir(), "other.json")
	saveProfiles(t, other, config.Store{Current: "staging", Profiles: map[string]config.Profile{
		"staging": {Server: srv.URL},
	}})

	h := newHarness(t, srv, "", false)
	h.env.ConfigPath = "" // let AIDETECTOR_CONFIG choose the file
	h.env.Getenv = func(k string) string {
		if k == "AIDETECTOR_CONFIG" {
			return other
		}
		return ""
	}
	if got := h.run("status"); got != ExitOK {
		t.Fatalf("exit = %d\n%s", got, h.errOut.String())
	}
	if out := h.out.String(); !strings.Contains(out, "profile: staging\n") {
		t.Fatalf("status should read AIDETECTOR_CONFIG:\n%s", out)
	}

	// Env.ConfigPath (the test harness) still wins over the environment.
	h = newHarness(t, srv, "", false)
	saveProfiles(t, h.cfg, config.Store{Current: "default", Profiles: map[string]config.Profile{
		"default": {Server: srv.URL},
	}})
	h.env.Getenv = func(k string) string {
		if k == "AIDETECTOR_CONFIG" {
			return other
		}
		return ""
	}
	h.out.Reset()
	if got := h.run("status"); got != ExitOK {
		t.Fatalf("exit = %d\n%s", got, h.errOut.String())
	}
	if out := h.out.String(); !strings.Contains(out, "profile: default\n") {
		t.Fatalf("Env.ConfigPath must win over AIDETECTOR_CONFIG:\n%s", out)
	}
}

func TestCredAddLocalOnlySendsNoSecret(t *testing.T) {
	f := &fake{}
	srv := httptest.NewServer(f.handler())
	defer srv.Close()
	h := newHarness(t, srv, "", false)
	if got := h.run("cred", "add", fakeScanID, "--name", "alice", "--role", "user", "--local-only"); got != ExitOK {
		t.Fatalf("exit = %d\n%s", got, h.errOut.String())
	}
	var body map[string]any
	_ = json.Unmarshal(f.bodies["POST "+fakeScanPath+"/credentials"], &body)
	if body["local_only"] != true {
		t.Fatalf("local_only should be sent: %v", body)
	}
	if _, sent := body["secret"]; sent {
		t.Fatalf("no secret may be sent: %v", body)
	}
	if got := h.run("cred", "add", fakeScanID, "--name", "x", "--role", "user", "--local-only", "--secret-stdin"); got != ExitUsage {
		t.Fatalf("--local-only with --secret-stdin: exit = %d", got)
	}
}

// auth_type none has nothing to send, but a stored identity needs a value.
func TestCredAddNoneSendsAPlaceholder(t *testing.T) {
	f := &fake{}
	srv := httptest.NewServer(f.handler())
	defer srv.Close()
	h := newHarness(t, srv, "", false)
	if got := h.run("cred", "add", fakeScanID, "--name", "anon", "--role", "guest", "--auth-type", "none"); got != ExitOK {
		t.Fatalf("exit = %d\n%s", got, h.errOut.String())
	}
	var body map[string]any
	_ = json.Unmarshal(f.bodies["POST "+fakeScanPath+"/credentials"], &body)
	if body["secret"] != "-" {
		t.Fatalf("secret = %v, want the placeholder", body["secret"])
	}
}

func TestRunSendsLevelAIAndWrites(t *testing.T) {
	f := &fake{}
	srv := httptest.NewServer(f.handler())
	defer srv.Close()
	h := newHarness(t, srv, "", false)

	code := h.run("run", fakeScanID, "--authorized", "--level", "deep", "--ai", "--writes")
	if code != ExitOK {
		t.Fatalf("exit = %d\n%s", code, h.errOut.String())
	}
	var body map[string]any
	if err := json.Unmarshal(f.bodies["POST "+fakeScanPath+"/local-runs"], &body); err != nil {
		t.Fatal(err)
	}
	if body["level"] != "deep" || body["ai"] != true || body["mutate"] != true {
		t.Fatalf("body = %v; want level deep, ai and writes (mutate)", body)
	}
	if _, set := body["fuzz"]; set {
		t.Fatalf("--level must be expanded by the server, not the CLI: %v", body)
	}
}

func TestRunRejectsAnUnknownLevel(t *testing.T) {
	f := &fake{}
	srv := httptest.NewServer(f.handler())
	defer srv.Close()
	h := newHarness(t, srv, "", false)

	if code := h.run("run", fakeScanID, "--authorized", "--level", "turbo"); code != ExitUsage {
		t.Fatalf("exit = %d, want %d", code, ExitUsage)
	}
	if !strings.Contains(h.errOut.String(), "--level must be one of quick, standard, deep") {
		t.Fatalf("stderr = %q", h.errOut.String())
	}
	if len(f.requests) != 0 {
		t.Fatalf("an invalid level must send nothing: %v", f.requests)
	}
}

func TestWithNoServerConfiguredTheClientUsesTheHostedService(t *testing.T) {
	e := &Env{
		Getenv:     func(string) string { return "" },
		ConfigPath: filepath.Join(t.TempDir(), "none.json"),
	}
	c, err := e.client()
	if err != nil {
		t.Fatal(err)
	}
	if c.Base() != config.DefaultServer || config.DefaultServer != "https://runpentests.com" {
		t.Fatalf("base = %q, want %q", c.Base(), "https://runpentests.com")
	}
}
