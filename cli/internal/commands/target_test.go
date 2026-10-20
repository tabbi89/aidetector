package commands

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

const testSpec = `{"openapi":"3.0.0","info":{"title":"t","version":"1"},"paths":{"/items":{"get":{"responses":{"200":{"description":"ok"}}}}}}`

// stateful is a fake server that remembers scans, identities and specs, so
// the target form's find-or-create and upsert logic can be checked end to end.
type stateful struct {
	mu       sync.Mutex
	scans    []map[string]any // newest first, like the real list
	requests []string
	bodies   map[string][]map[string]any // "METHOD /path" -> every JSON body sent
	finished string                      // status a run ends in
	findings []map[string]any
	nextID   int
	// capabilities, when set, is the answer to GET /capabilities; nil is an
	// old server that 404s the route.
	capabilities map[string]any
	// hints, when set, is the answer to POST /specs/auth-hints; nil 404s.
	hints map[string]any
	// events is the answer to GET /scans/{id}/events.
	events []map[string]any
}

func (s *stateful) scan(id string) map[string]any {
	for _, sc := range s.scans {
		if sc["id"] == id {
			return sc
		}
	}
	return nil
}

func (s *stateful) handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s.mu.Lock()
		defer s.mu.Unlock()
		key := r.Method + " " + r.URL.Path
		s.requests = append(s.requests, key)
		var body map[string]any
		raw, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(raw, &body)
		if s.bodies == nil {
			s.bodies = map[string][]map[string]any{}
		}
		s.bodies[key] = append(s.bodies[key], body)
		w.Header().Set("Content-Type", "application/json")
		parts := strings.Split(strings.Trim(r.URL.Path, "/"), "/")
		writeJSON := func(code int, v any) {
			w.WriteHeader(code)
			_ = json.NewEncoder(w).Encode(v)
		}
		switch {
		case r.URL.Path == "/specs/auth-hints" && r.Method == "POST":
			if s.hints == nil {
				writeJSON(404, map[string]string{"detail": "not found"})
				return
			}
			writeJSON(200, s.hints)
		case r.URL.Path == "/capabilities" && r.Method == "GET":
			if s.capabilities == nil {
				writeJSON(404, map[string]string{"detail": "not found"})
				return
			}
			writeJSON(200, s.capabilities)
		case r.URL.Path == "/scans" && r.Method == "GET":
			var out []map[string]any
			for _, sc := range s.scans {
				out = append(out, map[string]any{
					"id": sc["id"], "target_base_url": sc["target_base_url"], "status": sc["status"],
					"last_run_at": sc["last_run_at"], "finding_counts": map[string]int{},
				})
			}
			writeJSON(200, out)
		case r.URL.Path == "/scans" && r.Method == "POST":
			s.nextID++
			sc := map[string]any{
				"id": fmt.Sprintf("new%d", s.nextID), "target_base_url": body["target_base_url"],
				"status": "draft", "operations": []any{}, "credential_profiles": []any{},
				"spec_text": nil, "managed_config": map[string]any{},
			}
			s.scans = append([]map[string]any{sc}, s.scans...)
			writeJSON(201, sc)
		case len(parts) >= 2 && parts[0] == "scans":
			sc := s.scan(parts[1])
			if sc == nil {
				writeJSON(404, map[string]string{"detail": "scan not found"})
				return
			}
			sub := strings.Join(parts[2:], "/")
			switch {
			case sub == "" && r.Method == "GET":
				writeJSON(200, sc)
			case sub == "" && r.Method == "PATCH":
				sc["target_base_url"] = body["target_base_url"]
				writeJSON(200, sc)
			case sub == "" && r.Method == "DELETE":
				for i, other := range s.scans {
					if other["id"] == sc["id"] {
						s.scans = append(s.scans[:i], s.scans[i+1:]...)
						break
					}
				}
				writeJSON(200, map[string]string{"status": "deleted"})
			case sub == "spec":
				sc["spec_text"] = body["content"]
				sc["operations"] = []any{map[string]any{"id": "op1", "method": "GET", "path": "/items", "enabled": true}}
				writeJSON(200, sc)
			case sub == "credentials" && r.Method == "POST":
				profiles := sc["credential_profiles"].([]any)
				for _, p := range profiles {
					if p.(map[string]any)["name"] == body["name"] {
						writeJSON(409, map[string]string{"detail": "a credential with that name already exists"})
						return
					}
				}
				profiles = append(profiles, map[string]any{
					"id": "c-" + body["name"].(string), "name": body["name"], "role": body["role"],
					"auth_type": body["auth_type"], "header_name": body["header_name"],
				})
				sc["credential_profiles"] = profiles
				writeJSON(201, map[string]any{})
			case strings.HasPrefix(sub, "credentials/") && r.Method == "PATCH":
				writeJSON(200, map[string]any{})
			case sub == "managed-config":
				sc["managed_config"] = body
				writeJSON(200, sc)
			case sub == "local-runs":
				// The runner the default Docker stub stands for finishes at once.
				sc["status"] = s.finished
				var creds []any
				for _, p := range sc["credential_profiles"].([]any) {
					creds = append(creds, p)
				}
				writeJSON(201, map[string]any{
					"run_id": "r1aaaaaa-bbbb", "token": "run-token-xyz", "options": map[string]any{},
					"max_requests": 750, "target_base_url": sc["target_base_url"], "credentials": creds,
				})
			case sub == "events":
				if s.events == nil {
					writeJSON(200, []any{})
					return
				}
				writeJSON(200, s.events)
			case sub == "findings":
				writeJSON(200, s.findings)
			case sub == "diff":
				writeJSON(409, map[string]string{"detail": "a diff needs two runs"})
			default:
				writeJSON(404, map[string]string{"detail": "not found"})
			}
		default:
			writeJSON(404, map[string]string{"detail": "not found"})
		}
	})
}

func (s *stateful) saw(key string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, r := range s.requests {
		if r == key {
			return true
		}
	}
	return false
}

func (s *stateful) last(key string) map[string]any {
	s.mu.Lock()
	defer s.mu.Unlock()
	b := s.bodies[key]
	if len(b) == 0 {
		return nil
	}
	return b[len(b)-1]
}

// targetHarness serves a fake API (with a spec at /openapi.json when spec is
// set) as the target, plus the stateful server. env adds environment values.
func targetHarness(t *testing.T, s *stateful, stdin string, tty bool, env map[string]string) (*harness, string, *int) {
	t.Helper()
	srv := httptest.NewServer(s.handler())
	t.Cleanup(srv.Close)
	hits := new(int)
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		*hits++
		if r.URL.Path == "/openapi.json" {
			_, _ = w.Write([]byte(testSpec))
			return
		}
		w.WriteHeader(404)
	}))
	t.Cleanup(target.Close)
	h := newHarness(t, srv, stdin, tty)
	base := h.env.Getenv
	h.env.Getenv = func(k string) string {
		if v, ok := env[k]; ok {
			return v
		}
		return base(k)
	}
	h.env.Dir = t.TempDir()
	h.env.GitHead = func(string) string { return "0123abcd" }
	if s.finished == "" {
		s.finished = "completed"
	}
	return h, target.URL, hits
}

func writeFile(t *testing.T, dir, name, body string) string {
	t.Helper()
	p := filepath.Join(dir, name)
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestTargetFormRefusesWithoutConsentBeforeAnyRequest(t *testing.T) {
	s := &stateful{}
	h, target, hits := targetHarness(t, s, "", false, nil)
	if code := h.run(target); code != ExitUsage {
		t.Fatalf("exit = %d, want %d", code, ExitUsage)
	}
	if len(s.requests) != 0 || *hits != 0 {
		t.Fatalf("nothing may be sent before consent: server %v, target hits %d", s.requests, *hits)
	}
	if !strings.Contains(h.errOut.String(), "--authorized") {
		t.Errorf("the refusal should say how to consent: %s", h.errOut.String())
	}
}

func TestTargetFormCreatesAScanAndFetchesTheSpecFromTheTarget(t *testing.T) {
	s := &stateful{findings: []map[string]any{
		{"check": "bola", "severity": "high", "confidence": "verified", "title": "BOLA", "verdict": "unreviewed"},
	}}
	h, target, _ := targetHarness(t, s, "", false, nil)
	code := h.run(target, "--authorized")
	if code != ExitOK {
		t.Fatalf("exit = %d\n%s", code, h.errOut.String())
	}
	if !s.saw("POST /scans") || !s.saw("POST /scans/new1/spec") || !s.saw("POST /scans/new1/local-runs") {
		t.Fatalf("want create, spec and run; got %v", s.requests)
	}
	if got := s.last("POST /scans/new1/spec")["content"]; got != testSpec {
		t.Errorf("the spec the target published should be uploaded, got %v", got)
	}
	if !strings.Contains(h.out.String(), "BOLA") || !strings.Contains(h.out.String(), "1 finding(s), 1 verified") {
		t.Errorf("findings should be shown:\n%s", h.out.String())
	}
	// No identities and no terminal: warn, don't block.
	if !strings.Contains(h.errOut.String(), "no identities") {
		t.Errorf("a scan with no identities should be called out:\n%s", h.errOut.String())
	}
}

func TestARunThatNeverReachedTheAPISaysSoAfterTheFindings(t *testing.T) {
	ev := func(stage, msg string) map[string]any {
		return map[string]any{"stage": stage, "pct": 0, "message": msg, "created_at": "t"}
	}
	s := &stateful{
		findings: []map[string]any{
			{"check": "security_headers", "severity": "medium", "confidence": "verified",
				"title": "Missing CSP", "verdict": "unreviewed"},
		},
		events: []map[string]any{
			ev("resource_setup_note", "resource setup failed after 1 attempt(s): POST /api/v1/monitors (HTTP 404)"),
			ev("resource_setup_note", "resource setup skipped: no create endpoint for 'incident'"),
			ev("check_skipped", "oob_injection did not run: no out-of-band collector configured"),
			ev("check_skipped", "bfla did not run: no privileged operation"),
			ev("check_skipped", "discovery bfla did not run: no privileged operation"),
			ev("cleanup_failed", "DELETE /monitors/{id}: HTTP 403"),
			ev("security_headers", "completed security_headers"),
			ev("target_unreached", "118 of 121 requests to the spec's endpoints answered 404, so this run "+
				"never reached the API: GET /api/v1/monitors was sent to http://caddy/api/v1/api/v1/monitors"),
		},
	}
	h, target, _ := targetHarness(t, s, "", false, nil)
	if code := h.run(target, "--authorized"); code != ExitOK {
		t.Fatalf("exit = %d\n%s", code, h.errOut.String())
	}
	errOut := h.errOut.String()
	summary := errOut[strings.Index(errOut, "what limited this run"):]
	// Worst first: the 404 diagnosis leads the setup failure that follows from it.
	health := strings.Index(summary, "✗ 118 of 121")
	setup := strings.Index(summary, "! resource setup failed")
	if health < 0 || setup < 0 || health > setup {
		t.Fatalf("want the 404 diagnosis first, then the setup failure:\n%s", summary)
	}
	if strings.Contains(summary, "no create endpoint") || strings.Contains(summary, "completed") {
		t.Errorf("only what the user can act on belongs in the summary:\n%s", summary)
	}
	if !strings.Contains(summary, "! DELETE /monitors/{id}: HTTP 403") {
		t.Errorf("a failed cleanup means data may be left on the target:\n%s", summary)
	}
	if !strings.Contains(summary, "2 check(s) had nothing to test in this API: bfla, oob_injection") {
		t.Errorf("skipped checks collapse into one line:\n%s", summary)
	}
	if !strings.Contains(summary, "the findings above are not a result") {
		t.Errorf("a run that never reached the API must not read as a result:\n%s", summary)
	}
	// stdout stays the findings table, so a pipe sees no summary lines.
	if strings.Contains(h.out.String(), "limited") {
		t.Errorf("the summary belongs on stderr:\n%s", h.out.String())
	}
}

func TestARunThatReachedTheAPIIsNotCalledUnreached(t *testing.T) {
	s := &stateful{events: []map[string]any{{"stage": "target_health", "pct": 0,
		"message": "identity 'b' was rejected: all 5 requests it sent answered 401", "created_at": "t"}}}
	h, target, _ := targetHarness(t, s, "", false, nil)
	if code := h.run(target, "--authorized"); code != ExitOK {
		t.Fatalf("exit = %d\n%s", code, h.errOut.String())
	}
	got := h.errOut.String()
	if !strings.Contains(got, "✗ identity 'b' was rejected") {
		t.Fatalf("a rejected identity is a ✗ line:\n%s", got)
	}
	if strings.Contains(got, "not a result") {
		t.Errorf("only target_unreached voids the findings:\n%s", got)
	}
}

func TestACleanRunPrintsNoLimitsSummary(t *testing.T) {
	s := &stateful{}
	h, target, _ := targetHarness(t, s, "", false, nil)
	if code := h.run(target, "--authorized"); code != ExitOK {
		t.Fatalf("exit = %d\n%s", code, h.errOut.String())
	}
	if strings.Contains(h.errOut.String(), "what limited this run") {
		t.Errorf("nothing limited this run:\n%s", h.errOut.String())
	}
}

func TestTargetFormReusesTheScanForTheSameTarget(t *testing.T) {
	s := &stateful{}
	h, target, _ := targetHarness(t, s, "", false, nil)
	spec := testSpec
	s.scans = []map[string]any{
		{"id": "old", "target_base_url": target + "/", "status": "completed", "last_run_at": "2026-01-01",
			"spec_text": spec, "operations": []any{}, "managed_config": map[string]any{},
			"credential_profiles": []any{map[string]any{"id": "c1", "name": "alice", "role": "user", "auth_type": "bearer"}}},
		{"id": "older", "target_base_url": target, "status": "completed", "last_run_at": "2025-01-01",
			"credential_profiles": []any{}},
		{"id": "other", "target_base_url": "https://elsewhere.example.com", "credential_profiles": []any{}},
	}
	if code := h.run(target, "--authorized"); code != ExitOK {
		t.Fatalf("exit = %d\n%s", code, h.errOut.String())
	}
	if s.saw("POST /scans") {
		t.Fatal("a scan for this target exists; it must be reused, not duplicated")
	}
	if !s.saw("POST /scans/old/local-runs") {
		t.Fatalf("the latest-run scan should run, got %v", s.requests)
	}
	// The saved spec is unchanged, so it is not re-uploaded (that would reset
	// the operation selection someone made in the web).
	if s.saw("POST /scans/old/spec") {
		t.Error("an unchanged spec must not be re-uploaded")
	}
	if !strings.Contains(h.errOut.String(), "2 scans match") {
		t.Errorf("an ambiguous match should say how to pin one:\n%s", h.errOut.String())
	}
}

func TestTargetFormNewForcesAFreshScan(t *testing.T) {
	s := &stateful{}
	h, target, _ := targetHarness(t, s, "", false, nil)
	s.scans = []map[string]any{{"id": "old", "target_base_url": target, "credential_profiles": []any{}}}
	if code := h.run(target, "--authorized", "--new"); code != ExitOK {
		t.Fatalf("exit = %d\n%s", code, h.errOut.String())
	}
	if !s.saw("POST /scans") || s.saw("POST /scans/old/local-runs") {
		t.Fatalf("--new should create a scan, got %v", s.requests)
	}
}

func TestTargetFormDropsTheNewScanWhenNoSpecCanBeFound(t *testing.T) {
	s := &stateful{}
	h, target, _ := targetHarness(t, s, "", false, nil)
	if code := h.run(target+"/nothing-here", "--authorized"); code != ExitUsage {
		t.Fatalf("exit = %d, want usage\n%s", code, h.errOut.String())
	}
	if len(s.scans) != 0 || !s.saw("DELETE /scans/new1") {
		t.Fatalf("an empty scan must not be left behind: %v", s.requests)
	}
	if !strings.Contains(h.errOut.String(), "--spec") {
		t.Errorf("the error should say how to supply a spec:\n%s", h.errOut.String())
	}
}

const projectFile = `
target: %s
spec: api/openapi.json
rps: 7
fail_on: low
identities:
  - { name: alice, role: user, secret_env: ALICE_TOKEN }
  - { name: admin, role: admin, auth: header, header: X-Api-Key, secret_env: ADMIN_TOKEN }
`

func TestProjectFileDrivesTheRunAndRecordsWhatItOwns(t *testing.T) {
	s := &stateful{findings: []map[string]any{
		{"check": "headers", "severity": "low", "confidence": "verified", "title": "Missing HSTS", "verdict": "unreviewed"},
	}}
	h, target, _ := targetHarness(t, s, "", false, map[string]string{
		"ALICE_TOKEN": "alice-secret-value", "ADMIN_TOKEN": "admin-secret-value",
	})
	writeFile(t, h.env.Dir, "aidetector.yml", fmt.Sprintf(projectFile, target))
	writeFile(t, h.env.Dir, "api/openapi.json", testSpec)
	s.scans = []map[string]any{{
		"id": "s9", "target_base_url": target, "status": "completed", "spec_text": nil,
		"operations": []any{}, "managed_config": map[string]any{},
		"credential_profiles": []any{map[string]any{"id": "c1", "name": "alice", "role": "user", "auth_type": "bearer"}},
	}}

	// A bare `aidetector` in the project: the file says what to do. --fail-on
	// on the command line beats the file's fail_on.
	code := h.run("--authorized", "--fail-on", "high")
	if code != ExitOK {
		t.Fatalf("exit = %d (a low finding must not fail --fail-on high)\n%s", code, h.errOut.String())
	}

	run := s.last("POST /scans/s9/local-runs")
	if run["requests_per_second"] != float64(7) {
		t.Errorf("rps from the file should reach the run: %v", run)
	}
	src, _ := run["config_source"].(map[string]any)
	if src["path"] != "aidetector.yml" || len(fmt.Sprint(src["digest"])) != 64 || src["commit"] != "0123abcd" {
		t.Errorf("the run should record where its settings came from: %v", src)
	}

	mc := s.last("PUT /scans/s9/managed-config")
	if fmt.Sprint(mc["fields"]) != "[target spec identities requests_per_second]" ||
		fmt.Sprint(mc["identities"]) != "[alice admin]" {
		t.Errorf("managed config = %v", mc)
	}

	// alice existed with the file's shape: nothing to update, and her secret
	// never leaves this machine.
	if s.saw("PATCH /scans/s9/credentials/c1") {
		t.Errorf("alice's unchanged identity should not be sent: %v", s.last("PATCH /scans/s9/credentials/c1"))
	}
	// admin did not: created from the file.
	add := s.last("POST /scans/s9/credentials")
	if add["name"] != "admin" || add["auth_type"] != "header" || add["header_name"] != "X-Api-Key" {
		t.Errorf("admin should be created from the file: %v", add)
	}
	if !s.saw("POST /scans/s9/spec") {
		t.Error("the file's spec differs from the scan's, so it should be uploaded")
	}

	for _, out := range []string{h.out.String(), h.errOut.String()} {
		for _, secret := range []string{"alice-secret-value", "admin-secret-value", secretKey} {
			if strings.Contains(out, secret) {
				t.Fatalf("a secret was printed: %s", secret)
			}
		}
	}
}

func TestProjectFileMutatePassNamesItsNewName(t *testing.T) {
	s := &stateful{}
	h, target, _ := targetHarness(t, s, "", false, nil)
	writeFile(t, h.env.Dir, "aidetector.yml", fmt.Sprintf(
		"target: %s\nspec: api/openapi.json\npasses: [mutate]\n", target))
	writeFile(t, h.env.Dir, "api/openapi.json", testSpec)

	if code := h.run("--authorized"); code != ExitUsage {
		t.Fatalf("exit = %d, want %d\n%s", code, ExitUsage, h.errOut.String())
	}
	if !strings.Contains(h.errOut.String(), `the "mutate" pass is now called "writes"`) {
		t.Fatalf("the error should name the new pass:\n%s", h.errOut.String())
	}
	if run := s.last("POST /scans/new1/local-runs"); run != nil {
		t.Fatalf("a refused pass must not claim a run: %v", run)
	}
}

func TestProjectFileLevelAndWritesReachTheRunAndAFlagWins(t *testing.T) {
	s := &stateful{}
	h, target, _ := targetHarness(t, s, "", false, nil)
	writeFile(t, h.env.Dir, "aidetector.yml", fmt.Sprintf(
		"target: %s\nspec: api/openapi.json\nlevel: standard\npasses: [writes, ai]\n", target))
	writeFile(t, h.env.Dir, "api/openapi.json", testSpec)

	if code := h.run("--authorized"); code != ExitOK {
		t.Fatalf("exit = %d\n%s", code, h.errOut.String())
	}
	run := s.last("POST /scans/new1/local-runs")
	if run["level"] != "standard" || run["mutate"] != true || run["ai"] != true {
		t.Fatalf("the file's level and passes should reach the run: %v", run)
	}

	// A flag beats the file, setting by setting.
	if code := h.run("--authorized", "--level", "deep"); code != ExitOK {
		t.Fatalf("flag run: exit = %d\n%s", code, h.errOut.String())
	}
	if got := s.last("POST /scans/new1/local-runs")["level"]; got != "deep" {
		t.Fatalf("level = %v, want the flag's deep", got)
	}
}

func TestProjectFileFailOnAppliesWhenNoFlagOverridesIt(t *testing.T) {
	s := &stateful{findings: []map[string]any{
		{"check": "headers", "severity": "low", "confidence": "verified", "title": "Missing HSTS", "verdict": "unreviewed"},
	}}
	h, target, _ := targetHarness(t, s, "", false, map[string]string{"ALICE_TOKEN": "a", "ADMIN_TOKEN": "b"})
	writeFile(t, h.env.Dir, "aidetector.yml", fmt.Sprintf(projectFile, target))
	writeFile(t, h.env.Dir, "api/openapi.json", testSpec)
	if code := h.run("--authorized"); code != ExitFindings {
		t.Fatalf("exit = %d, want %d: fail_on: low in the file", code, ExitFindings)
	}
}

func TestProjectFileWithASecretIsRefusedBeforeAnyRequest(t *testing.T) {
	s := &stateful{}
	h, target, hits := targetHarness(t, s, "", false, nil)
	writeFile(t, h.env.Dir, "aidetector.yml",
		"target: "+target+"\nidentities:\n  - { name: a, role: user, token: hunter2 }\n")
	if code := h.run("--authorized"); code != ExitUsage {
		t.Fatalf("exit = %d, want usage", code)
	}
	if len(s.requests) != 0 || *hits != 0 {
		t.Fatal("a refused file must not lead to any request")
	}
	if !strings.Contains(h.errOut.String(), "secret_env") {
		t.Errorf("the error should point at secret_env:\n%s", h.errOut.String())
	}
}

func TestAPinnedScanFollowsTheFilesTarget(t *testing.T) {
	s := &stateful{}
	h, target, _ := targetHarness(t, s, "", false, nil)
	s.scans = []map[string]any{{"id": "pin", "target_base_url": "https://old.example.com",
		"spec_text": testSpec, "credential_profiles": []any{}, "managed_config": map[string]any{}}}
	writeFile(t, h.env.Dir, "aidetector.yml", "target: "+target+"\nscan: pin\n")
	if code := h.run("--authorized"); code != ExitOK {
		t.Fatalf("exit = %d\n%s", code, h.errOut.String())
	}
	if got := s.last("PATCH /scans/pin"); got["target_base_url"] != target {
		t.Errorf("the file owns the target, so the pinned scan should follow it: %v", got)
	}
}

func TestBareCommandOutsideAProjectStillPrintsHelp(t *testing.T) {
	s := &stateful{}
	h, _, _ := targetHarness(t, s, "", false, nil)
	if code := h.run(); code != ExitUsage || !strings.Contains(h.out.String(), "usage:") {
		t.Fatalf("exit = %d, out = %s", code, h.out.String())
	}
}

func TestSubcommandsAreNotMistakenForTargets(t *testing.T) {
	s := &stateful{}
	h, _, _ := targetHarness(t, s, "", false, nil)
	h.run("scans", "list")
	if !s.saw("GET /scans") || s.saw("POST /scans") {
		t.Fatalf("`scans list` must stay a subcommand: %v", s.requests)
	}
}

func TestADirectoryRunsLocallyWithTheCodeAndKeepsSecretsOffTheServer(t *testing.T) {
	s := &stateful{}
	h, target, _ := targetHarness(t, s, "", false, map[string]string{"ALICE_TOKEN": "alice-secret-value"})
	proj := t.TempDir()
	writeFile(t, proj, "aidetector.yml",
		"target: "+target+"\nidentities:\n  - { name: alice, role: user, secret_env: ALICE_TOKEN }\n")
	writeFile(t, proj, "docs/openapi.json", testSpec)
	s.scans = []map[string]any{{"id": "loc", "target_base_url": target, "spec_text": nil,
		"managed_config":      map[string]any{},
		"credential_profiles": []any{map[string]any{"id": "c1", "name": "alice", "role": "user", "auth_type": "bearer"}}}}

	var calls []dockerCall
	h.env.Docker = func(_ context.Context, name string, args []string, stdin io.Reader, _, _ io.Writer) error {
		var in bytes.Buffer
		_, _ = in.ReadFrom(stdin)
		calls = append(calls, dockerCall{name, args, in.String()})
		s.mu.Lock()
		s.scan("loc")["status"] = "completed"
		s.mu.Unlock()
		return nil
	}
	if code := h.run(target, proj, "--authorized", "--docker-network", "app_internal,app_egress"); code != ExitOK {
		t.Fatalf("exit = %d\n%s", code, h.errOut.String())
	}
	if len(calls) != 1 {
		t.Fatalf("want one runner container, got %d (%v)", len(calls), s.requests)
	}
	argv := strings.Join(calls[0].args, " ")
	if !strings.Contains(argv, proj+":/src:ro") {
		t.Errorf("the project should be mounted read-only: %s", argv)
	}
	// The target's own network and one with egress to the server, both joined.
	if !strings.Contains(argv, "--network app_internal --network app_egress ") {
		t.Errorf("the runner should join both networks: %s", argv)
	}
	if !strings.Contains(h.errOut.String(), "docs/openapi.json") {
		t.Errorf("the spec found in the project should be named:\n%s", h.errOut.String())
	}
	cfg := parseConfig(t, calls[0].stdin)
	if cfg.Secrets["alice"]["secret"] != "alice-secret-value" {
		t.Errorf("alice's secret should reach the runner on stdin: %v", cfg.Secrets)
	}
	// alice already exists with the same shape: a local run sends no secret.
	if s.saw("PATCH /scans/loc/credentials/c1") || s.saw("POST /scans/loc/credentials") {
		t.Errorf("a local run must not send an unchanged identity's secret to the server: %v", s.requests)
	}
	if !s.saw("POST /scans/loc/local-runs") {
		t.Errorf("a directory means a local run: %v", s.requests)
	}
}

// A local run reads every secret on this machine, so an identity it has to
// create goes to the server as a shape: the secret must not cross even once.
func TestALocalRunCreatesIdentitiesLocalOnly(t *testing.T) {
	s := &stateful{}
	h, target, _ := targetHarness(t, s, "", false, map[string]string{"ALICE_TOKEN": "alice-secret-value"})
	proj := t.TempDir()
	writeFile(t, proj, "aidetector.yml",
		"target: "+target+"\nidentities:\n  - { name: alice, role: user, secret_env: ALICE_TOKEN }\n")
	writeFile(t, proj, "docs/openapi.json", testSpec)
	s.scans = []map[string]any{{"id": "loc", "target_base_url": target, "spec_text": nil,
		"managed_config": map[string]any{}, "credential_profiles": []any{}}}
	h.env.Docker = func(_ context.Context, _ string, _ []string, stdin io.Reader, _, _ io.Writer) error {
		_, _ = io.Copy(io.Discard, stdin)
		s.mu.Lock()
		s.scan("loc")["status"] = "completed"
		s.mu.Unlock()
		return nil
	}
	h.run(target, proj, "--authorized")
	add := s.last("POST /scans/loc/credentials")
	if add == nil || add["local_only"] != true || add["name"] != "alice" {
		t.Fatalf("alice should be created local-only: %v", add)
	}
	if _, sent := add["secret"]; sent {
		t.Fatalf("a local-only identity must carry no secret: %v", add)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	for key, bodies := range s.bodies {
		for _, b := range bodies {
			if strings.Contains(fmt.Sprint(b), "alice-secret-value") {
				t.Fatalf("the secret reached the server in %s: %v", key, b)
			}
		}
	}
}

func TestATenantFromTheFileIsSentAndAChangeUpdatesTheIdentity(t *testing.T) {
	s := &stateful{}
	h, target, _ := targetHarness(t, s, "", false, map[string]string{"A": "a", "B": "b"})
	proj := t.TempDir()
	writeFile(t, proj, "aidetector.yml", "target: "+target+"\nidentities:\n"+
		"  - { name: a-write, role: editor, tenant: a, secret_env: A }\n"+
		"  - { name: b-write, role: editor, tenant: b, secret_env: B }\n")
	writeFile(t, proj, "docs/openapi.json", testSpec)
	s.scans = []map[string]any{{"id": "loc", "target_base_url": target, "spec_text": nil,
		"managed_config": map[string]any{}, "credential_profiles": []any{
			// b-write exists with no tenant: the file now owns one.
			map[string]any{"id": "c-b", "name": "b-write", "role": "editor", "auth_type": "bearer",
				"tenant": nil, "local_only": true},
		}}}
	h.env.Docker = func(_ context.Context, _ string, _ []string, stdin io.Reader, _, _ io.Writer) error {
		_, _ = io.Copy(io.Discard, stdin)
		s.mu.Lock()
		s.scan("loc")["status"] = "completed"
		s.mu.Unlock()
		return nil
	}
	h.run(target, proj, "--authorized")
	if add := s.last("POST /scans/loc/credentials"); add == nil || add["tenant"] != "a" {
		t.Fatalf("a-write should be created with its tenant: %v", add)
	}
	if upd := s.last("PATCH /scans/loc/credentials/c-b"); upd == nil || upd["tenant"] != "b" {
		t.Fatalf("a tenant the server lacks should update the identity: %v", upd)
	}
}

// Identities typed at the prompt for a local run stay on this machine too.
func TestPromptedIdentitiesForALocalRunStayLocal(t *testing.T) {
	s := &stateful{}
	h, target, _ := targetHarness(t, s, "alice\nuser\n\n\n", true, nil)
	proj := t.TempDir()
	writeFile(t, proj, "aidetector.yml", "target: "+target+"\n")
	writeFile(t, proj, "docs/openapi.json", testSpec)
	s.scans = []map[string]any{{"id": "loc", "target_base_url": target, "spec_text": nil,
		"managed_config": map[string]any{}, "credential_profiles": []any{}}}
	h.env.Docker = func(_ context.Context, _ string, _ []string, stdin io.Reader, _, _ io.Writer) error {
		_, _ = io.Copy(io.Discard, stdin)
		s.mu.Lock()
		s.scan("loc")["status"] = "completed"
		s.mu.Unlock()
		return nil
	}
	h.run(target, proj, "--authorized")
	add := s.last("POST /scans/loc/credentials")
	if add == nil || add["local_only"] != true {
		t.Fatalf("the prompted identity should be created local-only: %v\n%s", add, h.errOut.String())
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	for key, bodies := range s.bodies {
		for _, b := range bodies {
			if strings.Contains(fmt.Sprint(b), "typed-secret") {
				t.Fatalf("the typed secret reached the server in %s: %v", key, b)
			}
		}
	}
}

func TestScanPageURLPointsAtTheWebUI(t *testing.T) {
	env := map[string]string{}
	e := &Env{Getenv: func(k string) string { return env[k] }}
	cases := map[string]string{
		"https://runpentests.com":  "https://runpentests.com/scans/abc",
		"https://runpentests.com/": "https://runpentests.com/scans/abc",
		"http://127.0.0.1:8000":    "http://127.0.0.1:3000/scans/abc",
		"http://localhost:8000":    "http://localhost:3000/scans/abc",
	}
	for server, want := range cases {
		if got := scanPageURL(e, server, "abc"); got != want {
			t.Errorf("scanPageURL(%q) = %q, want %q", server, got, want)
		}
	}
	env["AIDETECTOR_WEB_URL"] = "https://app.example.com/"
	if got := scanPageURL(e, "https://api.example.com", "abc"); got != "https://app.example.com/scans/abc" {
		t.Errorf("override ignored: %q", got)
	}
}
