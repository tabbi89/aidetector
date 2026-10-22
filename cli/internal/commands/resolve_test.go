package commands

import (
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestAFullScanIDNeedsNoListCall(t *testing.T) {
	f := &fake{}
	srv := httptest.NewServer(f.handler())
	defer srv.Close()
	h := newHarness(t, srv, "", false)
	if code := h.run("scans", "show", fakeScanID); code != ExitOK {
		t.Fatalf("exit = %d\n%s", code, h.errOut.String())
	}
	if f.sawRequest("GET /scans") {
		t.Fatal("a full scan ID must not cost a list call")
	}
	if !f.sawRequest("GET " + fakeScanPath) {
		t.Fatal("the scan itself should have been fetched")
	}
}

func TestAUniquePrefixResolves(t *testing.T) {
	f := &fake{}
	srv := httptest.NewServer(f.handler())
	defer srv.Close()
	h := newHarness(t, srv, "", false)
	if code := h.run("scans", "show", "1111"); code != ExitOK {
		t.Fatalf("exit = %d\n%s", code, h.errOut.String())
	}
	if !f.sawRequest("GET /scans") {
		t.Fatal("a prefix is resolved against the scan list")
	}
	if !strings.Contains(h.out.String(), fakeScanID) {
		t.Fatalf("stdout should name the resolved scan: %q", h.out.String())
	}
}

func TestAnAmbiguousPrefixExitsUsageAndListsMatches(t *testing.T) {
	f := &fake{scanList: []map[string]any{
		{"id": "aaaa1111-1111-1111-1111-111111111111", "target_base_url": "http://a", "status": "completed"},
		{"id": "aaaa2222-2222-2222-2222-222222222222", "target_base_url": "http://b", "status": "completed"},
	}}
	srv := httptest.NewServer(f.handler())
	defer srv.Close()
	h := newHarness(t, srv, "", false)
	if code := h.run("findings", "aaaa"); code != ExitUsage {
		t.Fatalf("exit = %d, want %d", code, ExitUsage)
	}
	for _, want := range []string{"matches 2 scans", "http://a", "http://b", "use more characters"} {
		if !strings.Contains(h.errOut.String(), want) {
			t.Fatalf("stderr should contain %q: %q", want, h.errOut.String())
		}
	}
	if f.sawRequest("GET " + fakeScanPath + "/findings") {
		t.Fatal("an ambiguous prefix must not pick a scan")
	}
}

func TestABadScanRefIsUsageWithoutAServerCall(t *testing.T) {
	f := &fake{}
	srv := httptest.NewServer(f.handler())
	defer srv.Close()
	h := newHarness(t, srv, "", false)
	if code := h.run("findings", "zzzz"); code != ExitUsage {
		t.Fatalf("exit = %d, want %d", code, ExitUsage)
	}
	if n := f.count(); n != 0 {
		t.Fatalf("a bad reference sent %d request(s)", n)
	}
	if !strings.Contains(h.errOut.String(), "not a scan ID or ID prefix") {
		t.Fatalf("stderr = %q", h.errOut.String())
	}
}

func TestFindingsDefaultsToTheProjectTarget(t *testing.T) {
	f := &fake{}
	srv := httptest.NewServer(f.handler())
	defer srv.Close()
	h := newHarness(t, srv, "", false)
	h.env.Dir = t.TempDir()
	writeFile(t, h.env.Dir, "runpentests.yml", "target: http://t\n")
	if code := h.run("findings"); code != ExitOK {
		t.Fatalf("exit = %d\n%s", code, h.errOut.String())
	}
	if !f.sawRequest("GET " + fakeScanPath + "/findings") {
		t.Fatal("the scan for the project's target should have been read")
	}
	if !strings.Contains(h.errOut.String(), "scan 11111111 (from runpentests.yml)") {
		t.Fatalf("stderr should say which scan was picked: %q", h.errOut.String())
	}
}

func TestScansRmNeedsAScanID(t *testing.T) {
	f := &fake{}
	srv := httptest.NewServer(f.handler())
	defer srv.Close()
	h := newHarness(t, srv, "", false)
	if code := h.run("scans", "rm"); code != ExitUsage {
		t.Fatalf("exit = %d, want %d", code, ExitUsage)
	}
	if n := f.count(); n != 0 {
		t.Fatalf("nothing should be sent without an ID, got %d request(s)", n)
	}
}

func TestScansListShowsEverySeverityAndFiltersByTarget(t *testing.T) {
	f := &fake{scanList: []map[string]any{
		{"id": fakeScanID, "target_base_url": "http://t", "status": "completed",
			"finding_counts": map[string]int{"critical": 1, "high": 3, "medium": 2, "low": 4},
			"last_run_at":    "2024-03-04T05:06:07Z"},
		{"id": "22222222-2222-2222-2222-222222222222", "target_base_url": "http://other", "status": "draft"},
	}}
	srv := httptest.NewServer(f.handler())
	defer srv.Close()

	h := newHarness(t, srv, "", false)
	if code := h.run("scans", "list"); code != ExitOK {
		t.Fatalf("exit = %d\n%s", code, h.errOut.String())
	}
	out := h.out.String()
	if !strings.Contains(out, "HIGH") || !strings.Contains(out, "   1    3    2    4") {
		t.Fatalf("the table should show every severity count: %q", out)
	}
	if !strings.Contains(out, "11111111") || strings.Contains(out, fakeScanID) {
		t.Fatalf("the default ID is its first 8 characters: %q", out)
	}

	h = newHarness(t, srv, "", false)
	if code := h.run("scans", "list", "--target", "http://t"); code != ExitOK {
		t.Fatalf("exit = %d\n%s", code, h.errOut.String())
	}
	if strings.Contains(h.out.String(), "http://other") {
		t.Fatalf("--target should filter the list: %q", h.out.String())
	}

	h = newHarness(t, srv, "", false)
	if code := h.run("scans", "list", "--full-ids"); code != ExitOK {
		t.Fatalf("exit = %d\n%s", code, h.errOut.String())
	}
	if !strings.Contains(h.out.String(), fakeScanID) {
		t.Fatalf("--full-ids should print the whole UUID: %q", h.out.String())
	}
}

func TestCredListAndRemove(t *testing.T) {
	credID := "abcdef12-1111-1111-1111-111111111111"
	f := &fake{credentials: []map[string]any{
		{"id": credID, "name": "alice", "role": "user", "auth_type": "bearer", "header_name": nil},
	}}
	srv := httptest.NewServer(f.handler())
	defer srv.Close()

	h := newHarness(t, srv, "", false)
	if code := h.run("cred", "list", fakeScanID); code != ExitOK {
		t.Fatalf("exit = %d\n%s", code, h.errOut.String())
	}
	for _, want := range []string{"alice", "user", "bearer", "abcdef12"} {
		if !strings.Contains(h.out.String(), want) {
			t.Fatalf("cred list should contain %q: %q", want, h.out.String())
		}
	}

	// No --yes and no terminal: refuse before sending the DELETE.
	h = newHarness(t, srv, "", false)
	if code := h.run("cred", "rm", fakeScanID, "alice"); code != ExitUsage {
		t.Fatalf("exit = %d, want %d", code, ExitUsage)
	}
	if f.sawRequest("DELETE " + fakeScanPath + "/credentials/" + credID) {
		t.Fatal("an identity must not be removed without confirmation")
	}

	h = newHarness(t, srv, "", false)
	if code := h.run("cred", "rm", fakeScanID, "alice", "--yes"); code != ExitOK {
		t.Fatalf("exit = %d\n%s", code, h.errOut.String())
	}
	if !f.sawRequest("DELETE " + fakeScanPath + "/credentials/" + credID) {
		t.Fatal("cred rm --yes should delete the identity")
	}
}

func TestReportDefaultsToAUniqueFilename(t *testing.T) {
	f := &fake{}
	srv := httptest.NewServer(f.handler())
	defer srv.Close()
	h := newHarness(t, srv, "", false)
	h.env.Dir = t.TempDir()

	if code := h.run("report", fakeScanID, "--format", "json"); code != ExitOK {
		t.Fatalf("exit = %d\n%s", code, h.errOut.String())
	}
	path := filepath.Join(h.env.Dir, "runpentests-11111111.json")
	data, err := os.ReadFile(path)
	if err != nil || !strings.Contains(string(data), "findings") {
		t.Fatalf("default report = %q, %v", data, err)
	}

	// A second report must not silently replace the first.
	if code := h.run("report", fakeScanID, "--format", "json"); code != ExitUsage {
		t.Fatalf("a second default report: exit = %d, want %d", code, ExitUsage)
	}
	if !strings.Contains(h.errOut.String(), "exists; pass -o FILE to overwrite") {
		t.Fatalf("stderr = %q", h.errOut.String())
	}
}
