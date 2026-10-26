package commands

import (
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func listedDomain(host string) map[string]any {
	return map[string]any{
		"id": "dddddddd-0000-0000-0000-00000000000a", "host": host, "token": "tok",
		"dns_record_name": "_runpentests-challenge." + host, "dns_record_value": "runpentests-verify=tok",
		"http_path": "/.well-known/runpentests-verify/tok", "http_url": "https://" + host + "/.well-known/runpentests-verify/tok",
		"verified_at": nil, "last_checked_at": nil, "last_error": nil, "last_checks": []any{},
		"created_at": "2026-10-26T10:00:00Z",
	}
}

var (
	dnsOK       = map[string]any{"proof": "dns", "ok": true, "detail": nil}
	httpFailed  = map[string]any{"proof": "http", "ok": false, "detail": "https://api.example.com did not return the verification token"}
	httpOK      = map[string]any{"proof": "http", "ok": true, "detail": nil}
	pendingFail = map[string]any{"verified_at": nil, "last_checked_at": "2026-10-26T10:01:00Z",
		"last_error": "https://api.example.com did not return the verification token", "last_checks": []any{dnsOK, httpFailed}}
	verifiedNow = map[string]any{"verified_at": "2026-10-26T10:02:00Z", "last_checked_at": "2026-10-26T10:02:00Z",
		"last_error": nil, "last_checks": []any{dnsOK, httpOK}}
)

func TestDomainsAddPrintsExactlyWhatToPublish(t *testing.T) {
	f := &fake{}
	srv := httptest.NewServer(f.handler())
	defer srv.Close()
	h := newHarness(t, srv, "", false)
	if got := h.run("domains", "add", "https://API.example.com"); got != ExitOK {
		t.Fatalf("exit = %d\n%s", got, h.errOut.String())
	}
	out := h.out.String()
	for _, want := range []string{
		"_runpentests-challenge.api.example.com", "runpentests-verify=tok123",
		"/.well-known/runpentests-verify/tok123", "runpentests domains verify api.example.com",
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("missing %q:\n%s", want, out)
		}
	}
	// Adding is not verifying, and nothing scans.
	if f.verifyCalls != 0 || f.sawRequest("POST "+fakeScanPath+"/local-runs") {
		t.Fatalf("add must not verify or scan: %v", f.requests)
	}

	h = newHarness(t, srv, "", false)
	h.run("domains", "add", "203.0.113.9")
	if !strings.Contains(h.out.String(), "IP address, which has no name to prove") {
		t.Fatalf("an IP literal has no DNS proof:\n%s", h.out.String())
	}
}

func TestDomainsVerifyReportsEachProofAndTheNextStep(t *testing.T) {
	f := &fake{domains: []map[string]any{listedDomain("api.example.com")},
		verifyAnswers: []map[string]any{pendingFail}}
	srv := httptest.NewServer(f.handler())
	defer srv.Close()
	h := newHarness(t, srv, "", false)
	if got := h.run("domains", "verify", "api.example.com"); got != ExitUsage {
		t.Fatalf("a failed proof is not verified: exit = %d", got)
	}
	out := h.out.String()
	if !strings.Contains(out, "✓ DNS") || !strings.Contains(out, "✗ HTTP") ||
		!strings.Contains(out, "did not return the verification token") {
		t.Fatalf("each proof's outcome should show:\n%s", out)
	}

	f.verifyAnswers, f.verifyCalls = []map[string]any{verifiedNow}, 0
	h = newHarness(t, srv, "", false)
	if got := h.run("domains", "verify", "api.example.com", "--json"); got != ExitOK {
		t.Fatalf("verified: exit = %d\n%s", got, h.errOut.String())
	}
	if !strings.Contains(h.out.String(), `"state": "verified"`) {
		t.Fatalf("json: %s", h.out.String())
	}
}

func TestDomainsVerifyWaitsBoundedForPropagation(t *testing.T) {
	saved := domainVerifyPoll
	domainVerifyPoll = time.Millisecond
	defer func() { domainVerifyPoll = saved }()

	f := &fake{domains: []map[string]any{listedDomain("api.example.com")},
		verifyAnswers: []map[string]any{pendingFail, pendingFail, verifiedNow}}
	srv := httptest.NewServer(f.handler())
	defer srv.Close()
	h := newHarness(t, srv, "", false)
	if got := h.run("domains", "verify", "api.example.com", "--wait", "1m"); got != ExitOK {
		t.Fatalf("exit = %d\n%s", got, h.errOut.String())
	}
	if f.verifyCalls != 3 {
		t.Fatalf("verify calls = %d, want 3", f.verifyCalls)
	}

	// A wait that runs out exits 4, not 0.
	f.verifyAnswers, f.verifyCalls = []map[string]any{pendingFail}, 0
	h = newHarness(t, srv, "", false)
	start := time.Now()
	h.env.Now = func() time.Time { return start.Add(time.Duration(f.verifyCalls) * time.Minute) }
	if got := h.run("domains", "verify", "api.example.com", "--wait", "2m"); got != ExitTimeout {
		t.Fatalf("exit = %d, want %d", got, ExitTimeout)
	}
}

func TestDomainsFindAnIDNAHostInTheServersSpelling(t *testing.T) {
	d := listedDomain("xn--bcher-kva.example")
	d["unicode"] = "bücher.example" // the fake's stand-in for server-side IDNA
	f := &fake{domains: []map[string]any{listedDomain("api.example.com"), d},
		verifyAnswers: []map[string]any{verifiedNow}}
	srv := httptest.NewServer(f.handler())
	defer srv.Close()
	h := newHarness(t, srv, "", false)
	if got := h.run("domains", "verify", "BÜCHER.example."); got != ExitOK {
		t.Fatalf("exit = %d\n%s", got, h.errOut.String())
	}
	if !f.sawRequest("POST /workspace/domains/" + d["id"].(string) + "/verify") {
		t.Fatalf("verified the wrong record: %v", f.requests)
	}
}

func TestDomainsListNeverVerifies(t *testing.T) {
	f := &fake{domains: []map[string]any{listedDomain("api.example.com")}}
	srv := httptest.NewServer(f.handler())
	defer srv.Close()
	h := newHarness(t, srv, "", false)
	if got := h.run("domains", "list"); got != ExitOK {
		t.Fatalf("exit = %d", got)
	}
	if !strings.Contains(h.out.String(), "pending") || f.verifyCalls != 0 {
		t.Fatalf("list shows the recorded state and runs no check:\n%s", h.out.String())
	}
}

func TestDomainsNeedAnAdminAndSayItSo(t *testing.T) {
	f := &fake{status: map[string]int{"POST /workspace/domains": 403}}
	srv := httptest.NewServer(f.handler())
	defer srv.Close()
	h := newHarness(t, srv, "", false)
	if got := h.run("domains", "add", "api.example.com"); got != ExitUsage {
		t.Fatalf("exit = %d", got)
	}
	if !strings.Contains(h.errOut.String(), "needs a workspace admin") {
		t.Fatalf("stderr = %s", h.errOut.String())
	}
}

func TestDomainsCheckExplainsTheGateWithoutContactingTheTarget(t *testing.T) {
	cases := []struct {
		name      string
		ownership map[string]any
		want      string
		code      int
	}{
		{"private is exempt by address", map[string]any{"host": "api.internal", "allowed": true, "required": false,
			"exempt": "private"}, "resolves only to private addresses", ExitOK},
		{"public with no record", map[string]any{"host": "api.example.com", "allowed": true, "required": true},
			"next: runpentests domains add api.example.com", ExitUsage},
		{"listed, unverified", map[string]any{"host": "api.example.com", "allowed": true, "required": true,
			"domain_id": "d1", "last_error": "no TXT record"}, "next: runpentests domains verify api.example.com", ExitUsage},
		{"verified", map[string]any{"host": "api.example.com", "allowed": true, "required": true,
			"domain_id": "d1", "verified_at": "2026-10-26T10:00:00Z"}, "re-proves it live", ExitOK},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			f := &fake{ownership: c.ownership}
			srv := httptest.NewServer(f.handler())
			defer srv.Close()
			h := newHarness(t, srv, "", false)
			if got := h.run("domains", "check", fakeScanID); got != c.code {
				t.Fatalf("exit = %d, want %d\n%s", got, c.code, h.out.String())
			}
			if !strings.Contains(h.out.String(), c.want) {
				t.Fatalf("want %q:\n%s", c.want, h.out.String())
			}
		})
	}
	// An older server without the route says so.
	srv := httptest.NewServer((&fake{}).handler())
	defer srv.Close()
	h := newHarness(t, srv, "", false)
	if got := h.run("domains", "check", fakeScanID); got != ExitUsage || !strings.Contains(h.errOut.String(), "older than this CLI") {
		t.Fatalf("exit = %d\n%s", got, h.errOut.String())
	}
}

func TestARefusedRunPointsAtTheDomainSteps(t *testing.T) {
	f := &fake{claimStatus: 422, claimDetail: "target not verified: 'api.example.com' resolves to a public address",
		ownership: map[string]any{"host": "api.example.com", "allowed": true, "required": true}}
	srv := httptest.NewServer(f.handler())
	defer srv.Close()
	h := newHarness(t, srv, "", false)
	if got := h.run("run", fakeScanID, "--authorized"); got != ExitUsage {
		t.Fatalf("exit = %d", got)
	}
	if !strings.Contains(h.errOut.String(), "runpentests domains add api.example.com") {
		t.Fatalf("the refusal should name the next step:\n%s", h.errOut.String())
	}
}
