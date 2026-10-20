package commands

import (
	"net/http/httptest"
	"strings"
	"testing"
)

// capsWithPass builds a /capabilities answer with one pass entry and a free
// premium plan, which is all the warning paths need.
func capsWithPass(field string, available bool, reason string) map[string]any {
	pass := map[string]any{"available": available}
	if reason != "" {
		pass["reason"] = reason
	} else {
		pass["reason"] = nil
	}
	return map[string]any{
		"passes": map[string]any{field: pass},
		"premium": map[string]any{
			"available": false, "plan": "free", "reason": "this tenant is on the free plan",
		},
	}
}

func TestStatusListsEveryPassWithItsReason(t *testing.T) {
	f := &fake{capabilities: map[string]any{
		"passes": map[string]any{
			"zap":             map[string]any{"available": false, "reason": "OWASP ZAP is not configured on this server"},
			"confirm":         map[string]any{"available": true, "reason": "tplmap not installed"},
			"security_review": map[string]any{"available": true, "reason": nil},
		},
		"premium": map[string]any{
			"available": false, "plan": "free", "reason": "this tenant is on the free plan",
		},
	}}
	srv := httptest.NewServer(f.handler())
	defer srv.Close()
	h := newHarness(t, srv, "", false)

	if code := h.run("status"); code != ExitOK {
		t.Fatalf("exit = %d, want %d\n%s", code, ExitOK, h.errOut.String())
	}
	out := h.out.String()
	for _, want := range []string{
		"passes:",
		"--zap",
		"unavailable — OWASP ZAP is not configured on this server",
		"--confirm",
		"available (note: tplmap not installed)",
		"--security-review",
		"--premium",
		"unavailable — this tenant is on the free plan",
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("status output is missing %q:\n%s", want, out)
		}
	}
	h.assertNoSecretPrinted(t)
}

func TestStatusWithoutCapabilitiesSaysUnknown(t *testing.T) {
	f := &fake{} // no /capabilities answer: the fake 404s
	srv := httptest.NewServer(f.handler())
	defer srv.Close()
	h := newHarness(t, srv, "", false)

	if code := h.run("status"); code != ExitOK {
		t.Fatalf("an old server must not change status's exit code: %d\n%s", code, h.errOut.String())
	}
	if !strings.Contains(h.out.String(), "passes: unknown (server has no /capabilities)") {
		t.Fatalf("status = %q", h.out.String())
	}
}
