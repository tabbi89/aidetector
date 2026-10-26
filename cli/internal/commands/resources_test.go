package commands

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const fixtureID = "m_fixture_SECRETISH_42"

func writeIDs(t *testing.T, body string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "ids.json")
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestResourceIDsGoToTheRunnerOnStdinAndNowhereElse(t *testing.T) {
	f := &fake{bindings: map[string]any{
		"names": []any{map[string]any{"name": "merchant", "key": "merchant", "ambiguous_with": []any{},
			"routes": []any{map[string]any{"method": "GET", "path": "/merchants/{merchantId}", "param": "merchantId"}}}},
		"unbound": []any{},
	}}
	h, calls := localHarness(t, f, "completed", nil, nil)
	ids := writeIDs(t, `{"merchant": "`+fixtureID+`"}`)
	if got := h.run("run", fakeScanID, "--authorized", "--resource-ids", ids); got != ExitOK {
		t.Fatalf("exit = %d\n%s", got, h.errOut.String())
	}
	if len(*calls) != 1 || !strings.Contains((*calls)[0].stdin, `"predefined_resource_ids":{"merchant":"`+fixtureID+`"}`) {
		t.Fatalf("the runner's stdin should carry the map: %+v", *calls)
	}
	if strings.Contains(strings.Join((*calls)[0].args, " "), fixtureID) {
		t.Fatalf("an id reached the container's argv: %v", (*calls)[0].args)
	}
	for key, body := range f.bodies {
		if strings.Contains(string(body), fixtureID) {
			t.Fatalf("an id reached the server in %s: %s", key, body)
		}
	}
	if !strings.Contains(string(f.bodies["POST "+fakeScanPath+"/resource-bindings"]), `"merchant"`) {
		t.Fatalf("the names should be previewed: %v", f.requests)
	}
	if strings.Contains(h.errOut.String()+h.out.String(), fixtureID) {
		t.Fatalf("an id was printed:\n%s", h.errOut.String())
	}
	if !strings.Contains(h.errOut.String(), "merchant fills {merchantId} on GET /merchants/{merchantId}") {
		t.Fatalf("the binding preview should be shown:\n%s", h.errOut.String())
	}
	// The preview precedes the claim: the budget is not spent to learn it.
	if f.indexOf("POST "+fakeScanPath+"/resource-bindings") > f.indexOf("POST "+fakeScanPath+"/local-runs") {
		t.Fatalf("preview after claim: %v", f.requests)
	}
}

func TestAmbiguousResourceIDsAreRefusedBeforeTheClaim(t *testing.T) {
	f := &fake{bindings: map[string]any{
		"names": []any{
			map[string]any{"name": "merchant", "key": "merchant", "ambiguous_with": []any{"merchant_id"}, "routes": []any{}},
			map[string]any{"name": "merchant_id", "key": "merchant", "ambiguous_with": []any{"merchant"}, "routes": []any{}},
		},
		"unbound": []any{},
	}}
	h, calls := localHarness(t, f, "completed", nil, nil)
	ids := writeIDs(t, `{"merchant": "a", "merchant_id": "b"}`)
	if got := h.run("run", fakeScanID, "--authorized", "--resource-ids", ids); got != ExitUsage {
		t.Fatalf("exit = %d", got)
	}
	if len(*calls) != 0 || f.sawRequest("POST "+fakeScanPath+"/local-runs") {
		t.Fatalf("an ambiguous map must stop before the claim")
	}
}

func TestAnInvalidResourceIDFileIsAUsageErrorNamingNoID(t *testing.T) {
	h, _ := localHarness(t, &fake{}, "completed", nil, nil)
	ids := writeIDs(t, `{"merchant": "a/`+fixtureID+`"}`)
	if got := h.run("run", fakeScanID, "--authorized", "--resource-ids", ids); got != ExitUsage {
		t.Fatalf("exit = %d", got)
	}
	if strings.Contains(h.errOut.String(), fixtureID) || !strings.Contains(h.errOut.String(), `the id for "merchant"`) {
		t.Fatalf("stderr = %s", h.errOut.String())
	}
}

func TestAnOlderServerStillGetsTheIDsToTheRunner(t *testing.T) {
	h, calls := localHarness(t, &fake{}, "completed", nil, nil)
	ids := writeIDs(t, "merchant: m1\n")
	if got := h.run("run", fakeScanID, "--authorized", "--resource-ids", ids); got != ExitOK {
		t.Fatalf("exit = %d\n%s", got, h.errOut.String())
	}
	if !strings.Contains(h.errOut.String(), "cannot preview") || !strings.Contains((*calls)[0].stdin, `"merchant":"m1"`) {
		t.Fatalf("stderr = %s", h.errOut.String())
	}
}
