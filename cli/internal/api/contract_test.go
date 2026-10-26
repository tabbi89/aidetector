package api

import (
	"encoding/json"
	"os"
	"strings"
	"testing"
)

// The server's OpenAPI document, snapshotted into testdata. A Python test
// (tests/test_cli_contract_snapshot.py) fails when the snapshot drifts from the
// live app, so this file can never be silently stale.
func loadSpec(t *testing.T) map[string]map[string]json.RawMessage {
	t.Helper()
	data, err := os.ReadFile("../../testdata/openapi.json")
	if err != nil {
		t.Fatalf("contract snapshot missing: %v", err)
	}
	var doc struct {
		Paths map[string]map[string]json.RawMessage `json:"paths"`
	}
	if err := json.Unmarshal(data, &doc); err != nil {
		t.Fatal(err)
	}
	return doc.Paths
}

func TestEveryRouteTheClientCallsExistsOnTheServer(t *testing.T) {
	paths := loadSpec(t)
	for _, r := range UsedRoutes {
		methods, ok := paths[r.Path]
		if !ok {
			t.Errorf("route %s %s: path is not in the server's OpenAPI document", r.Method, r.Path)
			continue
		}
		if _, ok := methods[strings.ToLower(r.Method)]; !ok {
			t.Errorf("route %s %s: the path exists but not with that method", r.Method, r.Path)
		}
	}
}

func TestUsedRoutesListsEveryRouteConstant(t *testing.T) {
	// A route added above but forgotten in UsedRoutes would escape the check.
	want := 39
	if len(UsedRoutes) != want {
		t.Fatalf("UsedRoutes has %d entries, expected %d: add new Route* vars to UsedRoutes", len(UsedRoutes), want)
	}
	seen := map[Route]bool{}
	for _, r := range UsedRoutes {
		if seen[r] {
			t.Errorf("duplicate route %v", r)
		}
		seen[r] = true
	}
	for format, r := range ReportFormats {
		if !seen[r] {
			t.Errorf("report format %q uses a route missing from UsedRoutes", format)
		}
	}
}
