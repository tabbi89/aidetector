package commands

import (
	"encoding/json"
	"os"
	"sort"
	"testing"
)

// Every boolean the server's RunRequest accepts must be a CLI pass flag, or be
// listed in RunRequestNotFlags with a reason. A flag added to the engine fails
// this test until the CLI can send it — the same guarantee the web client has.
func TestRunFlagsCoverEveryRunRequestBoolean(t *testing.T) {
	data, err := os.ReadFile("../../testdata/openapi.json")
	if err != nil {
		t.Fatalf("contract snapshot missing: %v", err)
	}
	var doc struct {
		Components struct {
			Schemas map[string]struct {
				Properties map[string]struct {
					Type string `json:"type"`
				} `json:"properties"`
			} `json:"schemas"`
		} `json:"components"`
	}
	if err := json.Unmarshal(data, &doc); err != nil {
		t.Fatal(err)
	}
	props := doc.Components.Schemas["RunRequest"].Properties
	if len(props) == 0 {
		t.Fatal("RunRequest not found in the snapshot")
	}

	sent := map[string]bool{}
	for _, field := range RunFlags {
		sent[field] = true
	}
	var missing []string
	for name, p := range props {
		if p.Type != "boolean" {
			continue
		}
		if sent[name] {
			continue
		}
		if _, decided := RunRequestNotFlags[name]; decided {
			continue
		}
		missing = append(missing, name)
	}
	sort.Strings(missing)
	if len(missing) > 0 {
		t.Errorf("RunRequest booleans the CLI cannot send: %v — add to RunFlags, or to "+
			"RunRequestNotFlags with a reason", missing)
	}

	// And the other direction: a flag naming a field the server no longer has.
	for flagName, field := range RunFlags {
		if p, ok := props[field]; !ok || p.Type != "boolean" {
			t.Errorf("--%s sets %q, which is not a RunRequest boolean on the server", flagName, field)
		}
	}
	// Every "decided" exclusion must still exist, so the list cannot rot.
	for name := range RunRequestNotFlags {
		if _, ok := props[name]; !ok {
			t.Errorf("RunRequestNotFlags names %q, which RunRequest no longer has", name)
		}
	}
}
