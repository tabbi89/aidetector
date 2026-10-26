package commands

import (
	"encoding/json"
	"strings"
	"testing"
)

const retestFP = "9e41aa00bb11cc22"

func retestFake(original map[string]any, diffBucket string) *fake {
	row := map[string]any{"fingerprint": retestFP, "check": "bola", "severity": "high",
		"confidence": "verified", "title": "BOLA on /accounts/{id}", "verdict": "unreviewed"}
	diff := map[string]any{"from_run": 1, "to_run": 2, "added": []any{}, "resolved": []any{},
		"not_retested": []any{}, "unchanged": []any{}}
	diff[diffBucket] = []any{row}
	op := "op-accounts"
	return &fake{
		findings: []map[string]any{{"id": "f1", "fingerprint": retestFP, "check": "bola", "severity": "high",
			"confidence": "verified", "title": "BOLA on /accounts/{id}", "verdict": "unreviewed", "operation_id": op}},
		runs: []map[string]any{original},
		diff: &diff,
		coverage: []map[string]any{{"operation_id": op, "method": "GET", "path": "/accounts/{id}", "enabled": true,
			"requests": 4, "responses": 4, "ok": 4, "exercised": true, "checks": []any{"bola"}, "findings": 0}},
	}
}

func readOnlyRun() map[string]any {
	return map[string]any{"run_number": 1, "status": "completed",
		"options":  map[string]any{"mutate": false, "fuzz": true, "zap": true, "plan": true},
		"manifest": map[string]any{"seed": 77}}
}

func TestRetestScopesToTheCheckWithTheOriginalSeed(t *testing.T) {
	f := retestFake(readOnlyRun(), "unchanged")
	h, calls := localHarness(t, f, "completed", nil, nil)
	if got := h.run("retest", fakeScanID, "9e41", "--authorized"); got != ExitFindings {
		t.Fatalf("still present exits 1, got %d\n%s", got, h.errOut.String())
	}
	var body map[string]any
	if err := json.Unmarshal(f.bodies["POST "+fakeScanPath+"/local-runs"], &body); err != nil {
		t.Fatal(err)
	}
	if checks, _ := body["checks"].([]any); len(checks) != 1 || checks[0] != "bola" {
		t.Fatalf("scope = %v", body["checks"])
	}
	if body["seed"] != float64(77) || body["fuzz"] != true {
		t.Fatalf("the seed and the shaping passes carry over: %v", body)
	}
	// Tools and AI are not repeated without asking; nor are writes.
	for _, k := range []string{"zap", "plan", "mutate"} {
		if _, ok := body[k]; ok {
			t.Fatalf("%s must not be repeated implicitly: %v", k, body)
		}
	}
	if len(*calls) != 1 || !strings.Contains(h.errOut.String(), "not by endpoint") {
		t.Fatalf("the scope must be stated honestly:\n%s", h.errOut.String())
	}
}

func TestRetestCallsAFixOnlyWhenTheEndpointWasExercised(t *testing.T) {
	f := retestFake(readOnlyRun(), "resolved")
	h, _ := localHarness(t, f, "completed", nil, nil)
	if got := h.run("retest", fakeScanID, "9e41", "--authorized"); got != ExitOK {
		t.Fatalf("exit = %d\n%s", got, h.errOut.String())
	}
	if !strings.Contains(h.out.String(), "likely fixed") {
		t.Fatalf("out = %s", h.out.String())
	}

	// The endpoint never answered: the check never really ran there.
	f = retestFake(readOnlyRun(), "resolved")
	f.coverage[0]["responses"], f.coverage[0]["ok"], f.coverage[0]["exercised"] = 0, 0, false
	h, _ = localHarness(t, f, "completed", nil, nil)
	if got := h.run("retest", fakeScanID, "9e41", "--authorized", "--json"); got != ExitIncomplete {
		t.Fatalf("exit = %d\n%s", got, h.out.String())
	}
	if !strings.Contains(h.out.String(), `"outcome": "not_retested"`) || !strings.Contains(h.out.String(), "no response") {
		t.Fatalf("out = %s", h.out.String())
	}

	f = retestFake(readOnlyRun(), "not_retested")
	h, _ = localHarness(t, f, "completed", nil, nil)
	if got := h.run("retest", fakeScanID, "9e41", "--authorized"); got != ExitIncomplete {
		t.Fatalf("exit = %d", got)
	}
}

func TestRetestNeedsWritesWhenTheOriginalHadThem(t *testing.T) {
	run := readOnlyRun()
	run["options"] = map[string]any{"mutate": true}
	f := retestFake(run, "unchanged")
	h, calls := localHarness(t, f, "completed", nil, nil)
	if got := h.run("retest", fakeScanID, "9e41", "--authorized"); got != ExitUsage {
		t.Fatalf("exit = %d", got)
	}
	if len(*calls) != 0 || f.sawRequest("POST "+fakeScanPath+"/local-runs") {
		t.Fatal("nothing may run before the writes question is answered")
	}
	h, _ = localHarness(t, f, "completed", nil, nil)
	h.run("retest", fakeScanID, "9e41", "--authorized", "--writes")
	var body map[string]any
	_ = json.Unmarshal(f.bodies["POST "+fakeScanPath+"/local-runs"], &body)
	if body["mutate"] != true {
		t.Fatalf("--writes must reach the run: %v", body)
	}
}

func TestRetestAsksForConsent(t *testing.T) {
	f := retestFake(readOnlyRun(), "unchanged")
	h, calls := localHarness(t, f, "completed", nil, nil)
	if got := h.run("retest", fakeScanID, "9e41"); got != ExitUsage || len(*calls) != 0 {
		t.Fatalf("exit = %d, calls = %d", got, len(*calls))
	}
}

func TestRetestUsesTheProjectFilesIDsAndSecrets(t *testing.T) {
	f := retestFake(readOnlyRun(), "unchanged")
	h, calls := localHarness(t, f, "completed", nil, map[string]string{"ALICE_TOKEN": "alice-from-env"})
	h.env.Dir = t.TempDir()
	writeFile(t, h.env.Dir, "runpentests.yml",
		"resource_ids: { account: acct_77 }\nidentities:\n  - { name: alice, role: user, secret_env: ALICE_TOKEN }\n")
	h.run("retest", fakeScanID, "9e41", "--authorized")
	if len(*calls) != 1 {
		t.Fatalf("calls = %d\n%s", len(*calls), h.errOut.String())
	}
	stdin := (*calls)[0].stdin
	if !strings.Contains(stdin, `"predefined_resource_ids":{"account":"acct_77"}`) ||
		!strings.Contains(stdin, "alice-from-env") {
		t.Fatalf("the retest should run as the project's scan did: %s", stdin)
	}
}
