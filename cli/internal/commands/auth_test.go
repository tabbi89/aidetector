package commands

import (
	"context"
	"encoding/json"
	"io"
	"strings"
	"testing"
)

const aliceSecret = "alice-secret-NEVER-SHOWN"

// authHarness answers the container with a canned runner report.
func authHarness(t *testing.T, report string) (*harness, *fake, *[]dockerCall) {
	t.Helper()
	f := &fake{}
	h, calls := localHarness(t, f, "", nil, map[string]string{"RUNPENTESTS_SECRET_ALICE": aliceSecret})
	h.env.Dir = t.TempDir() // no project file unless a test writes one
	h.env.Docker = func(_ context.Context, name string, args []string, stdin io.Reader, stdout, _ io.Writer) error {
		data, _ := io.ReadAll(stdin)
		*calls = append(*calls, dockerCall{name, args, string(data)})
		_, _ = stdout.Write([]byte(report))
		return nil
	}
	return h, f, calls
}

const mixedReport = `{"target":"http://host.docker.internal:9000","reachable":true,"requests":3,
"routes":[{"method":"GET","path":"/me"}],"anonymous":[401],
"identities":[
 {"name":"alice","role":"user","auth":"bearer","state":"accepted","detail":"a route that refuses anonymous callers answered 2xx","statuses":[200]},
 {"name":"bob","role":"user","auth":"bearer","state":"missing_secret","detail":"no secret was supplied on this machine","statuses":[]}
],"events":[]}`

func TestAuthCheckRunsInTheRunnerAndReportsEachIdentity(t *testing.T) {
	h, f, calls := authHarness(t, mixedReport)
	if got := h.run("auth", "check", fakeScanID, "--authorized"); got != ExitFindings {
		t.Fatalf("one identity not accepted exits 1, got %d\n%s", got, h.errOut.String())
	}
	if len(*calls) != 1 {
		t.Fatalf("calls = %d", len(*calls))
	}
	call := (*calls)[0]
	if call.args[len(call.args)-1] != "--auth-check" || !strings.Contains(strings.Join(call.args, " "), "--cap-drop ALL") {
		t.Fatalf("the check runs in the hardened runner: %v", call.args)
	}
	var cfg struct {
		Check   map[string]any               `json:"check"`
		Secrets map[string]map[string]string `json:"secrets"`
	}
	if err := json.Unmarshal([]byte(call.stdin), &cfg); err != nil {
		t.Fatal(err)
	}
	if cfg.Secrets["alice"]["secret"] != aliceSecret || cfg.Check["target_base_url"] != "http://host.docker.internal:9000" {
		t.Fatalf("stdin = %s", call.stdin)
	}
	if strings.Contains(strings.Join(call.args, " "), aliceSecret) {
		t.Fatal("a secret reached argv")
	}
	for key, body := range f.bodies {
		if strings.Contains(string(body), aliceSecret) {
			t.Fatalf("a secret reached the server in %s", key)
		}
	}
	out := h.out.String()
	if !strings.Contains(out, "accepted") || !strings.Contains(out, "fix bob: export") {
		t.Fatalf("out = %s", out)
	}
	if strings.Contains(out+h.errOut.String(), aliceSecret) {
		t.Fatal("a secret was printed")
	}
	// No run was opened: the check never touches the local-run routes.
	if f.sawRequest("POST " + fakeScanPath + "/local-runs") {
		t.Fatal("an auth check must not claim a run")
	}
}

func TestAuthCheckNeedsConsent(t *testing.T) {
	h, f, calls := authHarness(t, mixedReport)
	if got := h.run("auth", "check", fakeScanID); got != ExitUsage || len(*calls) != 0 ||
		f.sawRequest("POST "+fakeScanPath+"/auth-checks") {
		t.Fatalf("exit = %d; nothing may be sent without consent", got)
	}
}

func TestAuthCheckAllAcceptedIsCleanAndUnreachableIsFailed(t *testing.T) {
	ok := strings.Replace(mixedReport, `"state":"missing_secret"`, `"state":"accepted"`, 1)
	h, _, _ := authHarness(t, ok)
	if got := h.run("auth", "check", fakeScanID, "--authorized", "--json"); got != ExitOK {
		t.Fatalf("exit = %d", got)
	}
	var doc authReport
	if err := json.Unmarshal(h.out.Bytes(), &doc); err != nil || len(doc.Identities) != 2 {
		t.Fatalf("json: %v %s", err, h.out.String())
	}

	down := strings.Replace(mixedReport, `"reachable":true`, `"reachable":false`, 1)
	h, _, _ = authHarness(t, down)
	if got := h.run("auth", "check", fakeScanID, "--authorized"); got != ExitFailed {
		t.Fatalf("exit = %d", got)
	}
	if !strings.Contains(h.out.String(), "did not answer from the runner") {
		t.Fatalf("out = %s", h.out.String())
	}
}

func TestAuthCheckNamesFileIdentitiesTheScanLacks(t *testing.T) {
	ok := strings.Replace(mixedReport, `"state":"missing_secret"`, `"state":"accepted"`, 1)
	h, _, _ := authHarness(t, ok)
	h.env.Dir = t.TempDir()
	writeFile(t, h.env.Dir, "runpentests.yml", "identities:\n  - { name: alice, role: user, secret_env: A }\n"+
		"  - { name: bob, role: user, secret_env: B }\n  - { name: carol, role: admin, secret_env: C }\n")
	if got := h.run("auth", "check", fakeScanID, "--authorized"); got != ExitFindings {
		t.Fatalf("an unchecked identity is not a clean result: exit = %d\n%s", got, h.out.String())
	}
	if !strings.Contains(h.out.String(), "not_on_scan") || !strings.Contains(h.out.String(), "carol") {
		t.Fatalf("out = %s", h.out.String())
	}
}
