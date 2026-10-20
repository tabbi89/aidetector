package commands

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"aidetector/cli/internal/api"
	"aidetector/cli/internal/project"
)

// dockerCall is what the CLI asked Docker to do.
type dockerCall struct {
	name  string
	args  []string
	stdin string
}

// localHarness wires a harness to a fake server and replaces the container with
// a recorder. finish is the status the "runner" leaves the scan in (it plays the
// runner's part of finishing the run); runErr is what Docker returns.
func localHarness(t *testing.T, f *fake, finish string, runErr error, env map[string]string) (*harness, *[]dockerCall) {
	t.Helper()
	srv := httptest.NewServer(f.handler())
	t.Cleanup(srv.Close)
	h := newHarness(t, srv, "", false)
	base := h.env.Getenv
	h.env.Getenv = func(k string) string {
		if v, ok := env[k]; ok {
			return v
		}
		return base(k)
	}
	calls := &[]dockerCall{}
	h.env.Docker = func(_ context.Context, name string, args []string, stdin io.Reader, _, stderr io.Writer) error {
		var in bytes.Buffer
		_, _ = in.ReadFrom(stdin)
		*calls = append(*calls, dockerCall{name, args, in.String()})
		_, _ = stderr.Write([]byte("  50%  scanning from the runner\n"))
		if finish != "" {
			f.mu.Lock()
			f.localStatus = finish
			f.mu.Unlock()
		}
		return runErr
	}
	return h, calls
}

func parseConfig(t *testing.T, stdin string) (cfg struct {
	Server  string                       `json:"server"`
	Run     map[string]any               `json:"run"`
	Secrets map[string]map[string]string `json:"secrets"`
}) {
	t.Helper()
	if err := json.Unmarshal([]byte(stdin), &cfg); err != nil {
		t.Fatalf("stdin is not the runner config: %v\n%s", err, stdin)
	}
	return cfg
}

func TestLocalRunKeepsSecretsOffTheCommandLineAndOffTheServer(t *testing.T) {
	f := &fake{apiKey: secretKey}
	h, calls := localHarness(t, f, "completed", nil, map[string]string{
		"AIDETECTOR_SECRET_ALICE": "alice-secret-value",
		"AIDETECTOR_SECRET_ADMIN": "admin-secret-value",
	})
	if code := h.run("run", fakeScanID, "--authorized"); code != ExitOK {
		t.Fatalf("exit = %d\n%s", code, h.errOut.String())
	}
	if len(*calls) != 1 {
		t.Fatalf("docker was called %d times, want 1", len(*calls))
	}
	call := (*calls)[0]
	argv := strings.Join(call.args, " ")
	for _, secret := range []string{"alice-secret-value", "admin-secret-value", "run-token-xyz", secretKey} {
		if strings.Contains(argv, secret) {
			t.Fatalf("a secret reached docker's argv: %q in %s", secret, argv)
		}
	}

	cfg := parseConfig(t, call.stdin)
	if cfg.Secrets["alice"]["secret"] != "alice-secret-value" || cfg.Secrets["admin"]["secret"] != "admin-secret-value" {
		t.Fatalf("secrets = %v", cfg.Secrets)
	}
	if cfg.Run["token"] != "run-token-xyz" {
		t.Fatalf("the per-run token must reach the container: %v", cfg.Run["token"])
	}
	if strings.Contains(call.stdin, secretKey) {
		t.Fatal("the API key must never reach the container; it gets the per-run token only")
	}
	// A loopback server and target would mean the container itself.
	if !strings.Contains(cfg.Server, "host.docker.internal") {
		t.Fatalf("server = %q, want a host.docker.internal address", cfg.Server)
	}
	if got, _ := cfg.Run["target_base_url"].(string); got != "http://host.docker.internal:9000" {
		t.Fatalf("target = %q", got)
	}
	// The secrets went nowhere but the container's stdin: not the server, not the terminal.
	for _, secret := range []string{"alice-secret-value", "admin-secret-value", "run-token-xyz"} {
		if strings.Contains(h.out.String()+h.errOut.String(), secret) {
			t.Fatalf("%q was printed", secret)
		}
		for key, body := range f.bodies {
			if strings.Contains(string(body), secret) {
				t.Fatalf("%q was sent to the server in %s", secret, key)
			}
		}
	}
	if !strings.Contains(h.errOut.String(), "scanning from the runner") {
		t.Fatalf("the runner's progress should reach the terminal: %q", h.errOut.String())
	}
}

// sharedUserClaim is two identities with the same role: a role key can no
// longer stand for both of them.
func sharedUserClaim() []any {
	return []any{
		map[string]any{"name": "alice", "role": "user", "auth_type": "header"},
		map[string]any{"name": "bob", "role": "user", "auth_type": "header"},
	}
}

func TestLocalRunKeepsSameRoleSecretsDistinctByName(t *testing.T) {
	f := &fake{claimCredentials: sharedUserClaim()}
	h, calls := localHarness(t, f, "completed", nil, map[string]string{
		"AIDETECTOR_SECRET_ALICE": "alice-secret-value",
		"AIDETECTOR_SECRET_BOB":   "bob-secret-value",
	})
	if code := h.run("run", fakeScanID, "--authorized"); code != ExitOK {
		t.Fatalf("exit = %d\n%s", code, h.errOut.String())
	}
	if len(*calls) != 1 {
		t.Fatalf("docker was called %d times, want 1", len(*calls))
	}
	cfg := parseConfig(t, (*calls)[0].stdin)
	if cfg.Secrets["alice"]["secret"] != "alice-secret-value" || cfg.Secrets["bob"]["secret"] != "bob-secret-value" {
		t.Fatalf("the two identities lost their own secrets: %v", cfg.Secrets)
	}
	if cfg.Secrets["user"]["secret"] != "" {
		t.Fatalf("secrets must not be keyed by the shared role: %v", cfg.Secrets)
	}
}

func TestLocalRunRefusesARoleSecretWhenTheRoleIsShared(t *testing.T) {
	f := &fake{claimCredentials: sharedUserClaim()}
	h, calls := localHarness(t, f, "completed", nil, map[string]string{
		"AIDETECTOR_SECRET_USER": "one-secret-for-both",
	})
	if code := h.run("run", fakeScanID, "--authorized"); code != ExitUsage {
		t.Fatalf("exit = %d, want %d\n%s", code, ExitUsage, h.errOut.String())
	}
	if len(*calls) != 0 {
		t.Fatal("no container may start when a shared role key is ambiguous")
	}
	msg := h.errOut.String()
	if !strings.Contains(msg, `the "user" role is shared`) || !strings.Contains(msg, "key the secret by name") {
		t.Fatalf("the error must name the shared role and say to key by name: %q", msg)
	}
	// The run was claimed before the secrets were read, so it must be closed.
	if !f.sawRequest("POST /runner/runs/r1aaaaaa-bbbb/fail") {
		t.Fatal("a claimed run must not be left open when the CLI bails out")
	}
}

func TestLocalRunSecretsFileKeyedByNameForASharedRole(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("no unix modes on windows")
	}
	f := &fake{claimCredentials: sharedUserClaim()}
	h, calls := localHarness(t, f, "completed", nil, nil)
	path := filepath.Join(t.TempDir(), "secrets.json")
	if err := os.WriteFile(path, []byte(`{"alice":"alice-secret-value","bob":"bob-secret-value"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if code := h.run("run", fakeScanID, "--authorized", "--secrets-file", path); code != ExitOK {
		t.Fatalf("exit = %d\n%s", code, h.errOut.String())
	}
	cfg := parseConfig(t, (*calls)[0].stdin)
	if cfg.Secrets["alice"]["secret"] != "alice-secret-value" || cfg.Secrets["bob"]["secret"] != "bob-secret-value" {
		t.Fatalf("secrets = %v", cfg.Secrets)
	}
}

func TestLocalRunRefusesASharedRoleKeyInTheSecretsFile(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("no unix modes on windows")
	}
	f := &fake{claimCredentials: sharedUserClaim()}
	h, calls := localHarness(t, f, "completed", nil, nil)
	path := filepath.Join(t.TempDir(), "secrets.json")
	if err := os.WriteFile(path, []byte(`{"user":"one-secret-for-both"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if code := h.run("run", fakeScanID, "--authorized", "--secrets-file", path); code != ExitUsage {
		t.Fatalf("exit = %d, want %d\n%s", code, ExitUsage, h.errOut.String())
	}
	if len(*calls) != 0 {
		t.Fatal("no container may start when a shared role key is ambiguous")
	}
	msg := h.errOut.String()
	if !strings.Contains(msg, `the "user" role is shared`) || !strings.Contains(msg, "key the secret by name") {
		t.Fatalf("the error must name the shared role and say to key by name: %q", msg)
	}
}

func claimOf(pairs ...string) []any {
	out := []any{}
	for i := 0; i+1 < len(pairs); i += 2 {
		out = append(out, map[string]any{"name": pairs[i], "role": pairs[i+1], "auth_type": "header"})
	}
	return out
}

// A name owns its environment key: a role fallback must never hand another
// identity the secret of the identity actually named after that role.
func TestLocalRunRoleEnvFallbackNeverTakesANamedIdentitysKey(t *testing.T) {
	cases := []struct {
		name  string
		claim []any
		env   map[string]string
		want  map[string]map[string]string
	}{
		{
			name:  "role names another identity",
			claim: claimOf("alice", "user", "user", "admin"),
			env:   map[string]string{"AIDETECTOR_SECRET_USER": "user-token", "AIDETECTOR_REFRESH_SECRET_USER": "user-refresh"},
			want:  map[string]map[string]string{"user": {"secret": "user-token", "refresh_secret": "user-refresh"}},
		},
		{
			name:  "shared role, one identity named after it",
			claim: claimOf("user", "user", "bob", "user"),
			env:   map[string]string{"AIDETECTOR_SECRET_USER": "user-token"},
			want:  map[string]map[string]string{"user": {"secret": "user-token", "refresh_secret": ""}},
		},
		{
			name:  "role normalises onto another identity's name",
			claim: claimOf("alice", "user-a", "user_a", "admin"),
			env:   map[string]string{"AIDETECTOR_SECRET_USER_A": "user-a-token"},
			want:  map[string]map[string]string{"user_a": {"secret": "user-a-token", "refresh_secret": ""}},
		},
		{
			name:  "unique role still falls back",
			claim: claimOf("alice", "user", "root", "admin"),
			env:   map[string]string{"AIDETECTOR_SECRET_USER": "alice-token", "AIDETECTOR_SECRET_ROOT": "root-token"},
			want: map[string]map[string]string{
				"alice": {"secret": "alice-token", "refresh_secret": ""},
				"root":  {"secret": "root-token", "refresh_secret": ""},
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := &fake{claimCredentials: tc.claim}
			h, calls := localHarness(t, f, "completed", nil, tc.env)
			if code := h.run("run", fakeScanID, "--authorized"); code != ExitOK {
				t.Fatalf("exit = %d\n%s", code, h.errOut.String())
			}
			got := parseConfig(t, (*calls)[0].stdin).Secrets
			if len(got) != len(tc.want) {
				t.Fatalf("secrets = %v, want %v", got, tc.want)
			}
			for name, entry := range tc.want {
				if got[name]["secret"] != entry["secret"] || got[name]["refresh_secret"] != entry["refresh_secret"] {
					t.Fatalf("secrets[%q] = %v, want %v (all: %v)", name, got[name], entry, got)
				}
			}
		})
	}
}

// `user-a` and `user_a` are distinct names with one environment key: reading
// it for either would give both the same token, so the run refuses.
func TestLocalRunRefusesAnEnvKeyTwoNamesNormaliseTo(t *testing.T) {
	for _, key := range []string{"AIDETECTOR_SECRET_USER_A", "AIDETECTOR_REFRESH_SECRET_USER_A"} {
		t.Run(key, func(t *testing.T) {
			f := &fake{claimCredentials: claimOf("user-a", "user", "user_a", "admin")}
			env := map[string]string{"AIDETECTOR_SECRET_USER_A": "one-token"}
			if key != "AIDETECTOR_SECRET_USER_A" {
				env = map[string]string{key: "one-refresh"}
			}
			h, calls := localHarness(t, f, "completed", nil, env)
			if code := h.run("run", fakeScanID, "--authorized"); code != ExitUsage {
				t.Fatalf("exit = %d, want %d\n%s", code, ExitUsage, h.errOut.String())
			}
			if len(*calls) != 0 {
				t.Fatal("no container may start when an environment key is ambiguous")
			}
			msg := h.errOut.String()
			if !strings.Contains(msg, `"user-a"`) || !strings.Contains(msg, `"user_a"`) || !strings.Contains(msg, "by exact name") {
				t.Fatalf("the error must name both identities and say to key by exact name: %q", msg)
			}
			if !f.sawRequest("POST /runner/runs/r1aaaaaa-bbbb/fail") {
				t.Fatal("a claimed run must not be left open when the CLI bails out")
			}
		})
	}
}

// The same pair resolves when each name is given explicitly in the file.
func TestLocalRunCollidingNamesResolveThroughTheSecretsFile(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("no unix modes on windows")
	}
	f := &fake{claimCredentials: claimOf("user-a", "user", "user_a", "admin")}
	h, calls := localHarness(t, f, "completed", nil, nil)
	path := filepath.Join(t.TempDir(), "secrets.json")
	if err := os.WriteFile(path, []byte(`{"user-a":"dash","user_a":"underscore"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if code := h.run("run", fakeScanID, "--authorized", "--secrets-file", path); code != ExitOK {
		t.Fatalf("exit = %d\n%s", code, h.errOut.String())
	}
	got := parseConfig(t, (*calls)[0].stdin).Secrets
	if got["user-a"]["secret"] != "dash" || got["user_a"]["secret"] != "underscore" {
		t.Fatalf("secrets = %v", got)
	}
}

func TestLocalRunContainerIsLockedDown(t *testing.T) {
	f := &fake{}
	h, calls := localHarness(t, f, "completed", nil, nil)
	code := h.run("run", fakeScanID, "--authorized", "--image", "my/runner:1", "--docker-network", "appnet")
	if code != ExitOK {
		t.Fatalf("exit = %d\n%s", code, h.errOut.String())
	}
	argv := strings.Join((*calls)[0].args, " ")
	for _, want := range []string{
		"--rm", "--read-only", "--cap-drop ALL", "--security-opt no-new-privileges",
		"--user 65534:65534", "--memory 1g", "--pids-limit 512", "--network appnet",
		"my/runner:1 python -m app.runner",
	} {
		if !strings.Contains(argv, want) {
			t.Errorf("docker args missing %q:\n%s", want, argv)
		}
	}
	if strings.Contains(argv, "--privileged") || strings.Contains(argv, "docker.sock") {
		t.Fatal("the runner container must never be privileged or get the docker socket")
	}
}

func TestLocalRunJoinsEveryDockerNetwork(t *testing.T) {
	// A stack whose own network is internal has no route to the server, so the
	// runner joins that one for the target and an egress one for the server.
	f := &fake{}
	h, calls := localHarness(t, f, "completed", nil, nil)
	code := h.run("run", fakeScanID, "--authorized", "--docker-network", "app_internal, app_egress", "--docker-network", "app_internal",
		"--docker-network", "extra")
	if code != ExitOK {
		t.Fatalf("exit = %d\n%s", code, h.errOut.String())
	}
	argv := strings.Join((*calls)[0].args, " ")
	// Comma-separated and repeated forms combine, in order, each name once.
	if !strings.Contains(argv, "--network app_internal --network app_egress --network extra ") {
		t.Fatalf("docker args do not join every network once:\n%s", argv)
	}
	if n := strings.Count(argv, "--network "); n != 3 {
		t.Fatalf("--network appears %d times, want 3:\n%s", n, argv)
	}
}

func TestDockerArgsNetworks(t *testing.T) {
	for _, tc := range []struct {
		networks []string
		want     int
	}{{nil, 0}, {[]string{"a"}, 1}, {[]string{"a", "b"}, 2}} {
		argv := strings.Join(dockerArgs("n", localFlags{image: "img", networks: tc.networks}), " ")
		if n := strings.Count(argv, "--network "); n != tc.want {
			t.Errorf("networks %v: --network appears %d times, want %d:\n%s", tc.networks, n, tc.want, argv)
		}
	}
}

func TestDockerNetworkRefusesWhatDockerWouldBeforeClaiming(t *testing.T) {
	for _, tc := range []struct {
		flags []string
		want  string
	}{
		{[]string{"--docker-network", "a,,b"}, "empty network name"},
		{[]string{"--docker-network", "host,app_egress"}, `"host" cannot be combined`},
		{[]string{"--docker-network", "app", "--docker-network", "container:db"}, `"container:db" cannot be combined`},
	} {
		f := &fake{}
		h, calls := localHarness(t, f, "completed", nil, nil)
		args := append([]string{"run", fakeScanID, "--authorized"}, tc.flags...)
		if code := h.run(args...); code != ExitUsage {
			t.Fatalf("%v: exit = %d, want %d", tc.flags, code, ExitUsage)
		}
		if len(*calls) != 0 || f.countRequests("POST "+fakeScanPath+"/local-runs") != 0 {
			t.Fatalf("%v: a refused flag still claimed the run or started the container", tc.flags)
		}
		if !strings.Contains(h.errOut.String(), tc.want) {
			t.Fatalf("%v: stderr does not name the problem:\n%s", tc.flags, h.errOut.String())
		}
	}
	// A single special mode is still Docker's to judge.
	var single dockerNetworks
	if err := single.Set("host"); err != nil {
		t.Fatalf("host alone was refused: %v", err)
	}
}

func TestLocalRunClosesTheRunIfTheContainerDiesFirst(t *testing.T) {
	f := &fake{}
	// The container fails and never finishes the run: the scan stays "running".
	h, _ := localHarness(t, f, "", errors.New("exit status 137"), nil)
	f.localStatus = "running"
	if code := h.run("run", fakeScanID, "--authorized"); code != ExitFailed {
		t.Fatalf("exit = %d, want %d", code, ExitFailed)
	}
	if !f.sawRequest("POST /runner/runs/r1aaaaaa-bbbb/fail") {
		t.Fatal("the CLI must close a run the container abandoned, or the scan stays locked")
	}
	// It authenticates with the run's own token, not the API key.
	hdr := f.headers["POST /runner/runs/r1aaaaaa-bbbb/fail"]
	if hdr.Get("X-Run-Token") != "run-token-xyz" || hdr.Get("X-API-Key") != "" {
		t.Fatalf("fail must carry only the run token: %v", hdr)
	}
	if !strings.Contains(h.errOut.String(), "ended failed") {
		t.Fatalf("stderr = %q", h.errOut.String())
	}
}

func TestLocalRunGatesOnWhatTheRunnerUploaded(t *testing.T) {
	high := map[string]any{"severity": "high", "confidence": "verified", "check": "bola", "title": "BOLA", "verdict": "unreviewed"}
	f := &fake{findings: []map[string]any{high}}
	h, _ := localHarness(t, f, "completed", nil, nil)
	// --fail-on works without --wait: a local run is synchronous.
	if code := h.run("run", fakeScanID, "--authorized", "--fail-on", "high"); code != ExitFindings {
		t.Fatalf("exit = %d, want %d\n%s", code, ExitFindings, h.out.String())
	}
}

func TestLocalRunStopsIfTheServerRefusesTheClaim(t *testing.T) {
	f := &fake{status: map[string]int{"POST " + fakeScanPath + "/local-runs": 422}}
	h, calls := localHarness(t, f, "completed", nil, nil)
	if code := h.run("run", fakeScanID, "--authorized", "--kali"); code != ExitUsage {
		t.Fatalf("exit = %d, want %d", code, ExitUsage)
	}
	if len(*calls) != 0 {
		t.Fatal("no container may start for a claim the server refused")
	}
}

func TestLocalRunStillAnswersTheAuthorizationGateBeforeClaiming(t *testing.T) {
	f := &fake{}
	h, calls := localHarness(t, f, "completed", nil, nil)
	if code := h.run("run", fakeScanID); code != ExitUsage {
		t.Fatalf("exit = %d, want %d", code, ExitUsage)
	}
	if f.count() != 0 || len(*calls) != 0 {
		t.Fatal("a refused local run must send nothing and start nothing")
	}
}

func TestLocalRunAbandonsTheClaimOnABadSecretsFile(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("no unix modes on windows")
	}
	f := &fake{}
	h, calls := localHarness(t, f, "completed", nil, nil)
	path := filepath.Join(t.TempDir(), "secrets.json")
	if err := os.WriteFile(path, []byte(`{"alice":"u","admin":"a"}`), 0o644); err != nil {
		t.Fatal(err)
	}
	if code := h.run("run", fakeScanID, "--authorized", "--secrets-file", path); code != ExitUsage {
		t.Fatalf("exit = %d, want %d (a world-readable secrets file is refused)", code, ExitUsage)
	}
	if len(*calls) != 0 {
		t.Fatal("no container may start with a loose secrets file")
	}
	// The run was claimed before the file was read, so it must be closed again.
	if !f.sawRequest("POST /runner/runs/r1aaaaaa-bbbb/fail") {
		t.Fatal("a claimed run must not be left open when the CLI bails out")
	}

	if err := os.Chmod(path, 0o600); err != nil {
		t.Fatal(err)
	}
	f2 := &fake{}
	h2, calls2 := localHarness(t, f2, "completed", nil, nil)
	if code := h2.run("run", fakeScanID, "--authorized", "--secrets-file", path); code != ExitOK {
		t.Fatalf("a 0600 secrets file should work: exit = %d\n%s", code, h2.errOut.String())
	}
	cfg := parseConfig(t, (*calls2)[0].stdin)
	if cfg.Secrets["alice"]["secret"] != "u" || cfg.Secrets["admin"]["secret"] != "a" {
		t.Fatalf("secrets = %v", cfg.Secrets)
	}
}

func TestLocalRunWithoutASecretWarnsAndDropsOnlyThatIdentity(t *testing.T) {
	f := &fake{}
	h, calls := localHarness(t, f, "completed", nil, map[string]string{"AIDETECTOR_SECRET_USER": "u"})
	if code := h.run("run", fakeScanID, "--authorized"); code != ExitOK {
		t.Fatalf("exit = %d\n%s", code, h.errOut.String())
	}
	if !strings.Contains(h.errOut.String(), `no secret for the "admin" identity`) {
		t.Fatalf("stderr = %q", h.errOut.String())
	}
	cfg := parseConfig(t, (*calls)[0].stdin)
	if _, has := cfg.Secrets["admin"]; has || cfg.Secrets["alice"]["secret"] != "u" {
		t.Fatalf("secrets = %v", cfg.Secrets)
	}
}

func TestRewriteLoopbackAndEnvName(t *testing.T) {
	for in, want := range map[string]string{
		"http://localhost:8000":   "http://host.docker.internal:8000",
		"http://127.0.0.1:9000/x": "http://host.docker.internal:9000/x",
		"http://[::1]:8000":       "http://host.docker.internal:8000",
		"https://api.example.com": "https://api.example.com",
		"http://10.0.0.5:8080":    "http://10.0.0.5:8080",
		"http://target:9000":      "http://target:9000",
		"not a url":               "not a url",
	} {
		if got := rewriteLoopback(in); got != want {
			t.Errorf("rewriteLoopback(%q) = %q, want %q", in, got, want)
		}
	}
	for in, want := range map[string]string{"user": "USER", "read-only": "READ_ONLY", " a.b ": "A_B"} {
		if got := envName(in); got != want {
			t.Errorf("envName(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestLocalRunMountsSourceReadOnlyForWhitebox(t *testing.T) {
	f := &fake{}
	h, calls := localHarness(t, f, "completed", nil, nil)
	dir := t.TempDir()
	if code := h.run("run", fakeScanID, "--authorized", "--source", dir); code != ExitOK {
		t.Fatalf("exit = %d, want %d", code, ExitOK)
	}
	if len(*calls) != 1 {
		t.Fatalf("docker called %d times, want 1", len(*calls))
	}
	call := (*calls)[0]
	abs, _ := filepath.Abs(dir)
	wantMount := abs + ":" + sourceMount + ":ro"
	if !strings.Contains(strings.Join(call.args, " "), wantMount) {
		t.Fatalf("source not mounted read-only; args: %v", call.args)
	}
	var cfg struct {
		SourceDir string `json:"source_dir"`
	}
	if err := json.Unmarshal([]byte(call.stdin), &cfg); err != nil {
		t.Fatalf("runner config not JSON: %v", err)
	}
	if cfg.SourceDir != sourceMount {
		t.Fatalf("source_dir = %q, want %q", cfg.SourceDir, sourceMount)
	}
}

func TestSourceFlagRejectsAMissingDir(t *testing.T) {
	f := &fake{}
	h, calls := localHarness(t, f, "completed", nil, nil)
	if code := h.run("run", fakeScanID, "--authorized", "--source", "/no/such/dir"); code != ExitUsage {
		t.Fatalf("missing dir exit = %d, want %d", code, ExitUsage)
	}
	if len(*calls) != 0 {
		t.Fatalf("docker should not have been called")
	}
}

func schemaEnv(stderr io.Writer, tty bool, env map[string]string) *Env {
	return &Env{
		Stdout:     io.Discard,
		Stderr:     stderr,
		IsTTY:      func() bool { return tty },
		Getenv:     func(k string) string { return env[k] },
		ReadSecret: func(string) (string, error) { return "typed-secret", nil },
	}
}

func testSchema(host string) *project.Schema {
	return &project.Schema{
		Host: host, Port: 5432, Database: "appdb", Username: "scanner",
		PasswordEnv: "DB_PASSWORD", SSLMode: "disable", Tables: []string{"public.users"},
	}
}

// The schema password is read here, and a loopback host gets the same rewrite
// the target URL does.
func TestCollectSchemaReadsThePasswordAndRewritesLoopback(t *testing.T) {
	cases := []struct {
		name        string
		host        string
		env         map[string]string
		tty         bool
		wantHost    string
		wantPass    string
		wantBlock   bool
		wantWarning string
	}{
		{"password from the environment", "localhost", map[string]string{"DB_PASSWORD": "db-s3cret"}, false,
			"host.docker.internal", "db-s3cret", true, ""},
		{"a remote host is kept", "db.example.com", map[string]string{"DB_PASSWORD": "db-s3cret"}, false,
			"db.example.com", "db-s3cret", true, ""},
		{"a loopback address is rewritten", "127.0.0.1", map[string]string{"DB_PASSWORD": "db-s3cret"}, false,
			"host.docker.internal", "db-s3cret", true, ""},
		{"no password and no terminal sends the block without one", "db.example.com", nil, false,
			"db.example.com", "", true, "warning: no password in $DB_PASSWORD"},
		{"a terminal is asked", "db.example.com", nil, true,
			"db.example.com", "typed-secret", true, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var stderr bytes.Buffer
			e := schemaEnv(&stderr, tc.tty, tc.env)
			block, ca, err := collectSchema(e, testSchema(tc.host), t.TempDir())
			if err != nil {
				t.Fatal(err)
			}
			if ca != "" {
				t.Errorf("caPath = %q, want none", ca)
			}
			if !tc.wantBlock {
				if block != nil {
					t.Fatalf("block = %v, want skipped", block)
				}
			} else {
				if got, _ := block["password"].(string); block["host"] != tc.wantHost || got != tc.wantPass {
					t.Fatalf("block = %v", block)
				}
				if block["port"] != 5432 || block["database"] != "appdb" ||
					block["username"] != "scanner" || block["sslmode"] != "disable" {
					t.Fatalf("block = %v", block)
				}
				tables, _ := block["tables"].([]map[string]string)
				if len(tables) != 1 || tables[0]["schema_name"] != "public" || tables[0]["table_name"] != "users" {
					t.Fatalf("tables = %v", block["tables"])
				}
			}
			if tc.wantWarning != "" && !strings.Contains(stderr.String(), tc.wantWarning) {
				t.Fatalf("stderr = %q, want %q", stderr.String(), tc.wantWarning)
			}
		})
	}
}

// The CA path resolves against the project file's directory, must exist, and is
// mounted at the fixed container path.
func TestCollectSchemaResolvesAndMountsTheCA(t *testing.T) {
	dir := t.TempDir()
	ca := filepath.Join(dir, "ca.pem")
	if err := os.WriteFile(ca, []byte("pem"), 0o644); err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name      string
		cert      string
		wantCA    string
		wantError bool
	}{
		{"relative", "ca.pem", ca, false},
		{"absolute", ca, ca, false},
		{"missing", "missing.pem", "", true},
		{"a directory", ".", "", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s := testSchema("db.example.com")
			s.SSLMode, s.SSLRootCert = "verify-full", tc.cert
			block, caPath, err := collectSchema(schemaEnv(io.Discard, false, map[string]string{"DB_PASSWORD": "pw"}), s, dir)
			if tc.wantError {
				if err == nil {
					t.Fatalf("want an error for sslrootcert %q", tc.cert)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if caPath != tc.wantCA || block["sslrootcert"] != schemaCAMount {
				t.Fatalf("caPath = %q, block = %v", caPath, block)
			}
		})
	}
}

// The CA is mounted read-only and the password never reaches docker's argv.
func TestDockerArgsMountTheSchemaCAAndNeverThePassword(t *testing.T) {
	var stderr bytes.Buffer
	e := schemaEnv(&stderr, false, map[string]string{"DB_PASSWORD": "pw-never-in-argv"})
	dir := t.TempDir()
	ca := filepath.Join(dir, "ca.pem")
	if err := os.WriteFile(ca, []byte("pem"), 0o644); err != nil {
		t.Fatal(err)
	}
	s := testSchema("db.example.com")
	s.SSLMode, s.SSLRootCert = "verify-full", "ca.pem"
	block, caPath, err := collectSchema(e, s, dir)
	if err != nil {
		t.Fatal(err)
	}

	withCA := strings.Join(dockerArgs("n", localFlags{image: "img", schemaCA: caPath}), " ")
	if !strings.Contains(withCA, "--mount type=bind,src="+ca+",dst="+schemaCAMount+",readonly") {
		t.Fatalf("the CA mount is missing: %s", withCA)
	}
	if strings.Contains(withCA, "pw-never-in-argv") {
		t.Fatalf("the schema password reached docker's argv: %s", withCA)
	}
	withoutCA := strings.Join(dockerArgs("n", localFlags{image: "img"}), " ")
	if strings.Contains(withoutCA, schemaCAMount) {
		t.Fatalf("no CA was configured, yet it is mounted: %s", withoutCA)
	}

	cfg, err := runnerConfig("http://127.0.0.1:8000", api.LocalClaim{"token": "t"},
		map[string]map[string]string{}, "", "", block, nil)
	if err != nil {
		t.Fatal(err)
	}
	var decoded struct {
		Schema map[string]any `json:"schema"`
	}
	if err := json.Unmarshal(cfg, &decoded); err != nil {
		t.Fatal(err)
	}
	if decoded.Schema["password"] != "pw-never-in-argv" || decoded.Schema["host"] != "db.example.com" {
		t.Fatalf("cfg[schema] = %v", decoded.Schema)
	}

	noSchema, _ := runnerConfig("http://127.0.0.1:8000", api.LocalClaim{"token": "t"},
		map[string]map[string]string{}, "", "", nil, nil)
	var raw map[string]any
	if err := json.Unmarshal(noSchema, &raw); err != nil {
		t.Fatal(err)
	}
	if _, ok := raw["schema"]; ok {
		t.Fatalf("a nil schema block must not appear in the config: %v", raw)
	}
}

// A CA the unprivileged runner user cannot read is refused here, with the fix,
// rather than surfacing as an opaque "unavailable" from inside the container.

func TestCollectSchemaRefusesACAOthersCannotRead(t *testing.T) {
	dir := t.TempDir()
	ca := filepath.Join(dir, "ca.pem")
	if err := os.WriteFile(ca, []byte("pem"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(ca, 0o600); err != nil {
		t.Fatal(err)
	}
	s := testSchema("db.example.com")
	s.SSLMode, s.SSLRootCert = "verify-full", "ca.pem"
	_, _, err := collectSchema(schemaEnv(io.Discard, false, map[string]string{"DB_PASSWORD": "pw"}), s, dir)
	if err == nil || !strings.Contains(err.Error(), "readable by others") {
		t.Fatalf("err = %v, want a readable-by-others refusal", err)
	}
}

func TestALocalRunWaitsForTheServicesAIAnalysis(t *testing.T) {
	// The runner uploaded and exited; the service is adjudicating before the
	// run completes. That is not a dead runner: wait, never close the run.
	f := &fake{
		runs:     []map[string]any{{"run_number": 1, "status": "analysing"}},
		statuses: []string{"running", "running", "completed"},
	}
	h, _ := localHarness(t, f, "", nil, nil)
	if code := h.run("run", fakeScanID, "--authorized", "--ai"); code != ExitOK {
		t.Fatalf("exit = %d\n%s", code, h.errOut.String())
	}
	if f.sawRequest("POST /runner/runs/r1aaaaaa-bbbb/fail") {
		t.Fatal("an analysing run was closed as if its runner had died")
	}
	if !strings.Contains(h.errOut.String(), "AI analysis") {
		t.Fatalf("the wait was not explained:\n%s", h.errOut.String())
	}
}

func TestADeadRunnerIsStillClosedWhenNothingIsAnalysing(t *testing.T) {
	f := &fake{
		runs:     []map[string]any{{"run_number": 1, "status": "running"}},
		statuses: []string{"running"},
	}
	h, _ := localHarness(t, f, "", nil, nil)
	if code := h.run("run", fakeScanID, "--authorized"); code != ExitFailed {
		t.Fatalf("exit = %d, want %d", code, ExitFailed)
	}
	if !f.sawRequest("POST /runner/runs/r1aaaaaa-bbbb/fail") {
		t.Fatal("a runner that died before uploading must close its run")
	}
}

func TestARunLongerThanTheServerCallTimeoutStillReadsItsResult(t *testing.T) {
	// The deadline once started at the claim, so a run longer than it ended in
	// "context deadline exceeded" after the container had uploaded fine.
	saved := serverCallTimeout
	t.Cleanup(func() { serverCallTimeout = saved })
	serverCallTimeout = 50 * time.Millisecond
	f := &fake{}
	h, _ := localHarness(t, f, "completed", nil, nil)
	scan := h.env.Docker
	h.env.Docker = func(ctx context.Context, name string, args []string, stdin io.Reader, stdout, stderr io.Writer) error {
		time.Sleep(4 * serverCallTimeout)
		return scan(ctx, name, args, stdin, stdout, stderr)
	}
	if code := h.run("run", fakeScanID, "--authorized"); code != ExitOK {
		t.Fatalf("exit = %d, want %d\n%s", code, ExitOK, h.errOut.String())
	}
	if strings.Contains(h.errOut.String(), "deadline exceeded") {
		t.Fatalf("the result read must get its own deadline:\n%s", h.errOut.String())
	}
}

func TestAMissingRunnerImageIsCaughtBeforeTheClaim(t *testing.T) {
	f := &fake{}
	h, calls := localHarness(t, f, "completed", nil, nil)
	h.env.ImageExists = func(context.Context, string) (bool, error) { return false, nil }
	h.env.PullImage = func(context.Context, string, io.Writer) error {
		t.Fatal("the default runner image is built, never pulled")
		return nil
	}
	if code := h.run("run", fakeScanID, "--authorized"); code != ExitUsage {
		t.Fatalf("exit = %d, want %d", code, ExitUsage)
	}
	if f.sawRequest("POST "+fakeScanPath+"/local-runs") || len(*calls) != 0 {
		t.Fatal("nothing should be claimed or started without the image")
	}
	if !strings.Contains(h.errOut.String(), "make runner-image") {
		t.Fatalf("the error should say how to build it:\n%s", h.errOut.String())
	}
}

func TestAStaleRunnerImageIsCalledOutBeforeTheRun(t *testing.T) {
	saved := Version
	t.Cleanup(func() { Version = saved })
	Version = "abc1234"
	for _, tc := range []struct {
		name, label, want string
	}{
		{"older build", "0ld0001", "was built from 0ld0001, and this CLI is abc1234"},
		{"no label", "", "was built before runner images were versioned"},
		{"current", "abc1234", ""},
		{"same commit, edited tree", "abc1234-dirty", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := &fake{}
			h, _ := localHarness(t, f, "completed", nil, nil)
			h.env.ImageExists = func(context.Context, string) (bool, error) { return true, nil }
			h.env.ImageRevision = func(_ context.Context, image string) (string, error) {
				if image != runnerImageDefault {
					t.Fatalf("inspected %q", image)
				}
				return tc.label, nil
			}
			if code := h.run("run", fakeScanID, "--authorized"); code != ExitOK {
				t.Fatalf("exit = %d\n%s", code, h.errOut.String())
			}
			got := h.errOut.String()
			if tc.want == "" {
				if strings.Contains(got, "make runner-image") {
					t.Fatalf("a current image needs no warning:\n%s", got)
				}
				return
			}
			if !strings.Contains(got, tc.want) || !strings.Contains(got, "make runner-image") {
				t.Fatalf("want %q and the rebuild command:\n%s", tc.want, got)
			}
		})
	}
}

func TestAMissingCustomImageIsPulledOnlyWhenTheUserSaysSo(t *testing.T) {
	for _, tc := range []struct {
		name   string
		tty    bool
		answer string
		want   int
		pulled bool
	}{
		{"no terminal", false, "", ExitUsage, false},
		{"declined", true, "n\n", ExitUsage, false},
		{"accepted", true, "y\n", ExitOK, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := &fake{}
			h, _ := localHarness(t, f, "completed", nil, nil)
			h.env.IsTTY = func() bool { return tc.tty }
			h.env.Stdin = strings.NewReader(tc.answer)
			pulled := false
			h.env.ImageExists = func(context.Context, string) (bool, error) { return pulled, nil }
			h.env.PullImage = func(_ context.Context, image string, _ io.Writer) error {
				if image != "registry.example/runner:1" {
					t.Fatalf("pulled %q", image)
				}
				pulled = true
				return nil
			}
			code := h.run("run", fakeScanID, "--authorized", "--image", "registry.example/runner:1")
			if code != tc.want || pulled != tc.pulled {
				t.Fatalf("exit = %d (want %d), pulled = %v\n%s", code, tc.want, pulled, h.errOut.String())
			}
		})
	}
}

type startedContainer struct {
	name string
	args []string
}

// withSiblingDocker records detached container starts/stops on the harness.
func withSiblingDocker(h *harness) (*[]startedContainer, *[]string) {
	started := &[]startedContainer{}
	stopped := &[]string{}
	h.env.ImageExists = func(context.Context, string) (bool, error) { return true, nil }
	h.env.StartContainer = func(_ context.Context, name string, args []string) error {
		*started = append(*started, startedContainer{name, args})
		return nil
	}
	h.env.StopContainer = func(name string) { *stopped = append(*stopped, name) }
	return started, stopped
}

func TestLocalRunStartsZapAndKaliSiblingsAndTearsThemDown(t *testing.T) {
	f := &fake{}
	h, calls := localHarness(t, f, "completed", nil, nil)
	started, stopped := withSiblingDocker(h)
	code := h.run("run", fakeScanID, "--authorized", "--zap", "--kali",
		"--docker-network", "appnet")
	if code != ExitOK {
		t.Fatalf("exit = %d\n%s", code, h.errOut.String())
	}
	if len(*started) != 2 {
		t.Fatalf("want ZAP and Kali started, got %d: %v", len(*started), *started)
	}
	var zap, kali startedContainer
	for _, c := range *started {
		switch {
		case strings.Contains(c.name, "-zap-"):
			zap = c
		case strings.Contains(c.name, "-kali-"):
			kali = c
		}
	}
	zapArgs := strings.Join(zap.args, " ")
	if !strings.Contains(zapArgs, "--network appnet") || !strings.Contains(zapArgs, "ghcr.io/zaproxy/zaproxy") {
		t.Fatalf("ZAP not on the network or wrong image: %s", zapArgs)
	}
	if !strings.Contains(zapArgs, "api.key=") {
		t.Fatalf("ZAP started without an api key: %s", zapArgs)
	}
	kaliArgs := strings.Join(kali.args, " ")
	if !strings.Contains(kaliArgs, "--network appnet") || !strings.Contains(kaliArgs, "KALI_API_KEY=") {
		t.Fatalf("Kali not on the network or without a key: %s", kaliArgs)
	}

	// The runner config points at the siblings by name, with the keys on stdin.
	cfg := parseFullConfig(t, (*calls)[0].stdin)
	adj, _ := cfg["adjuncts"].(map[string]any)
	zc, _ := adj["zap"].(map[string]any)
	kc, _ := adj["kali"].(map[string]any)
	if zc == nil || !strings.HasPrefix(zc["base_url"].(string), "http://"+zap.name+":8090") {
		t.Fatalf("runner config missing the ZAP url: %v", adj)
	}
	if kc == nil || !strings.HasPrefix(kc["base_url"].(string), "http://"+kali.name+":8091") {
		t.Fatalf("runner config missing the Kali url: %v", adj)
	}
	// Both siblings are removed on exit.
	if len(*stopped) != 2 {
		t.Fatalf("both siblings should be torn down, got %v", *stopped)
	}
}

func TestZapAndKaliNeedAScanNetwork(t *testing.T) {
	f := &fake{}
	h, calls := localHarness(t, f, "completed", nil, nil)
	withSiblingDocker(h)
	// No --docker-network: the runner could not reach a sibling by name.
	if code := h.run("run", fakeScanID, "--authorized", "--zap"); code != ExitUsage {
		t.Fatalf("exit = %d, want %d", code, ExitUsage)
	}
	if len(*calls) != 0 {
		t.Fatal("the runner must not start when the siblings cannot be reached")
	}
	if !strings.Contains(h.errOut.String(), "--docker-network") {
		t.Fatalf("the error should say how to fix it:\n%s", h.errOut.String())
	}
}

func TestAFailedSiblingClosesTheRun(t *testing.T) {
	f := &fake{}
	h, calls := localHarness(t, f, "completed", nil, nil)
	h.env.ImageExists = func(context.Context, string) (bool, error) { return true, nil }
	h.env.StartContainer = func(context.Context, string, []string) error {
		return fmt.Errorf("docker daemon said no")
	}
	h.env.StopContainer = func(string) {}
	if code := h.run("run", fakeScanID, "--authorized", "--zap", "--docker-network", "appnet"); code != ExitUsage {
		t.Fatalf("exit = %d, want %d", code, ExitUsage)
	}
	if len(*calls) != 0 {
		t.Fatal("the runner must not start when a sibling failed")
	}
	if !f.sawRequest("POST /runner/runs/r1aaaaaa-bbbb/fail") {
		t.Fatal("the claimed run must be closed when a sibling could not start")
	}
}

func parseFullConfig(t *testing.T, stdin string) map[string]any {
	t.Helper()
	var cfg map[string]any
	if err := json.Unmarshal([]byte(stdin), &cfg); err != nil {
		t.Fatalf("runner config was not JSON: %v", err)
	}
	return cfg
}
