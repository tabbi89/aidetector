package commands

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"runpentests/cli/internal/project"
)

func loadInit(t *testing.T, h *harness) *project.Loaded {
	t.Helper()
	loaded, err := project.Load(filepath.Join(h.env.Dir, project.FileName))
	if err != nil {
		t.Fatalf("the written file must load: %v", err)
	}
	return loaded
}

func TestInitSingleKeyFollowsTheSpecsScheme(t *testing.T) {
	s := &stateful{hints: map[string]any{
		"suggested": "single", "reason": "one key", "operations": 1, "protected_operations": 1,
		"schemes": []any{map[string]any{
			"name": "key", "kind": "apiKey", "auth_type": "query", "header_name": "api_key",
			"grant_type": "static", "scopes": []any{},
		}},
		"roles": []any{},
	}}
	h, _, hits := targetHarness(t, s, "", false, nil)
	writeFile(t, h.env.Dir, "openapi.json", testSpec)
	if code := h.run("init", "--yes"); code != ExitOK {
		t.Fatalf("exit = %d\n%s", code, h.errOut.String())
	}
	f := loadInit(t, h).File
	if f.TokenEnv != "RUNPENTESTS_TOKEN" || f.TokenAuth != "query" || f.TokenHeader != "api_key" {
		t.Fatalf("want a query-key shorthand, got %+v", f)
	}
	if f.Spec != "openapi.json" {
		t.Errorf("the spec found on disk should be recorded, got %q", f.Spec)
	}
	if *hits != 0 {
		t.Errorf("init must never contact the target (%d hits)", *hits)
	}
	if got := s.last("POST /specs/auth-hints")["spec"]; got != testSpec {
		t.Errorf("the local spec should be sent for hints, got %v", got)
	}
	if !strings.Contains(h.errOut.String(), "export RUNPENTESTS_TOKEN=") {
		t.Errorf("init should say which variable to export:\n%s", h.errOut.String())
	}
}

func TestInitRolesWithAnOAuthGrant(t *testing.T) {
	s := &stateful{hints: map[string]any{
		"suggested": "roles", "reason": "admin scopes", "operations": 2, "protected_operations": 2,
		"schemes": []any{map[string]any{
			"name": "oauth", "kind": "oauth2", "auth_type": "bearer", "grant_type": "client_credentials",
			"token_url": "https://auth.example/token", "scopes": []any{"read", "admin"},
		}},
		"roles": []any{
			map[string]any{"name": "user", "privilege": 1},
			map[string]any{"name": "admin", "privilege": 3},
		},
	}}
	h, _, _ := targetHarness(t, s, "", false, nil)
	writeFile(t, h.env.Dir, "openapi.json", testSpec)
	if code := h.run("init", "--yes"); code != ExitOK {
		t.Fatalf("exit = %d\n%s", code, h.errOut.String())
	}
	ids := loadInit(t, h).File.Identities
	if len(ids) != 2 || ids[0].Name != "user" || *ids[0].Rank != 1 || *ids[1].Rank != 3 {
		t.Fatalf("want user(1) and admin(3), got %+v", ids)
	}
	g := ids[1].Grant
	if g == nil || g.Type != "client_credentials" || g.TokenURL != "https://auth.example/token" ||
		g.ClientID != grantPlaceholder {
		t.Fatalf("want a client_credentials grant with a placeholder client_id, got %+v", g)
	}
	if ids[1].SecretEnv != "RUNPENTESTS_ADMIN_TOKEN" {
		t.Errorf("secret_env = %q", ids[1].SecretEnv)
	}
	if !strings.Contains(h.errOut.String(), grantPlaceholder) {
		t.Errorf("init should say what to fill in:\n%s", h.errOut.String())
	}
}

func TestInitWithoutHintsWritesAUserAndAnAdmin(t *testing.T) {
	s := &stateful{} // no hints route: an older server
	h, _, _ := targetHarness(t, s, "", false, nil)
	writeFile(t, h.env.Dir, "openapi.json", testSpec)
	if code := h.run("init", "--yes"); code != ExitOK {
		t.Fatalf("exit = %d\n%s", code, h.errOut.String())
	}
	ids := loadInit(t, h).File.Identities
	if len(ids) != 2 || ids[0].Role != "user" || ids[1].Role != "admin" {
		t.Fatalf("got %+v", ids)
	}
	if !strings.Contains(h.errOut.String(), "auth hints unavailable") {
		t.Errorf("a failed hint lookup should be explained:\n%s", h.errOut.String())
	}
}

func TestInitAsksWhatKindOfAPIOnATerminal(t *testing.T) {
	s := &stateful{}
	h, _, _ := targetHarness(t, s, "public\n", true, nil)
	if code := h.run("init"); code != ExitOK {
		t.Fatalf("exit = %d\n%s", code, h.errOut.String())
	}
	if f := loadInit(t, h).File; f.Auth != "public" || len(f.Identities) != 0 {
		t.Fatalf("want auth: public, got %+v", f)
	}
}

func TestInitRefusesToOverwrite(t *testing.T) {
	s := &stateful{}
	h, _, _ := targetHarness(t, s, "", false, nil)
	writeFile(t, h.env.Dir, project.FileName, "level: quick\n")
	if code := h.run("init", "--yes"); code != ExitUsage {
		t.Fatalf("exit = %d, want %d", code, ExitUsage)
	}
	data, _ := os.ReadFile(filepath.Join(h.env.Dir, project.FileName))
	if string(data) != "level: quick\n" {
		t.Errorf("the existing file must be left alone, got %q", data)
	}
	if code := h.run("init", "--yes", "--force"); code != ExitOK {
		t.Fatalf("--force should overwrite: exit = %d\n%s", code, h.errOut.String())
	}
}

func TestTargetFormPublicAPIIsNotWarnedAboutIdentities(t *testing.T) {
	s := &stateful{}
	h, target, _ := targetHarness(t, s, "", false, nil)
	writeFile(t, h.env.Dir, project.FileName, "auth: public\n")
	if code := h.run(target, "--authorized"); code != ExitOK {
		t.Fatalf("exit = %d\n%s", code, h.errOut.String())
	}
	if strings.Contains(h.errOut.String(), "no identities") {
		t.Errorf("auth: public is deliberate; no warning expected:\n%s", h.errOut.String())
	}
}

func TestTargetFormTokenEnvShorthandAddsOneIdentity(t *testing.T) {
	s := &stateful{}
	h, target, _ := targetHarness(t, s, "", false, map[string]string{"MY_KEY": "k-123"})
	writeFile(t, h.env.Dir, project.FileName,
		"token_env: MY_KEY\ntoken_auth: api_key\ntoken_header: X-Api-Token\n")
	if code := h.run(target, "--authorized"); code != ExitOK {
		t.Fatalf("exit = %d\n%s", code, h.errOut.String())
	}
	// The shape goes to the server; the secret stays on this machine.
	body := s.last("POST /scans/new1/credentials")
	if body["name"] != "default" || body["auth_type"] != "api_key" ||
		body["header_name"] != "X-Api-Token" || body["local_only"] != true || body["secret"] != nil {
		t.Fatalf("want the expanded identity, local-only, got %v", body)
	}
}

func TestCredAddUpdateReplacesAnExistingIdentity(t *testing.T) {
	s := &stateful{scans: []map[string]any{{
		"id": fakeScanID, "target_base_url": "http://t", "status": "draft", "operations": []any{},
		"managed_config": map[string]any{},
		"credential_profiles": []any{map[string]any{
			"id": "c-alice", "name": "alice", "role": "user", "auth_type": "bearer",
		}},
	}}}
	h, _, _ := targetHarness(t, s, "new-secret\n", false, nil)
	args := []string{"cred", "add", fakeScanID, "--name", "alice", "--role", "viewer",
		"--auth-type", "cookie", "--header-name", "sid", "--privilege", "0", "--secret-stdin"}
	if code := h.run(append(args, "--update")...); code != ExitOK {
		t.Fatalf("exit = %d\n%s", code, h.errOut.String())
	}
	body := s.last("PATCH /scans/" + fakeScanID + "/credentials/c-alice")
	if body["role"] != "viewer" || body["auth_type"] != "cookie" || body["header_name"] != "sid" ||
		body["privilege"] != float64(0) {
		t.Fatalf("want the new shape patched, got %v", body)
	}
	if body["secret"] != "new-secret" {
		t.Errorf("the new secret should replace the stored one: %v", body)
	}
}
