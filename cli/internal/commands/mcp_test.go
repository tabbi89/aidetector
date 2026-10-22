package commands

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"

	"runpentests/cli/docs"
	"runpentests/cli/internal/project"
)

// mcpSession runs `runpentests mcp` over the given requests (after initialize)
// and returns each answer by id.
func mcpSession(t *testing.T, h *harness, requests ...map[string]any) map[int]map[string]any {
	t.Helper()
	lines := []string{
		`{"jsonrpc":"2.0","id":0,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"test","version":"1"}}}`,
		`{"jsonrpc":"2.0","method":"notifications/initialized"}`,
	}
	for i, r := range requests {
		r["jsonrpc"] = "2.0"
		r["id"] = i + 1
		b, err := json.Marshal(r)
		if err != nil {
			t.Fatal(err)
		}
		lines = append(lines, string(b))
	}
	h.env.Stdin = strings.NewReader(strings.Join(lines, "\n") + "\n")
	if code := h.run("mcp"); code != ExitOK {
		t.Fatalf("mcp exit = %d\n%s", code, h.errOut.String())
	}
	out := map[int]map[string]any{}
	for _, line := range strings.Split(strings.TrimSpace(h.out.String()), "\n") {
		var msg map[string]any
		if err := json.Unmarshal([]byte(line), &msg); err != nil {
			t.Fatalf("stdout must hold only protocol messages, got %q", line)
		}
		id, ok := msg["id"].(float64)
		if !ok {
			t.Fatalf("an answer without an id: %s", line)
		}
		out[int(id)] = msg
	}
	if len(out) != len(requests)+1 {
		t.Fatalf("want %d answers (the notification gets none), got %d:\n%s", len(requests)+1, len(out), h.out.String())
	}
	return out
}

func call(name string, args map[string]any) map[string]any {
	return map[string]any{"method": "tools/call", "params": map[string]any{"name": name, "arguments": args}}
}

// toolJSON decodes a tool answer's text, failing on a protocol error.
func toolJSON(t *testing.T, msg map[string]any) (map[string]any, bool) {
	t.Helper()
	res, ok := msg["result"].(map[string]any)
	if !ok {
		t.Fatalf("want a result, got %v", msg)
	}
	text := res["content"].([]any)[0].(map[string]any)["text"].(string)
	isError, _ := res["isError"].(bool)
	if isError {
		return map[string]any{"error": text}, true
	}
	var out map[string]any
	if err := json.Unmarshal([]byte(text), &out); err != nil {
		t.Fatalf("tool text is not JSON: %q", text)
	}
	return out, false
}

func TestMCPOffersSetupToolsAndNoWayToRunAScan(t *testing.T) {
	h, _, _ := targetHarness(t, &stateful{}, "", false, nil)
	answers := mcpSession(t, h, map[string]any{"method": "tools/list"})
	hello := answers[0]["result"].(map[string]any)
	if hello["protocolVersion"] != "2025-06-18" {
		t.Errorf("the client's protocol version should be echoed, got %v", hello["protocolVersion"])
	}
	var names []string
	for _, tool := range answers[1]["result"].(map[string]any)["tools"].([]any) {
		names = append(names, tool.(map[string]any)["name"].(string))
	}
	sort.Strings(names)
	want := []string{"find_spec", "next_steps", "server_status", "suggest_config", "validate_config"}
	if !reflect.DeepEqual(names, want) {
		// A run tool would let an agent answer the authorization gate, which
		// must stay one explicit act by a person.
		t.Fatalf("tools = %v, want exactly %v", names, want)
	}
}

func TestMCPServesEveryGuideAndTheSetupPrompt(t *testing.T) {
	h, _, _ := targetHarness(t, &stateful{}, "", false, nil)
	answers := mcpSession(t, h,
		map[string]any{"method": "resources/list"},
		map[string]any{"method": "resources/read", "params": map[string]any{"uri": "runpentests://docs/project-file"}},
		map[string]any{"method": "prompts/get", "params": map[string]any{
			"name": "setup_runpentests", "arguments": map[string]any{"target": "https://staging.example.com"},
		}},
	)
	listed := answers[1]["result"].(map[string]any)["resources"].([]any)
	if len(listed) != len(mcpGuides) {
		t.Errorf("want %d guides listed, got %d", len(mcpGuides), len(listed))
	}
	text := answers[2]["result"].(map[string]any)["contents"].([]any)[0].(map[string]any)["text"].(string)
	if !strings.Contains(text, "secret_env") {
		t.Errorf("the project-file guide should be served whole, got %.80q", text)
	}
	msg := answers[3]["result"].(map[string]any)["messages"].([]any)[0].(map[string]any)
	prompt := msg["content"].(map[string]any)["text"].(string)
	if !strings.Contains(prompt, "https://staging.example.com") || !strings.Contains(prompt, "You prepare; a person runs") {
		t.Errorf("the prompt should carry the target and the setup guide:\n%.300s", prompt)
	}
}

func TestMCPFindSpecListsCandidatesAndStaysInTheProject(t *testing.T) {
	h, _, _ := targetHarness(t, &stateful{}, "", false, nil)
	writeFile(t, h.env.Dir, "api/openapi.yaml", "openapi: 3.0.0")
	writeFile(t, h.env.Dir, "openapi.json", testSpec)
	writeFile(t, h.env.Dir, "node_modules/x/openapi.json", testSpec)
	answers := mcpSession(t, h,
		call("find_spec", nil),
		call("find_spec", map[string]any{"dir": ".."}),
	)
	got, isErr := toolJSON(t, answers[1])
	if isErr {
		t.Fatalf("find_spec failed: %v", got)
	}
	if got["suggested"] != "openapi.json" {
		t.Errorf("the shallowest spec should lead, got %v", got["suggested"])
	}
	if c := got["candidates"].([]any); len(c) != 2 {
		t.Errorf("vendored trees are skipped: want 2 candidates, got %v", c)
	}
	if out, isErr := toolJSON(t, answers[2]); !isErr || !strings.Contains(out["error"].(string), "outside the project") {
		t.Errorf("a path outside the project must be refused, got %v", out)
	}
}

func TestMCPSuggestConfigUsesServerHintsAndNeverTheTarget(t *testing.T) {
	s := &stateful{hints: map[string]any{
		"suggested": "roles", "reason": "role scopes", "operations": 2, "protected_operations": 2,
		"schemes": []any{map[string]any{
			"name": "bearer", "kind": "http", "auth_type": "bearer", "grant_type": "static", "scopes": []any{},
		}},
		"roles": []any{
			map[string]any{"name": "member", "privilege": 1},
			map[string]any{"name": "admin", "privilege": 3},
		},
	}}
	h, _, hits := targetHarness(t, s, "", false, nil)
	writeFile(t, h.env.Dir, "openapi.json", testSpec)
	answers := mcpSession(t, h, call("suggest_config", map[string]any{"target": "https://staging.example.com"}))
	got, isErr := toolJSON(t, answers[1])
	if isErr {
		t.Fatalf("suggest_config failed: %v", got)
	}
	if got["kind"] != "roles" || got["kind_source"] != "server hints" {
		t.Errorf("the server's suggestion should decide, got kind=%v from %v", got["kind"], got["kind_source"])
	}
	draft := got["draft"].(string)
	f, err := project.Parse([]byte(draft), project.FileName)
	if err != nil {
		t.Fatalf("the draft must load as written: %v\n%s", err, draft)
	}
	if len(f.Identities) != 2 || f.Identities[0].Name != "member" || f.Spec != "openapi.json" {
		t.Errorf("want one identity per hinted role and the spec recorded, got %+v", f)
	}
	if s.last("POST /specs/auth-hints")["spec"] != testSpec {
		t.Errorf("the spec should be sent to the runpentests server for hints")
	}
	if *hits != 0 {
		t.Errorf("suggest_config must never contact the target (%d hits)", *hits)
	}
	h.assertNoSecretPrinted(t)
}

func TestMCPSuggestConfigWithoutALoginSaysWhy(t *testing.T) {
	h, _, _ := targetHarness(t, &stateful{}, "", false, map[string]string{"RUNPENTESTS_SERVER": ""})
	writeFile(t, h.env.Dir, "openapi.json", testSpec)
	answers := mcpSession(t, h, call("suggest_config", map[string]any{"kind": "single"}))
	got, isErr := toolJSON(t, answers[1])
	if isErr {
		t.Fatalf("suggest_config failed: %v", got)
	}
	if got["server_hints_unavailable"] != errNotLoggedIn {
		t.Errorf("want the not-logged-in reason, got %v", got["server_hints_unavailable"])
	}
	if !strings.Contains(got["draft"].(string), "token_env: RUNPENTESTS_TOKEN") {
		t.Errorf("kind single should draft the token_env shorthand:\n%s", got["draft"])
	}
}

func TestMCPValidateConfigRefusesSecretsAndWarnsOnWrites(t *testing.T) {
	h, _, _ := targetHarness(t, &stateful{}, "", false, nil)
	answers := mcpSession(t, h,
		call("validate_config", map[string]any{"content": "target: https://a.example\ntoken: abc\n"}),
		call("validate_config", map[string]any{"content": "target: https://a.example\nspec: missing.yaml\n" +
			"passes: [writes]\nidentities:\n  - {name: alice, role: user, secret_env: ALICE_TOKEN}\n"}),
		call("validate_config", nil),
	)
	bad, _ := toolJSON(t, answers[1])
	if bad["valid"] != false || !strings.Contains(bad["error"].(string), "secret_env") {
		t.Errorf("a secret key must be refused with the secret_env advice, got %v", bad)
	}
	ok, _ := toolJSON(t, answers[2])
	if ok["valid"] != true {
		t.Fatalf("want valid, got %v", ok)
	}
	warnings := strings.Join(toStrings(ok["warnings"]), "\n")
	for _, want := range []string{"missing.yaml does not exist", "BOLA and BFLA need two", "change target data"} {
		if !strings.Contains(warnings, want) {
			t.Errorf("warnings should mention %q:\n%s", want, warnings)
		}
	}
	missing, _ := toolJSON(t, answers[3])
	if missing["valid"] != false || !strings.Contains(missing["error"].(string), "no runpentests.yml") {
		t.Errorf("with no file on disk, say so, got %v", missing)
	}
}

func TestMCPNextStepsNamesVariablesNeverValues(t *testing.T) {
	h, _, _ := targetHarness(t, &stateful{}, "", false, map[string]string{"ALICE_TOKEN": secretKey})
	writeFile(t, h.env.Dir, project.FileName, "target: https://a.example\nidentities:\n"+
		"  - {name: alice, role: user, secret_env: ALICE_TOKEN}\n"+
		"  - {name: root, role: admin, secret_env: ROOT_TOKEN}\n")
	answers := mcpSession(t, h, call("next_steps", nil))
	got, isErr := toolJSON(t, answers[1])
	if isErr {
		t.Fatalf("next_steps failed: %v", got)
	}
	steps := strings.Join(toStrings(got["steps"]), "\n")
	if !strings.Contains(steps, "export ALICE_TOKEN=...") || !strings.Contains(steps, "export ROOT_TOKEN=...") {
		t.Errorf("each secret_env should be named:\n%s", steps)
	}
	if strings.Contains(steps, "--authorized") {
		t.Errorf("the handed-over command must leave the gate to the person:\n%s", steps)
	}
	h.assertNoSecretPrinted(t)
}

func TestMCPRefusesASymlinkOutOfTheProject(t *testing.T) {
	h, _, _ := targetHarness(t, &stateful{}, "", false, nil)
	outside := t.TempDir()
	writeFile(t, outside, "openapi.json", testSpec)
	if err := os.Symlink(filepath.Join(outside, "openapi.json"), filepath.Join(h.env.Dir, "spec.json")); err != nil {
		t.Skipf("no symlinks here: %v", err)
	}
	answers := mcpSession(t, h, call("suggest_config", map[string]any{"spec": "spec.json"}))
	if out, isErr := toolJSON(t, answers[1]); !isErr || !strings.Contains(out["error"].(string), "outside the project") {
		t.Errorf("a symlink leading out of the project must be refused, got %v", out)
	}
}

func toStrings(v any) []string {
	var out []string
	for _, x := range v.([]any) {
		out = append(out, x.(string))
	}
	return out
}

// The guides are a hand-written mirror of the CLI. These keep them honest:
// every project-file key is documented, every pass flag is described, every
// guide is served, and the README links each one.
func TestGuidesMirrorTheProjectFileAndTheFlags(t *testing.T) {
	read := func(name string) string {
		data, err := docs.FS.ReadFile(name)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		return string(data)
	}
	ref := read("project-file.md")
	for _, typ := range []reflect.Type{
		reflect.TypeOf(project.File{}), reflect.TypeOf(project.Identity{}),
		reflect.TypeOf(project.Grant{}), reflect.TypeOf(project.Schema{}),
	} {
		for i := 0; i < typ.NumField(); i++ {
			key := strings.Split(typ.Field(i).Tag.Get("yaml"), ",")[0]
			if key == "" || key == "-" {
				continue
			}
			if !strings.Contains(ref, "`"+key+"`") {
				t.Errorf("project-file.md does not document %s.%s (`%s`)", typ.Name(), typ.Field(i).Name, key)
			}
		}
	}
	passes := read("levels-and-passes.md")
	for flagName := range RunFlags {
		if !strings.Contains(passes, "`--"+flagName+"`") {
			t.Errorf("levels-and-passes.md does not describe --%s", flagName)
		}
	}
	entries, err := docs.FS.ReadDir(".")
	if err != nil {
		t.Fatal(err)
	}
	served := map[string]bool{}
	for _, g := range mcpGuides {
		served[g.file] = true
	}
	readme, err := os.ReadFile(filepath.Join("..", "..", "README.md"))
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if !strings.HasSuffix(e.Name(), ".md") {
			continue
		}
		if !served[e.Name()] {
			t.Errorf("docs/%s is not served by the MCP server (add it to mcpGuides)", e.Name())
		}
		if !strings.Contains(string(readme), "docs/"+e.Name()) {
			t.Errorf("README.md does not link docs/%s", e.Name())
		}
	}
}

func TestMCPNextStepsTreatsALocalhostTargetAsALocalRun(t *testing.T) {
	h, _, _ := targetHarness(t, &stateful{}, "", false, nil)
	writeFile(t, h.env.Dir, project.FileName, "target: http://localhost:9000\nauth: public\n")
	answers := mcpSession(t, h, call("next_steps", nil))
	got, _ := toolJSON(t, answers[1])
	if steps := strings.Join(toStrings(got["steps"]), "\n"); !strings.Contains(steps, "make runner-image") {
		t.Errorf("a localhost target runs locally, so the runner image is a step:\n%s", steps)
	}
}

func TestMCPSuggestConfigWithAKeylessLoginSaysAKeyIsNeeded(t *testing.T) {
	h, _, _ := targetHarness(t, &stateful{}, "", false, map[string]string{"RUNPENTESTS_API_KEY": ""})
	writeFile(t, h.env.Dir, "openapi.json", testSpec)
	answers := mcpSession(t, h, call("suggest_config", nil))
	got, _ := toolJSON(t, answers[1])
	if got["server_hints_unavailable"] != errNoAPIKey {
		t.Errorf("a login without a key is not 'not logged in', got %v", got["server_hints_unavailable"])
	}
}

func TestMCPValidateConfigNeverChecksPathsOutsideTheProject(t *testing.T) {
	h, _, _ := targetHarness(t, &stateful{}, "", false, nil)
	outside := writeFile(t, t.TempDir(), "openapi.json", testSpec)
	answers := mcpSession(t, h, call("validate_config", map[string]any{
		"content": "spec: " + outside + "\nauth: public\npasses: [genai_payloads]\n",
	}))
	got, _ := toolJSON(t, answers[1])
	summary := got["summary"].(map[string]any)
	if _, told := summary["spec_found"]; told {
		t.Errorf("whether a file outside the project exists must not be reported: %v", summary)
	}
	warnings := strings.Join(toStrings(got["warnings"]), "\n")
	if !strings.Contains(warnings, "outside the project") || !strings.Contains(warnings, "spends AI tokens") {
		t.Errorf("want the outside-spec and token warnings:\n%s", warnings)
	}
}
