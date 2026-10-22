package config

import (
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func noEnv(string) string { return "" }

func TestBrandEnvironmentCompatibilityKeepsKeysWithTheirServer(t *testing.T) {
	get := CompatibleEnv(env(map[string]string{
		"AIDETECTOR_SERVER":       "https://old.example",
		"AIDETECTOR_API_KEY":      "old-key",
		"AIDETECTOR_SECRET_ALICE": "old-token",
	}))
	if get("RUNPENTESTS_SERVER") != "https://old.example" || get("RUNPENTESTS_API_KEY") != "old-key" || get("RUNPENTESTS_SECRET_ALICE") != "old-token" {
		t.Fatal("legacy environment must remain usable")
	}
	get = CompatibleEnv(env(map[string]string{
		"RUNPENTESTS_SERVER": "https://new.example",
		"AIDETECTOR_SERVER":  "https://old.example",
		"AIDETECTOR_API_KEY": "old-key",
	}))
	if get("RUNPENTESTS_SERVER") != "https://new.example" || get("RUNPENTESTS_API_KEY") != "" {
		t.Fatal("new server must not inherit an old namespace key")
	}
	get = CompatibleEnv(env(map[string]string{"RUNPENTESTS_API_KEY": "new-key", "AIDETECTOR_API_KEY": "old-key"}))
	if get("RUNPENTESTS_API_KEY") != "new-key" {
		t.Fatal("new namespace must win")
	}
}

func TestBrandConfigReusesSavedProfilesWithoutCreatingSecretCopies(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("XDG config layout is Unix-specific")
	}
	dir := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", dir)
	legacy := filepath.Join(dir, "aidetector", "config.json")
	if err := Save(legacy, twoProfiles()); err != nil {
		t.Fatal(err)
	}
	got, err := Path("")
	if err != nil || got != legacy {
		t.Fatalf("existing profiles: %q, %v", got, err)
	}
	current := filepath.Join(dir, "runpentests", "config.json")
	if err := Save(current, Store{}); err != nil {
		t.Fatal(err)
	}
	got, err = Path("")
	if err != nil || got != current {
		t.Fatalf("new config must win: %q, %v", got, err)
	}
}

func env(values map[string]string) func(string) string {
	return func(k string) string { return values[k] }
}

func twoProfiles() Store {
	return Store{Current: "staging", Profiles: map[string]Profile{
		"default": {Server: "https://prod.example", APIKey: "prod-key"},
		"staging": {Server: "https://staging.example", APIKey: "staging-key"},
	}}
}

func TestSaveWritesV2OwnerOnlyAndLoadsBack(t *testing.T) {
	path := filepath.Join(t.TempDir(), "sub", "config.json")
	if err := Save(path, twoProfiles()); err != nil {
		t.Fatal(err)
	}
	if runtime.GOOS != "windows" {
		info, _ := os.Stat(path)
		if info.Mode().Perm() != 0o600 {
			t.Fatalf("config mode = %#o, want 0600", info.Mode().Perm())
		}
		dir, _ := os.Stat(filepath.Dir(path))
		if dir.Mode().Perm() != 0o700 {
			t.Fatalf("config dir mode = %#o, want 0700", dir.Mode().Perm())
		}
	}
	// The saved file is the v2 shape, not the old flat one.
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(data, &raw); err != nil {
		t.Fatal(err)
	}
	if _, ok := raw["profiles"]; !ok {
		t.Fatalf("v2 file has no profiles: %s", data)
	}
	if _, ok := raw["server"]; ok {
		t.Fatalf("v2 file must not have a top-level server: %s", data)
	}

	got, err := Load(path, noEnv)
	if err != nil || got.Profile != "staging" ||
		got.Server != "https://staging.example" || got.APIKey != "staging-key" {
		t.Fatalf("Load = %+v, %v", got, err)
	}
}

func TestLoadReadsALegacyFlatFileAsDefault(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.json")
	if err := os.WriteFile(path, []byte(`{"server":"https://old.example","api_key":"k-123"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	st, err := ReadStore(path)
	if err != nil {
		t.Fatal(err)
	}
	if st.Current != "default" || st.Profiles["default"].Server != "https://old.example" ||
		st.Profiles["default"].APIKey != "k-123" {
		t.Fatalf("legacy file = %+v", st)
	}
	got, err := Load(path, noEnv)
	if err != nil || got.Profile != "default" || got.Server != "https://old.example" || got.APIKey != "k-123" {
		t.Fatalf("Load = %+v, %v", got, err)
	}
}

func TestProfileSelectionPrefersEnvThenCurrentThenDefault(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.json")

	// No environment: the file's current profile.
	if err := Save(path, twoProfiles()); err != nil {
		t.Fatal(err)
	}
	got, err := Load(path, noEnv)
	if err != nil || got.Profile != "staging" || got.ProfileFromEnv {
		t.Fatalf("current profile: Load = %+v, %v", got, err)
	}

	// RUNPENTESTS_PROFILE wins for this invocation.
	got, err = Load(path, env(map[string]string{"RUNPENTESTS_PROFILE": "default"}))
	if err != nil || got.Profile != "default" || !got.ProfileFromEnv ||
		got.Server != "https://prod.example" {
		t.Fatalf("env profile: Load = %+v, %v", got, err)
	}

	// No current profile: "default".
	if err := Save(path, Store{Profiles: map[string]Profile{
		"default": {Server: "https://prod.example"},
	}}); err != nil {
		t.Fatal(err)
	}
	got, err = Load(path, noEnv)
	if err != nil || got.Profile != "default" || got.Server != "https://prod.example" {
		t.Fatalf("default fallback: Load = %+v, %v", got, err)
	}
}

func TestUnknownProfileNamesTheKnownOnes(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.json")
	if err := Save(path, twoProfiles()); err != nil {
		t.Fatal(err)
	}
	_, err := Load(path, env(map[string]string{"RUNPENTESTS_PROFILE": "qa"}))
	if err == nil {
		t.Fatal("an unknown RUNPENTESTS_PROFILE must be an error")
	}
	for _, want := range []string{`"qa"`, "default", "staging"} {
		if !strings.Contains(err.Error(), want) {
			t.Fatalf("error %q is missing %q", err, want)
		}
	}
}

func TestEnvironmentServerOverridesTheSelectedProfile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.json")
	if err := Save(path, twoProfiles()); err != nil {
		t.Fatal(err)
	}
	got, err := Load(path, env(map[string]string{
		"RUNPENTESTS_SERVER":  "https://ci.example",
		"RUNPENTESTS_API_KEY": "ci-key",
	}))
	if err != nil {
		t.Fatal(err)
	}
	if got.Profile != "staging" || !got.ServerFromEnv ||
		got.Server != "https://ci.example" || got.APIKey != "ci-key" {
		t.Fatalf("Load = %+v", got)
	}
}

func TestLoadRefusesAConfigOthersCanRead(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("no unix modes on windows")
	}
	path := filepath.Join(t.TempDir(), "config.json")
	if err := os.WriteFile(path, []byte(`{"server":"https://s","api_key":"k"}`), 0o644); err != nil {
		t.Fatal(err)
	}
	_, err := Load(path, noEnv)
	if err == nil || !strings.Contains(err.Error(), "readable by others") {
		t.Fatalf("want a refusal naming the mode, got %v", err)
	}
}

func TestSaveTightensAnExistingLooseFile(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("no unix modes on windows")
	}
	path := filepath.Join(t.TempDir(), "config.json")
	_ = os.WriteFile(path, []byte("{}"), 0o644)
	st := Store{Profiles: map[string]Profile{"default": {Server: "https://s"}}}
	if err := Save(path, st); err != nil {
		t.Fatal(err)
	}
	info, _ := os.Stat(path)
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("mode = %#o after Save, want 0600", info.Mode().Perm())
	}
}

func TestEnvironmentWorksWithNoFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "none.json")
	got, err := Load(path, env(map[string]string{
		"RUNPENTESTS_SERVER":  "https://ci.example",
		"RUNPENTESTS_API_KEY": "ci-key",
	}))
	if err != nil || got.Server != "https://ci.example" || got.APIKey != "ci-key" {
		t.Fatalf("Load = %+v, %v", got, err)
	}
}

func TestNormalizeServer(t *testing.T) {
	cases := []struct {
		in       string
		insecure bool
		want     string
		wantErr  string
	}{
		{"https://scan.example.com/", false, "https://scan.example.com", ""},
		{"http://localhost:8000", false, "http://localhost:8000", ""},
		{"http://127.0.0.1:8000/", false, "http://127.0.0.1:8000", ""},
		{"http://[::1]:8000", false, "http://[::1]:8000", ""},
		{"http://scan.example.com", false, "", "clear text"},
		{"http://scan.example.com", true, "http://scan.example.com", ""},
		{"ftp://scan.example.com", false, "", "unsupported scheme"},
		{"not a url", false, "", "not a server URL"},
		{"https://s.example/api?x=1#f", false, "https://s.example/api", ""},
	}
	for _, c := range cases {
		got, err := NormalizeServer(c.in, c.insecure)
		if c.wantErr != "" {
			if err == nil || !strings.Contains(err.Error(), c.wantErr) {
				t.Errorf("NormalizeServer(%q) err = %v, want %q", c.in, err, c.wantErr)
			}
			continue
		}
		if err != nil || got != c.want {
			t.Errorf("NormalizeServer(%q) = %q, %v; want %q", c.in, got, err, c.want)
		}
	}
}

// A saved key must not follow RUNPENTESTS_SERVER to a different host.
func TestASavedKeyStaysWithItsServer(t *testing.T) {
	path := filepath.Join(t.TempDir(), "c.json")
	if err := Save(path, Store{Current: "default", Profiles: map[string]Profile{
		"default": {Server: "https://scan.example.com", APIKey: "saved-key"},
	}}); err != nil {
		t.Fatal(err)
	}
	env := func(m map[string]string) func(string) string { return func(k string) string { return m[k] } }

	c, err := Load(path, env(map[string]string{"RUNPENTESTS_SERVER": "https://other.example.net"}))
	if err != nil || c.APIKey != "" {
		t.Fatalf("key = %q, err = %v: a saved key must not go to another server", c.APIKey, err)
	}
	c, _ = Load(path, env(map[string]string{"RUNPENTESTS_SERVER": "https://SCAN.example.com/"}))
	if c.APIKey != "saved-key" {
		t.Fatalf("the same server (case, slash) keeps its key, got %q", c.APIKey)
	}
	c, _ = Load(path, env(map[string]string{
		"RUNPENTESTS_SERVER": "https://other.example.net", "RUNPENTESTS_API_KEY": "ci-key",
	}))
	if c.APIKey != "ci-key" {
		t.Fatalf("an explicit key goes with an explicit server, got %q", c.APIKey)
	}
}
