package project

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func write(t *testing.T, dir, name, body string) string {
	t.Helper()
	p := filepath.Join(dir, name)
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}

const good = `
target: https://staging.example.com
spec: openapi.yaml
rps: 5
passes: [mutate]
fail_on: high
verified_only: true
identities:
  - { name: alice, role: user, secret_env: ALICE_TOKEN }
  - { name: admin, role: admin, auth: header, header: X-Api-Key, secret_env: ADMIN_TOKEN }
`

func TestLoadReadsTheFileAndDefaultsAuthToBearer(t *testing.T) {
	dir := t.TempDir()
	l, err := Load(write(t, dir, FileName, good))
	if err != nil {
		t.Fatal(err)
	}
	if l.Target != "https://staging.example.com" || l.RPS != 5 || l.FailOn != "high" {
		t.Fatalf("unexpected file: %+v", l.File)
	}
	if l.Identities[0].Auth != "bearer" {
		t.Errorf("auth should default to bearer, got %q", l.Identities[0].Auth)
	}
	if len(l.Digest) != 64 || l.Dir != dir {
		t.Errorf("digest/dir: %q %q", l.Digest, l.Dir)
	}
	want := []string{"target", "spec", "identities", "requests_per_second", "run_options"}
	if got := l.Fields(); strings.Join(got, ",") != strings.Join(want, ",") {
		t.Errorf("fields = %v, want %v", got, want)
	}
}

func TestLevelIsReadAcceptedInPassesAndOwnsRunOptions(t *testing.T) {
	l, err := Load(write(t, t.TempDir(), FileName,
		"target: https://x.example.com\nlevel: standard\npasses: [ai, writes]\n"))
	if err != nil {
		t.Fatal(err)
	}
	if l.Level != "standard" {
		t.Fatalf("level = %q, want standard", l.Level)
	}
	want := []string{"target", "run_options"}
	if got := l.Fields(); strings.Join(got, ",") != strings.Join(want, ",") {
		t.Errorf("fields = %v, want %v", got, want)
	}
}

func TestLevelAloneOwnsRunOptions(t *testing.T) {
	l, err := Load(write(t, t.TempDir(), FileName, "level: deep\n"))
	if err != nil {
		t.Fatal(err)
	}
	if got := l.Fields(); len(got) != 1 || got[0] != "run_options" {
		t.Errorf("fields = %v, want run_options", got)
	}
}

func TestOnlyTheKeysAFileSetsAreOwned(t *testing.T) {
	l, err := Load(write(t, t.TempDir(), FileName, "target: https://x.example.com\n"))
	if err != nil {
		t.Fatal(err)
	}
	if got := l.Fields(); len(got) != 1 || got[0] != "target" {
		t.Errorf("a one-key file owns only that key, got %v", got)
	}
}

func TestAnEmptyFileIsValidAndOwnsNothing(t *testing.T) {
	l, err := Load(write(t, t.TempDir(), FileName, ""))
	if err != nil {
		t.Fatal(err)
	}
	if len(l.Fields()) != 0 {
		t.Errorf("fields = %v", l.Fields())
	}
}

func TestTheDigestChangesWithTheContent(t *testing.T) {
	dir := t.TempDir()
	a, _ := Load(write(t, dir, "a.yml", "target: https://x.example.com\n"))
	b, _ := Load(write(t, dir, "b.yml", "target: https://y.example.com\n"))
	if a.Digest == b.Digest {
		t.Fatal("different files must not share a digest")
	}
}

func TestLoadRefuses(t *testing.T) {
	cases := map[string]struct{ body, want string }{
		"a secret value": {
			"identities:\n  - { name: a, role: user, token: abc }\n", "secret_env instead"},
		"a top-level password": {"password: hunter2\n", "secret_env instead"},
		"a typo":               {"indentities: []\n", "indentities"},
		"consent in the file":  {"authorized: true\n", "authorized"},
		"a bad severity":       {"fail_on: loud\n", "fail_on"},
		"a bad level":          {"level: turbo\n", "level must be one of quick, standard, deep"},
		"a rate out of range":  {"rps: 500\n", "rps"},
		"a refinement alone":   {"new_only: true\n", "fail_on"},
		"a duplicate identity": {
			"identities:\n  - {name: a, role: user, secret_env: A}\n  - {name: a, role: admin, secret_env: B}\n",
			"twice"},
		"an identity with no secret_env": {
			"identities:\n  - {name: a, role: user}\n", "secret_env is required"},
		"an unknown auth type": {
			"identities:\n  - {name: a, role: user, auth: magic, secret_env: A}\n", "auth must be"},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			_, err := Load(write(t, t.TempDir(), FileName, tc.body))
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("want an error mentioning %q, got %v", tc.want, err)
			}
		})
	}
}

func TestAnAuthNoneIdentityNeedsNoSecret(t *testing.T) {
	_, err := Load(write(t, t.TempDir(), FileName, "identities:\n  - {name: anon, role: anon, auth: none}\n"))
	if err != nil {
		t.Fatal(err)
	}
}

const schemaBlock = `
target: https://x.example.com
schema:
  host: db.example.com
  database: appdb
  username: scanner
  password_env: DB_PASSWORD
  sslrootcert: ca.pem
  tables: [public.users, audit.*]
`

func TestSchemaDefaultsAndTableRefs(t *testing.T) {
	l, err := Load(write(t, t.TempDir(), FileName, schemaBlock))
	if err != nil {
		t.Fatal(err)
	}
	s := l.Schema
	if s == nil {
		t.Fatal("schema block was not read")
	}
	if s.Port != 5432 || s.SSLMode != "verify-full" {
		t.Errorf("defaults: port = %d, sslmode = %q", s.Port, s.SSLMode)
	}
	if s.PasswordEnv != "DB_PASSWORD" {
		t.Errorf("password_env = %q", s.PasswordEnv)
	}
	if got := l.Fields(); strings.Join(got, ",") != "target" {
		t.Errorf("fields = %v, want [target]: schema is not a managed field", got)
	}
	want := []map[string]string{
		{"schema_name": "public", "table_name": "users"},
		{"schema_name": "audit", "table_name": "*"},
	}
	if got := s.TableRefs(); len(got) != len(want) {
		t.Fatalf("TableRefs = %v, want %v", got, want)
	} else {
		for i := range want {
			if got[i]["schema_name"] != want[i]["schema_name"] || got[i]["table_name"] != want[i]["table_name"] {
				t.Fatalf("TableRefs = %v, want %v", got, want)
			}
		}
	}
}

func TestSchemaBlockIsRefused(t *testing.T) {
	cases := map[string]struct{ body, want string }{
		"no host": {
			"schema:\n  database: appdb\n  username: u\n  password_env: P\n  tables: [public.users]\n",
			"schema: host is required"},
		"a malformed host": {
			"schema:\n  host: db host\n  database: appdb\n  username: u\n  password_env: P\n  tables: [public.users]\n",
			"schema: host"},
		"a port out of range": {
			"schema:\n  host: db\n  port: 70000\n  database: appdb\n  username: u\n  password_env: P\n  tables: [public.users]\n",
			"schema: port"},
		"no database": {
			"schema:\n  host: db\n  username: u\n  password_env: P\n  tables: [public.users]\n",
			"schema: database is required"},
		"a malformed database": {
			"schema:\n  host: db\n  database: 1app\n  username: u\n  password_env: P\n  tables: [public.users]\n",
			"schema: database"},
		"no username": {
			"schema:\n  host: db\n  database: appdb\n  password_env: P\n  tables: [public.users]\n",
			"schema: username is required"},
		"no password_env": {
			"schema:\n  host: db\n  database: appdb\n  username: u\n  tables: [public.users]\n",
			"schema: password_env is required"},
		"an unknown sslmode": {
			"schema:\n  host: db\n  database: appdb\n  username: u\n  password_env: P\n  sslmode: require\n  tables: [public.users]\n",
			"schema: sslmode must be"},
		"verify-full without a CA": {
			"schema:\n  host: db\n  database: appdb\n  username: u\n  password_env: P\n  tables: [public.users]\n",
			"schema: sslrootcert is required"},
		"no tables": {
			"schema:\n  host: db\n  database: appdb\n  username: u\n  password_env: P\n  sslmode: disable\n",
			"schema: tables must list"},
		"too many tables": {
			"schema:\n  host: db\n  database: appdb\n  username: u\n  password_env: P\n  sslmode: disable\n  tables: [" +
				twentyOneTables() + "]\n",
			"schema: tables must list"},
		"a table with no schema": {
			"schema:\n  host: db\n  database: appdb\n  username: u\n  password_env: P\n  sslmode: disable\n  tables: [users]\n",
			"schema.table or schema.*"},
		"a table with too many parts": {
			"schema:\n  host: db\n  database: appdb\n  username: u\n  password_env: P\n  sslmode: disable\n  tables: [public.users.x]\n",
			"schema.table or schema.*"},
		"a malformed table": {
			"schema:\n  host: db\n  database: appdb\n  username: u\n  password_env: P\n  sslmode: disable\n  tables: [public.1users]\n",
			"schema.table or schema.*"},
		"a duplicate table": {
			"schema:\n  host: db\n  database: appdb\n  username: u\n  password_env: P\n  sslmode: disable\n  tables: [public.users, public.users]\n",
			"listed twice"},
		"a wildcard beside a named table": {
			"schema:\n  host: db\n  database: appdb\n  username: u\n  password_env: P\n  sslmode: disable\n  tables: [public.*, public.users]\n",
			"both as schema.* and as a named table"},
		"a pg_ catalog schema": {
			"schema:\n  host: db\n  database: appdb\n  username: u\n  password_env: P\n  sslmode: disable\n  tables: [pg_catalog.pg_class]\n",
			"system schema"},
		"information_schema": {
			"schema:\n  host: db\n  database: appdb\n  username: u\n  password_env: P\n  sslmode: disable\n  tables: [information_schema.tables]\n",
			"system schema"},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			_, err := Load(write(t, t.TempDir(), FileName, tc.body))
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("want an error mentioning %q, got %v", tc.want, err)
			}
		})
	}
}

func TestAuthShorthandsExpandToOneOrdinaryIdentity(t *testing.T) {
	cases := []struct {
		name     string
		body     string
		auth     string
		header   string
		secretEn string
	}{
		{"token_env defaults to bearer", "token_env: API_TOKEN\n", "bearer", "", "API_TOKEN"},
		{"token_auth and token_header follow", `
token_env: API_TOKEN
token_auth: api_key
token_header: X-Api-Key
`, "api_key", "X-Api-Key", "API_TOKEN"},
		{"query names its parameter", `
token_env: API_TOKEN
token_auth: query
token_header: access_token
`, "query", "access_token", "API_TOKEN"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			l, err := Load(write(t, t.TempDir(), FileName, tc.body))
			if err != nil {
				t.Fatal(err)
			}
			ids := l.ExpandIdentities()
			if len(ids) != 1 {
				t.Fatalf("want one expanded identity, got %v", ids)
			}
			id := ids[0]
			if id.Name != "default" || id.Role != "user" || id.Auth != tc.auth ||
				id.Header != tc.header || id.SecretEnv != tc.secretEn {
				t.Fatalf("expanded = %+v", id)
			}
			if got := l.IdentityNames(); len(got) != 1 || got[0] != "default" {
				t.Errorf("identity names = %v", got)
			}
			if got := l.Fields(); len(got) != 1 || got[0] != "identities" {
				t.Errorf("token_env owns identities, got %v", got)
			}
		})
	}
}

func TestAuthPublicOwnsNoIdentities(t *testing.T) {
	l, err := Load(write(t, t.TempDir(), FileName, "auth: public\ntarget: https://x.example.com\n"))
	if err != nil {
		t.Fatal(err)
	}
	if len(l.ExpandIdentities()) != 0 || len(l.IdentityNames()) != 0 {
		t.Fatalf("auth: public must expand to no identities: %+v", l.ExpandIdentities())
	}
	if got := strings.Join(l.Fields(), ","); got != "target,identities" {
		t.Errorf("fields = %q, want target,identities", got)
	}
}

func TestIdentityAcceptRankHeaderNamesAndGrants(t *testing.T) {
	body := `
identities:
  - name: svc
    role: service
    auth: query
    header: access_token
    secret_env: SVC_TOKEN
    rank: 3
    grant:
      type: client_credentials
      token_url: https://auth.example.com/token
      client_id: scanner
      scope: read:items
      format: form
      access_token_field: access_token
  - name: anon
    role: guest
    auth: cookie
    header: session
    secret_env: ANON_TOKEN
    rank: 0
    grant:
      type: password
      token_url: https://auth.example.com/login
      username: alice
      username_field: email
      password_field: pass
      cookie_name: session
`
	l, err := Load(write(t, t.TempDir(), FileName, body))
	if err != nil {
		t.Fatal(err)
	}
	svc := l.Identities[0]
	if svc.Rank == nil || *svc.Rank != 3 {
		t.Fatalf("rank = %v", svc.Rank)
	}
	if svc.Grant == nil || svc.Grant.Type != "client_credentials" ||
		svc.Grant.TokenURL != "https://auth.example.com/token" ||
		svc.Grant.ClientID != "scanner" || svc.Grant.Scope != "read:items" ||
		svc.Grant.Format != "form" {
		t.Fatalf("grant = %+v", svc.Grant)
	}
	anon := l.Identities[1]
	if anon.Auth != "cookie" || anon.Header != "session" || anon.Grant.CookieName != "session" ||
		anon.Grant.UsernameField != "email" || anon.Grant.PasswordField != "pass" {
		t.Fatalf("cookie identity = %+v / %+v", anon, anon.Grant)
	}
}

func TestNewIdentityRulesAreRefused(t *testing.T) {
	cases := map[string]struct{ body, want string }{
		"auth public with identities": {
			"auth: public\nidentities:\n  - {name: a, role: user, secret_env: A}\n", "remove identities"},
		"an unknown top-level auth": {"auth: token\n", "auth must be public"},
		"token_env with identities": {
			"token_env: TOKEN\nidentities:\n  - {name: a, role: user, secret_env: A}\n", "cannot be combined with identities"},
		"token_env with auth public":     {"auth: public\ntoken_env: TOKEN\n", "cannot be combined"},
		"token_auth without token_env":   {"token_auth: api_key\n", "set token_env too"},
		"token_header without token_env": {"token_header: X-Api-Key\n", "set token_env too"},
		"a bad token_env name":           {"token_env: 'not a name'\n", "environment variable name"},
		"token_auth query without a header": {
			"token_env: TOKEN\ntoken_auth: query\n", "token_header is required"},
		"an unknown token_auth": {"token_env: TOKEN\ntoken_auth: magic\n", "token_auth must be"},
		"query without a header": {
			"identities:\n  - {name: a, role: user, auth: query, secret_env: A}\n", "header is required"},
		"cookie without a header": {
			"identities:\n  - {name: a, role: user, auth: cookie, secret_env: A}\n", "header is required"},
		"a header name with a value in it": {
			"identities:\n  - {name: a, role: user, auth: header, header: 'Authorization Basic', secret_env: A}\n",
			"must be a name"},
		"a rank below zero": {
			"identities:\n  - {name: a, role: user, secret_env: A, rank: -1}\n", "rank must be between"},
		"a rank above 100": {
			"identities:\n  - {name: a, role: user, secret_env: A, rank: 101}\n", "rank must be between"},
		"a grant with no type": {
			"identities:\n  - {name: a, role: user, secret_env: A, grant: {token_url: 'https://x.example.com/t'}}\n",
			"grant.type is required"},
		"an unknown grant type": {
			"identities:\n  - {name: a, role: user, secret_env: A, grant: {type: magic, token_url: 'https://x.example.com/t'}}\n",
			"grant.type must be"},
		"a grant with no token_url": {
			"identities:\n  - {name: a, role: user, secret_env: A, grant: {type: password}}\n",
			"grant.token_url is required"},
		"a grant token_url with a bad scheme": {
			"identities:\n  - {name: a, role: user, secret_env: A, grant: {type: password, token_url: 'ftp://x.example.com/t'}}\n",
			"http(s) URL"},
		"a grant with a bad format": {
			"identities:\n  - {name: a, role: user, secret_env: A, grant: {type: password, token_url: 'https://x.example.com/t', format: xml}}\n",
			"json or form"},
		"a grant on auth none": {
			"identities:\n  - {name: a, role: user, auth: none, grant: {type: password, token_url: 'https://x.example.com/t'}}\n",
			"cannot have a grant"},
		"a grant without its secret": {
			"identities:\n  - {name: a, role: user, grant: {type: password, token_url: 'https://x.example.com/t'}}\n",
			"secret_env is required"},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			_, err := Load(write(t, t.TempDir(), FileName, tc.body))
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("want an error mentioning %q, got %v", tc.want, err)
			}
		})
	}
}

func twentyOneTables() string {
	out := make([]string, 21)
	for i := range out {
		out[i] = "s.t" + string(rune('a'+i))
	}
	return strings.Join(out, ", ")
}

// A password in the file is refused as it would be anywhere else, while the
// environment variable name is exactly the accepted shape.
func TestSchemaRefusesAPasswordButAcceptsPasswordEnv(t *testing.T) {
	body := "schema: {host: db, database: appdb, username: u, password: hunter2, " +
		"password_env: P, sslmode: disable, tables: [public.users]}\n"
	if _, err := Load(write(t, t.TempDir(), FileName, body)); err == nil ||
		!strings.Contains(err.Error(), "secret_env instead") {
		t.Fatalf("a schema password must be refused, got %v", err)
	}
	ok := "schema: {host: db, database: appdb, username: u, password_env: P, " +
		"sslmode: disable, tables: [public.users]}\n"
	if _, err := Load(write(t, t.TempDir(), FileName, ok)); err != nil {
		t.Fatalf("password_env must be accepted: %v", err)
	}
}

func TestFindLooksForEitherName(t *testing.T) {
	dir := t.TempDir()
	if l, err := Find(dir); l != nil || err != nil {
		t.Fatalf("no file: want nil, nil; got %v, %v", l, err)
	}
	write(t, dir, AltFileName, "target: https://x.example.com\n")
	l, err := Find(dir)
	if err != nil || l == nil || l.Target != "https://x.example.com" {
		t.Fatalf("got %v, %v", l, err)
	}
}

func TestFindSpecPrefersTheShallowestAndSkipsVendoredTrees(t *testing.T) {
	dir := t.TempDir()
	write(t, dir, "node_modules/pkg/openapi.json", "{}")
	write(t, dir, "services/api/docs/openapi.yaml", "{}")
	write(t, dir, "docs/swagger.json", "{}")
	got, err := FindSpec(dir)
	if err != nil {
		t.Fatal(err)
	}
	if got != filepath.Join(dir, "docs", "swagger.json") {
		t.Errorf("got %s", got)
	}
}

func TestFindSpecHasADepthLimit(t *testing.T) {
	dir := t.TempDir()
	write(t, dir, "a/b/c/d/openapi.json", "{}")
	if got, _ := FindSpec(dir); got != "" {
		t.Errorf("a spec four levels down should not be found, got %s", got)
	}
	write(t, dir, "orders.openapi.yml", "{}")
	if got, _ := FindSpec(dir); filepath.Base(got) != "orders.openapi.yml" {
		t.Errorf("*.openapi.yml should be found, got %s", got)
	}
}

func TestNormalizeTarget(t *testing.T) {
	cases := map[string]string{
		"https://API.Example.com/":      "https://api.example.com",
		"https://api.example.com:443":   "https://api.example.com",
		"http://api.example.com:80/v1/": "http://api.example.com/v1",
		"api.example.com":               "https://api.example.com",
		"localhost:9000":                "http://localhost:9000",
		"127.0.0.1:8080/api":            "http://127.0.0.1:8080/api",
		"http://[::1]:9000":             "http://[::1]:9000",
	}
	for in, want := range cases {
		got, err := NormalizeTarget(in)
		if err != nil || got != want {
			t.Errorf("NormalizeTarget(%q) = %q, %v; want %q", in, got, err, want)
		}
	}
	for _, bad := range []string{"", "ftp://x.example.com", "https://u:p@x.example.com",
		"https://x.example.com/?a=1", "https://"} {
		if _, err := NormalizeTarget(bad); err == nil {
			t.Errorf("NormalizeTarget(%q) should fail", bad)
		}
	}
}

func TestSameTargetIgnoresSpellingButNotPathsOrPorts(t *testing.T) {
	if !SameTarget("https://Example.com/", "example.com") {
		t.Error("case, slash and implied scheme should not matter")
	}
	if SameTarget("https://example.com/v1", "https://example.com/v2") {
		t.Error("different base paths are different targets")
	}
	if SameTarget("http://localhost:9000", "http://localhost:9001") {
		t.Error("different ports are different targets")
	}
}

func TestLooksLikeTarget(t *testing.T) {
	for _, yes := range []string{"https://x", "example.com", "localhost:9000", "api.example.com/v1"} {
		if !LooksLikeTarget(yes) {
			t.Errorf("%q should look like a target", yes)
		}
	}
	for _, no := range []string{"scans", "run", "findings", "--authorized", "./src", "help"} {
		if LooksLikeTarget(no) {
			t.Errorf("%q should not look like a target", no)
		}
	}
}

func TestLocalIsNoLongerAKey(t *testing.T) {
	// Every run is local, so the key that chose the lane is gone, and an
	// unknown key is refused rather than silently ignored.
	if _, err := Parse([]byte("target: https://api.example.com\nlocal: true\n"), FileName); err == nil {
		t.Fatal("local: should be refused as an unknown key")
	}
}

func TestIdentityAcceptsATenantAndBoundsIt(t *testing.T) {
	f, err := Parse([]byte("identities:\n  - { name: a, role: editor, tenant: ws-a, secret_env: A }\n"), "aidetector.yml")
	if err != nil {
		t.Fatal(err)
	}
	if got := f.Identities[0].Tenant; got != "ws-a" {
		t.Fatalf("tenant = %q", got)
	}
	long := strings.Repeat("x", 121)
	if _, err := Parse([]byte("identities:\n  - { name: a, role: editor, tenant: "+long+", secret_env: A }\n"), "aidetector.yml"); err == nil {
		t.Fatal("a tenant over 120 characters should be refused")
	}
}
