// Package project reads aidetector.yml, the project file that lets a plain
// `aidetector` inside a repository know what to scan and how.
//
// The file is committed, so two rules shape it:
//   - it never holds a secret: an identity names the environment variable its
//     secret lives in (secret_env), and a key that looks like a secret is
//     refused with that advice rather than silently ignored;
//   - it never holds consent: there is no `authorized` key, because a file is
//     copied into forks and branches, and the authorization gate must be
//     answered by whoever runs the command (--authorized or the prompt).
//
// Precedence is CLI flags > this file > the web's saved settings > defaults,
// decided setting by setting: a key the file does not set is left to the web.
package project

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"
)

// FileName is the project file the CLI looks for. AltFileName is accepted too.
const (
	FileName    = "aidetector.yml"
	AltFileName = "aidetector.yaml"
)

// maxFileBytes bounds the read: a project file is a few dozen lines.
const maxFileBytes = 64 << 10

// Identity is one identity the file owns, matched to the scan's by name.
//
// Rank is sent as the credential's privilege, on the server's role-name scale:
// 0 is the least privileged (guest), 3 the most (admin), so explicit and
// inferred ranks compare. nil leaves it to the server, which infers it from the
// role name.
//
// Tenant names the workspace (organisation, account) the identity belongs to.
// With tenants set, object-level checks (BOLA) pair identities of different
// tenants and function-level checks (BFLA) pair identities within one; without
// them both pair by rank alone, which cannot tell two keys of one workspace
// from two workspaces.
type Identity struct {
	Name      string `yaml:"name"`
	Role      string `yaml:"role"`
	Auth      string `yaml:"auth"`
	Header    string `yaml:"header"`
	SecretEnv string `yaml:"secret_env"`
	Rank      *int   `yaml:"rank"`
	Tenant    string `yaml:"tenant"`
	Grant     *Grant `yaml:"grant"`
}

// Grant is how an identity mints the token it authenticates with. The secret
// named by secret_env is the grant's sensitive half (client_secret or
// password), never a token to send as-is.
type Grant struct {
	Type             string `yaml:"type"`
	TokenURL         string `yaml:"token_url"`
	ClientID         string `yaml:"client_id"`
	Username         string `yaml:"username"`
	Scope            string `yaml:"scope"`
	CookieName       string `yaml:"cookie_name"`
	UsernameField    string `yaml:"username_field"`
	PasswordField    string `yaml:"password_field"`
	Format           string `yaml:"format"`
	AccessTokenField string `yaml:"access_token_field"`
}

// Schema is the database whose schema a local run reads for schema-aware checks.
// Only a local run ever connects: the password is named here (password_env) and
// read on this machine, never stored on the server.
type Schema struct {
	Host        string   `yaml:"host"`
	Port        int      `yaml:"port"`
	Database    string   `yaml:"database"`
	Username    string   `yaml:"username"`
	PasswordEnv string   `yaml:"password_env"`
	SSLMode     string   `yaml:"sslmode"`
	SSLRootCert string   `yaml:"sslrootcert"`
	Tables      []string `yaml:"tables"`
}

// File is aidetector.yml as written. A zero value means "not set here".
type File struct {
	Target       string   `yaml:"target"`
	Scan         string   `yaml:"scan"`
	Spec         string   `yaml:"spec"`
	Source       string   `yaml:"source"`
	RPS          int      `yaml:"rps"`
	Level        string   `yaml:"level"`
	Checks       []string `yaml:"checks"`
	Passes       []string `yaml:"passes"`
	FailOn       string   `yaml:"fail_on"`
	VerifiedOnly bool     `yaml:"verified_only"`
	NewOnly      bool     `yaml:"new_only"`
	// Shorthands: the one thing a file says about auth without listing every
	// identity. Both expand to ordinary identities in ExpandIdentities.
	Auth        string     `yaml:"auth"`         // public: deliberately unauthenticated
	TokenEnv    string     `yaml:"token_env"`    // one identity named "default"
	TokenAuth   string     `yaml:"token_auth"`   // its auth type (default bearer)
	TokenHeader string     `yaml:"token_header"` // its header / parameter / cookie name
	Identities  []Identity `yaml:"identities"`
	Schema      *Schema    `yaml:"schema"`
}

// Loaded is a parsed file plus where it came from.
type Loaded struct {
	File
	Path   string // absolute
	Dir    string // the directory relative paths in the file resolve against
	Digest string // SHA-256 of the file's bytes, hex
}

// AuthTypes are the identity auth types the server accepts.
var AuthTypes = map[string]bool{
	"bearer": true, "header": true, "api_key": true, "basic": true,
	"query": true, "cookie": true, "none": true,
}

// authTypesList is the same set in the order errors name them.
const authTypesList = "bearer, header, api_key, basic, query, cookie, none"

// MaxRank is the top of the privilege scale (admin), shared with the server.
const MaxRank = 3

// GrantTypes are how an identity obtains the token it sends.
var GrantTypes = map[string]bool{"client_credentials": true, "password": true, "cookie": true}

var severities = map[string]bool{"info": true, "low": true, "medium": true, "high": true, "critical": true}

// levels are the server's run levels: how hard a run looks, before passes.
var levels = map[string]bool{"quick": true, "standard": true, "deep": true}

// Identifier rules: a PostgreSQL identifier is at most 63 bytes and the host
// is what a DSN accepts. A table may also be "*" (every table in its schema).
//
// headerNameRE is the RFC 7230 token: a header, query parameter or cookie name,
// never the value that goes in it.
var (
	identifierRE = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_$-]{0,62}$`)
	hostRE       = regexp.MustCompile(`^[A-Za-z0-9.:-]{1,253}$`)
	headerNameRE = regexp.MustCompile("^[!#$%&'*+.^_`|~0-9A-Za-z-]+$")
	envNameRE    = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)
)

// secretKeys are keys that would put a secret in a committed file.
var secretKeys = map[string]bool{
	"secret": true, "token": true, "password": true, "api_key": true, "apikey": true,
	"key": true, "bearer": true, "credential": true, "credentials": true,
}

// Find looks for the project file in dir. It returns nil, nil when there is none.
func Find(dir string) (*Loaded, error) {
	for _, name := range []string{FileName, AltFileName} {
		p := filepath.Join(dir, name)
		if info, err := os.Stat(p); err == nil && !info.IsDir() {
			return Load(p)
		}
	}
	return nil, nil
}

// Load reads and validates one project file.
func Load(path string) (*Loaded, error) {
	abs, err := filepath.Abs(path)
	if err != nil {
		return nil, err
	}
	f, err := os.Open(abs)
	if err != nil {
		return nil, fmt.Errorf("cannot read %s: %w", path, err)
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, maxFileBytes+1))
	if err != nil {
		return nil, fmt.Errorf("cannot read %s: %w", path, err)
	}
	file, err := Parse(data, filepath.Base(abs))
	if err != nil {
		return nil, err
	}
	sum := sha256.Sum256(data)
	return &Loaded{File: *file, Path: abs, Dir: filepath.Dir(abs), Digest: hex.EncodeToString(sum[:])}, nil
}

// Parse validates a project file's bytes without reading a path, so a draft
// can be checked before it is written. name prefixes every error.
func Parse(data []byte, name string) (*File, error) {
	if len(data) > maxFileBytes {
		return nil, fmt.Errorf("%s is larger than %d KiB; a project file is a few dozen lines",
			name, maxFileBytes>>10)
	}
	if err := refuseSecrets(data); err != nil {
		return nil, fmt.Errorf("%s: %w", name, err)
	}
	var file File
	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true) // a typo ("indentities:") must not silently do nothing
	// An empty file decodes to EOF: it sets nothing, which is valid.
	if err := dec.Decode(&file); err != nil && !errors.Is(err, io.EOF) {
		return nil, fmt.Errorf("%s: %w", name, err)
	}
	if err := file.validate(); err != nil {
		return nil, fmt.Errorf("%s: %w", name, err)
	}
	return &file, nil
}

// refuseSecrets walks the raw document for a key that would hold a secret, so
// the error says what to do instead of "field token not found".
func refuseSecrets(data []byte) error {
	var root yaml.Node
	if err := yaml.Unmarshal(data, &root); err != nil {
		return err
	}
	var walk func(n *yaml.Node) error
	walk = func(n *yaml.Node) error {
		if n.Kind == yaml.MappingNode {
			for i := 0; i+1 < len(n.Content); i += 2 {
				if secretKeys[strings.ToLower(n.Content[i].Value)] {
					return fmt.Errorf("line %d: %q would put a secret in a committed file — "+
						"name the environment variable that holds it with secret_env instead",
						n.Content[i].Line, n.Content[i].Value)
				}
				if err := walk(n.Content[i+1]); err != nil {
					return err
				}
			}
			return nil
		}
		for _, c := range n.Content {
			if err := walk(c); err != nil {
				return err
			}
		}
		return nil
	}
	return walk(&root)
}

func (f *File) validate() error {
	if f.FailOn != "" && !severities[strings.ToLower(f.FailOn)] {
		return fmt.Errorf("fail_on must be one of info, low, medium, high, critical")
	}
	if f.RPS != 0 && (f.RPS < 1 || f.RPS > 100) {
		return fmt.Errorf("rps must be between 1 and 100")
	}
	if f.Level != "" && !levels[f.Level] {
		return fmt.Errorf("level must be one of quick, standard, deep")
	}
	if (f.VerifiedOnly || f.NewOnly) && f.FailOn == "" {
		return fmt.Errorf("verified_only and new_only refine fail_on; set fail_on too")
	}
	if err := f.validateAuthShorthand(); err != nil {
		return err
	}
	seen := map[string]bool{}
	for i := range f.Identities {
		id := &f.Identities[i]
		if id.Name == "" || id.Role == "" {
			return fmt.Errorf("identities[%d]: name and role are required", i)
		}
		if seen[id.Name] {
			return fmt.Errorf("identities: %q is listed twice", id.Name)
		}
		seen[id.Name] = true
		if id.Auth == "" {
			id.Auth = "bearer"
		}
		if !AuthTypes[id.Auth] {
			return fmt.Errorf("identities[%s]: auth must be one of %s", id.Name, authTypesList)
		}
		if err := id.validate(); err != nil {
			return err
		}
	}
	if f.Schema != nil {
		if err := f.Schema.validate(); err != nil {
			return err
		}
	}
	return nil
}

// validateAuthShorthand checks auth: public and token_env: against identities:.
// They are alternatives: a file that describes one identity in two ways would
// otherwise apply an ambiguous identity set.
func (f *File) validateAuthShorthand() error {
	if f.Auth != "" {
		if f.Auth != "public" {
			return fmt.Errorf("auth must be public (the only top-level value: an API with no authentication)")
		}
		if len(f.Identities) > 0 {
			return fmt.Errorf("auth: public means the API takes no identity; remove identities:")
		}
	}
	if f.TokenEnv != "" {
		if f.Auth != "" {
			return fmt.Errorf("token_env cannot be combined with auth: public")
		}
		if len(f.Identities) > 0 {
			return fmt.Errorf("token_env cannot be combined with identities:; list the identity itself instead")
		}
		if !envNameRE.MatchString(f.TokenEnv) {
			return fmt.Errorf("token_env %q must be an environment variable name (letters, digits and '_')", f.TokenEnv)
		}
		if f.TokenAuth == "" {
			f.TokenAuth = "bearer"
		}
		if !AuthTypes[f.TokenAuth] {
			return fmt.Errorf("token_auth must be one of %s", authTypesList)
		}
		if f.TokenHeader != "" {
			if !headerNameRE.MatchString(f.TokenHeader) {
				return fmt.Errorf("token_header %q must be a token (letters, digits and !#$%%&'*+-.^_`|~), not a value", f.TokenHeader)
			}
		} else if f.TokenAuth == "query" || f.TokenAuth == "cookie" {
			return fmt.Errorf("token_header is required for token_auth %s (the query parameter / cookie name)", f.TokenAuth)
		}
	} else {
		if f.TokenAuth != "" {
			return fmt.Errorf("token_auth describes token_env; set token_env too")
		}
		if f.TokenHeader != "" {
			return fmt.Errorf("token_header describes token_env; set token_env too")
		}
	}
	return nil
}

// validate checks one identity past the name/role/auth basics.
func (id *Identity) validate() error {
	if id.Header != "" && !headerNameRE.MatchString(id.Header) {
		return fmt.Errorf("identities[%s]: header %q must be a name (letters, digits and "+
			"!#$%%&'*+-.^_`|~), not the value sent in it", id.Name, id.Header)
	}
	if (id.Auth == "query" || id.Auth == "cookie") && id.Header == "" {
		return fmt.Errorf("identities[%s]: header is required for auth %s (the query parameter / cookie name)",
			id.Name, id.Auth)
	}
	if len(id.Tenant) > 120 {
		return fmt.Errorf("identities[%s]: tenant must be at most 120 characters", id.Name)
	}
	if id.Rank != nil && (*id.Rank < 0 || *id.Rank > MaxRank) {
		return fmt.Errorf("identities[%s]: rank must be between 0 (guest) and %d (admin)", id.Name, MaxRank)
	}
	if id.Grant != nil {
		if id.Auth == "none" {
			return fmt.Errorf("identities[%s]: auth none cannot have a grant", id.Name)
		}
		if err := id.Grant.validate(id.Name); err != nil {
			return err
		}
	}
	if id.Auth != "none" && id.SecretEnv == "" {
		return fmt.Errorf("identities[%s]: secret_env is required (the environment variable "+
			"that holds the secret)", id.Name)
	}
	return nil
}

// validate checks one grant block. Every message starts with the identity it
// belongs to, so a rejected file says which grant is wrong.
func (g *Grant) validate(name string) error {
	if g.Type == "" {
		return fmt.Errorf("identities[%s]: grant.type is required (client_credentials, password or cookie)", name)
	}
	if !GrantTypes[g.Type] {
		return fmt.Errorf("identities[%s]: grant.type must be client_credentials, password or cookie", name)
	}
	if g.TokenURL == "" {
		return fmt.Errorf("identities[%s]: grant.token_url is required", name)
	}
	u, err := url.Parse(g.TokenURL)
	if err != nil || u.Host == "" || (u.Scheme != "http" && u.Scheme != "https") {
		return fmt.Errorf("identities[%s]: grant.token_url must be an http(s) URL", name)
	}
	if g.Format != "" && g.Format != "json" && g.Format != "form" {
		return fmt.Errorf("identities[%s]: grant.format must be json or form", name)
	}
	return nil
}

// ExpandIdentities is the one place the shorthands become ordinary identities,
// so everything downstream (validation, applyIdentities, the server's managed
// config) sees one shape. It is safe to call on a validated file.
func (f *File) ExpandIdentities() []Identity {
	if f.TokenEnv == "" {
		return f.Identities
	}
	auth := f.TokenAuth
	if auth == "" {
		auth = "bearer"
	}
	return []Identity{{
		Name: "default", Role: "user", Auth: auth,
		Header: f.TokenHeader, SecretEnv: f.TokenEnv,
	}}
}

// validate fills defaults and checks the schema block. Every message starts
// with "schema:" so a rejected file says which block is wrong.
func (s *Schema) validate() error {
	if s.Host == "" {
		return fmt.Errorf("schema: host is required")
	}
	if !hostRE.MatchString(s.Host) {
		return fmt.Errorf("schema: host %q must be a hostname or address (letters, digits, '.', ':' and '-')", s.Host)
	}
	if s.Port == 0 {
		s.Port = 5432
	}
	if s.Port < 1 || s.Port > 65535 {
		return fmt.Errorf("schema: port must be between 1 and 65535")
	}
	if s.Database == "" {
		return fmt.Errorf("schema: database is required")
	}
	if !identifierRE.MatchString(s.Database) {
		return fmt.Errorf("schema: database %q is not a valid identifier", s.Database)
	}
	if s.Username == "" {
		return fmt.Errorf("schema: username is required")
	}
	if !identifierRE.MatchString(s.Username) {
		return fmt.Errorf("schema: username %q is not a valid identifier", s.Username)
	}
	if s.PasswordEnv == "" {
		return fmt.Errorf("schema: password_env is required (the environment variable that holds the password)")
	}
	if s.SSLMode == "" {
		s.SSLMode = "verify-full"
	}
	if s.SSLMode != "verify-full" && s.SSLMode != "disable" {
		return fmt.Errorf("schema: sslmode must be verify-full or disable")
	}
	if s.SSLMode == "verify-full" && s.SSLRootCert == "" {
		return fmt.Errorf("schema: sslrootcert is required when sslmode is verify-full")
	}
	if len(s.Tables) == 0 || len(s.Tables) > 20 {
		return fmt.Errorf("schema: tables must list between 1 and 20 entries")
	}
	seen := map[string]bool{}
	wildcard := map[string]bool{}
	named := map[string]bool{}
	for i, entry := range s.Tables {
		parts := strings.Split(entry, ".")
		if len(parts) != 2 || !identifierRE.MatchString(parts[0]) {
			return fmt.Errorf("schema: tables[%d] %q must be schema.table or schema.*", i, entry)
		}
		sch, table := parts[0], parts[1]
		if lower := strings.ToLower(sch); lower == "information_schema" || strings.HasPrefix(lower, "pg_") {
			return fmt.Errorf("schema: tables[%d] names the system schema %q", i, sch)
		}
		if table != "*" && !identifierRE.MatchString(table) {
			return fmt.Errorf("schema: tables[%d] %q must be schema.table or schema.*", i, entry)
		}
		if seen[entry] {
			return fmt.Errorf("schema: table %q is listed twice", entry)
		}
		seen[entry] = true
		if table == "*" {
			wildcard[sch] = true
		} else {
			named[sch] = true
		}
		if wildcard[sch] && named[sch] {
			return fmt.Errorf("schema: schema %q is listed both as schema.* and as a named table", sch)
		}
	}
	return nil
}

// TableRefs is the tables block the runner reads: one {schema_name, table_name}
// per entry, with "*" for a whole schema.
func (s *Schema) TableRefs() []map[string]string {
	out := make([]map[string]string, 0, len(s.Tables))
	for _, entry := range s.Tables {
		parts := strings.SplitN(entry, ".", 2)
		if len(parts) != 2 {
			continue
		}
		out = append(out, map[string]string{"schema_name": parts[0], "table_name": parts[1]})
	}
	return out
}

// Fields lists the settings this file owns, in the server's vocabulary.
func (f *File) Fields() []string {
	var out []string
	if f.Target != "" {
		out = append(out, "target")
	}
	if f.Spec != "" {
		out = append(out, "spec")
	}
	if len(f.Identities) > 0 || f.TokenEnv != "" || f.Auth != "" {
		// The shorthands are identities too: token_env expands to one, and
		// auth: public says deliberately none. Either way the file owns them.
		out = append(out, "identities")
	}
	if f.RPS != 0 {
		out = append(out, "requests_per_second")
	}
	if len(f.Passes) > 0 || len(f.Checks) > 0 || f.Level != "" {
		out = append(out, "run_options")
	}
	// schema: is deliberately not a managed field: the web has no control to
	// lock (its panel is read-only), and an older server would refuse the name.
	return out
}

// IdentityNames lists the identities the file owns, shorthands expanded.
func (f *File) IdentityNames() []string {
	ids := f.ExpandIdentities()
	out := make([]string, 0, len(ids))
	for _, id := range ids {
		out = append(out, id.Name)
	}
	return out
}

// Resolve makes a path from the file absolute against the file's directory.
func (l *Loaded) Resolve(p string) string {
	if filepath.IsAbs(p) {
		return p
	}
	return filepath.Join(l.Dir, p)
}

// --- spec discovery ---------------------------------------------------------

var specNames = map[string]bool{
	"openapi.json": true, "openapi.yaml": true, "openapi.yml": true,
	"swagger.json": true, "swagger.yaml": true, "swagger.yml": true,
}

// skipDirs are trees that hold someone else's specs, or generated ones.
var skipDirs = map[string]bool{
	".git": true, "node_modules": true, "vendor": true, ".venv": true, "venv": true,
	"dist": true, "build": true, "target": true, ".next": true, "__pycache__": true,
}

// maxSpecDepth bounds the walk: specs live near the top of a repo, and a
// monorepo walk must not read the whole disk.
const maxSpecDepth = 3

// FindSpec returns the most likely spec file under dir: the shallowest file
// named openapi.* / swagger.* (or *.openapi.*), alphabetical on a tie. It
// returns "" when there is none.
func FindSpec(dir string) (string, error) {
	hits, err := FindSpecs(dir)
	if err != nil || len(hits) == 0 {
		return "", err
	}
	return hits[0], nil
}

// FindSpecs returns every spec file FindSpec considers, most likely first.
func FindSpecs(dir string) ([]string, error) {
	type hit struct {
		path  string
		depth int
	}
	var hits []hit
	root := filepath.Clean(dir)
	err := filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil // unreadable corners are skipped, not fatal
		}
		rel, _ := filepath.Rel(root, p)
		depth := 0
		if rel != "." {
			depth = strings.Count(rel, string(filepath.Separator)) + 1
		}
		if d.IsDir() {
			if p != root && (skipDirs[d.Name()] || depth > maxSpecDepth) {
				return filepath.SkipDir
			}
			return nil
		}
		if d.Type()&fs.ModeSymlink != 0 {
			return nil
		}
		if isSpecName(d.Name()) {
			hits = append(hits, hit{p, depth})
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	sort.Slice(hits, func(i, j int) bool {
		if hits[i].depth != hits[j].depth {
			return hits[i].depth < hits[j].depth
		}
		return hits[i].path < hits[j].path
	})
	out := make([]string, len(hits))
	for i, h := range hits {
		out[i] = h.path
	}
	return out, nil
}

func isSpecName(name string) bool {
	lower := strings.ToLower(name)
	if specNames[lower] {
		return true
	}
	for _, ext := range []string{".json", ".yaml", ".yml"} {
		if strings.HasSuffix(lower, ".openapi"+ext) {
			return true
		}
	}
	return false
}
