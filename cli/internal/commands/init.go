package commands

import (
	"context"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"gopkg.in/yaml.v3"

	"aidetector/cli/internal/api"
	"aidetector/cli/internal/config"
	"aidetector/cli/internal/project"
)

// initSpecNames are the spec files `init` looks for in the project directory,
// in the order it tries them. It never asks the target for one.
var initSpecNames = []string{"openapi.yaml", "openapi.yml", "openapi.json", "swagger.yaml", "swagger.json"}

// initFile is the document `init` writes. Its keys are a deliberate subset of
// project.File: omitempty keeps the generated file short.
type initFile struct {
	Target      string         `yaml:"target,omitempty"`
	Spec        string         `yaml:"spec,omitempty"`
	Auth        string         `yaml:"auth,omitempty"`
	TokenEnv    string         `yaml:"token_env,omitempty"`
	TokenAuth   string         `yaml:"token_auth,omitempty"`
	TokenHeader string         `yaml:"token_header,omitempty"`
	Identities  []initIdentity `yaml:"identities,omitempty"`
}

type initIdentity struct {
	Name      string     `yaml:"name"`
	Role      string     `yaml:"role"`
	Rank      *int       `yaml:"rank,omitempty"`
	Auth      string     `yaml:"auth,omitempty"`
	Header    string     `yaml:"header,omitempty"`
	SecretEnv string     `yaml:"secret_env"`
	Grant     *initGrant `yaml:"grant,omitempty"`
}

type initGrant struct {
	Type     string `yaml:"type"`
	TokenURL string `yaml:"token_url"`
	ClientID string `yaml:"client_id,omitempty"`
	Username string `yaml:"username,omitempty"`
	Scope    string `yaml:"scope,omitempty"`
}

// grantPlaceholder marks a non-secret grant value init cannot know. It is
// written so the file loads, and named so the user sees what to fill in.
const grantPlaceholder = "CHANGE-ME"

// cmdInit writes an aidetector.yml that fits the API. It finds a spec on this
// machine (never by calling the target), asks the server what the spec says
// about authentication, and turns that into one of the three shorthands. It
// only ever writes environment variable names, never a secret.
func cmdInit(ctx context.Context, e *Env, args []string) int {
	fs := e.newFlagSet("init")
	specFlag := fs.String("spec", "", "OpenAPI/Swagger file to read auth hints from")
	force := fs.Bool("force", false, "overwrite an existing aidetector.yml")
	yes := fs.Bool("yes", false, "take the suggested answers without prompting")
	pos, err := parse(fs, args)
	if err != nil {
		return e.parseFailed("init", fs, err)
	}
	if len(pos) > 1 {
		return e.usage("init takes at most one target URL")
	}
	wd, err := e.workdir()
	if err != nil {
		return e.usage("%v", err)
	}
	if !*force {
		for _, name := range []string{project.FileName, project.AltFileName} {
			if _, err := os.Stat(filepath.Join(wd, name)); err == nil {
				return e.usage("%s already exists; pass --force to overwrite it", name)
			}
		}
	}

	target := ""
	if len(pos) == 1 {
		if target, err = project.NormalizeTarget(pos[0]); err != nil {
			return e.usage("%v", err)
		}
	}

	// A spec is read here, so init never sends a request to the target.
	specPath := *specFlag
	if specPath == "" {
		for _, name := range initSpecNames {
			if info, err := os.Stat(filepath.Join(wd, name)); err == nil && !info.IsDir() {
				specPath = name
				break
			}
		}
	}
	var specText string
	if specPath != "" {
		data, err := os.ReadFile(resolveIn(wd, specPath))
		if err != nil {
			return e.usage("cannot read spec %s: %v", specPath, err)
		}
		specText = string(data)
	}

	// What the server makes of the spec, when both a spec and a login exist.
	var hints api.AuthHints
	if specText != "" {
		if h, ok := fetchAuthHints(ctx, e, specText); ok {
			hints = h
		}
	}
	kind := "roles"
	if hints.Suggested != "" {
		kind = hints.Suggested
	}
	if kind != "public" && kind != "single" && kind != "roles" {
		kind = "roles"
	}
	interactive := e.IsTTY() && !*yes
	if interactive {
		e.errorf("What kind of API is this? [public/single/roles] (default: %s): ", kind)
		line, _ := e.readLine()
		switch strings.ToLower(strings.TrimSpace(line)) {
		case "":
		case "public", "single", "roles":
			kind = strings.ToLower(strings.TrimSpace(line))
		default:
			return e.usage("%q is not one of public, single or roles", strings.TrimSpace(line))
		}
	}

	cfg := draftInitFile(e, kind, target, specPath, hints, interactive)
	data, err := yaml.Marshal(cfg)
	if err != nil {
		return e.usage("cannot render %s: %v", project.FileName, err)
	}
	content := append([]byte(initHeader), data...)

	// Prove the document loads before it can be committed.
	tmp, err := os.CreateTemp(wd, ".aidetector-init-*.yml")
	if err != nil {
		return e.usage("cannot write %s: %v", project.FileName, err)
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)
	if _, err := tmp.Write(content); err != nil {
		tmp.Close()
		return e.usage("cannot write %s: %v", project.FileName, err)
	}
	if err := tmp.Close(); err != nil {
		return e.usage("cannot write %s: %v", project.FileName, err)
	}
	if _, err := project.Load(tmpName); err != nil {
		return e.usage("the generated %s would not load: %v", project.FileName, err)
	}
	if err := os.WriteFile(filepath.Join(wd, project.FileName), content, 0o644); err != nil {
		return e.usage("cannot write %s: %v", project.FileName, err)
	}
	e.printf("wrote %s\n", project.FileName)
	if strings.Contains(string(data), grantPlaceholder) {
		e.errorf("edit %s: replace %s with the grant's client_id / username\n",
			project.FileName, grantPlaceholder)
	}

	envs := identityEnvNames(cfg)
	if len(envs) == 0 {
		e.errorf("this API takes no credentials: nothing to export\n")
		return ExitOK
	}
	e.errorf("set these environment variables before running aidetector:\n")
	for _, name := range envs {
		e.errorf("  export %s=...\n", name)
	}
	return ExitOK
}

// draftInitFile is the file init writes for one kind of API (public, single
// or roles), shared with the MCP server's suggest_config so an agent's draft
// and init's file never differ.
func draftInitFile(e *Env, kind, target, specPath string, hints api.AuthHints, interactive bool) initFile {
	cfg := initFile{Target: target, Spec: specPath}
	switch kind {
	case "public":
		cfg.Auth = "public"
	case "single":
		cfg.TokenEnv = "AIDETECTOR_TOKEN"
		cfg.TokenAuth, cfg.TokenHeader = singleTokenShape(hints)
	case "roles":
		cfg.Identities = roleIdentities(e, hints, interactive)
	}
	return cfg
}

// initHeader is the comment at the top of a generated project file.
const initHeader = "# aidetector.yml — written by `aidetector init`.\n" +
	"# Commit this file: it names environment variables, never secrets.\n"

// resolveIn makes p absolute against dir when it is relative.
func resolveIn(dir, p string) string {
	if filepath.IsAbs(p) {
		return p
	}
	return filepath.Join(dir, p)
}

// fetchAuthHints asks the server what the spec says about authentication. It
// is advisory: an unconfigured login or any server error means init continues
// with the defaults, after one line saying why.
func fetchAuthHints(ctx context.Context, e *Env, specText string) (api.AuthHints, bool) {
	hints, why, ok := lookupAuthHints(ctx, e, specText)
	if !ok {
		if why != errNotLoggedIn && why != errNoAPIKey {
			// No server and key saved: nothing to ask, and nothing to explain.
			e.errorf("auth hints unavailable: %s\n", why)
		}
		return api.AuthHints{}, false
	}
	if hints.Reason != "" {
		e.errorf("auth hints: %s\n", hints.Reason)
	}
	return hints, true
}

// lookupAuthHints' reasons when it does not ask: no server saved, or a server
// saved without a key (a dev server with auth off answers hints only to a key).
const (
	errNotLoggedIn = "not logged in — run `aidetector login`"
	errNoAPIKey    = "logged in without an API key; auth hints need one — run `aidetector login` with a key"
)

// lookupAuthHints is fetchAuthHints without the printing: on failure it says
// why, so a caller with no terminal (the MCP server) can report it.
func lookupAuthHints(ctx context.Context, e *Env, specText string) (api.AuthHints, string, bool) {
	path, err := e.configPath()
	if err != nil {
		return api.AuthHints{}, errNotLoggedIn, false
	}
	cfg, err := config.Load(path, e.Getenv)
	if err != nil || cfg.Server == "" {
		return api.AuthHints{}, errNotLoggedIn, false
	}
	if cfg.APIKey == "" {
		return api.AuthHints{}, errNoAPIKey, false
	}
	c, err := e.client()
	if err != nil {
		return api.AuthHints{}, err.Error(), false
	}
	hints, err := c.AuthHints(ctx, specText)
	if err != nil {
		return api.AuthHints{}, err.Error(), false
	}
	return hints, "", true
}

// singleTokenShape picks token_auth / token_header from the first scheme. A
// bearer token is the default, so it is not written.
func singleTokenShape(hints api.AuthHints) (string, string) {
	if len(hints.Schemes) == 0 {
		return "", ""
	}
	s := hints.Schemes[0]
	if s.AuthType == "" || s.AuthType == "bearer" {
		return "", ""
	}
	if s.AuthType == "query" || s.AuthType == "cookie" ||
		s.AuthType == "header" || s.AuthType == "api_key" {
		if s.HeaderName == nil || *s.HeaderName == "" {
			return "", ""
		}
		return s.AuthType, *s.HeaderName
	}
	return s.AuthType, ""
}

// roleIdentities builds the roles branch: one identity per hinted role, or the
// classic user/admin pair. Interactive runs then let the user add more.
func roleIdentities(e *Env, hints api.AuthHints, interactive bool) []initIdentity {
	grant := grantFromHints(hints)
	// Every identity is sent the way the spec says, unless a grant mints it a
	// bearer token instead.
	auth, header := "", ""
	if grant == nil {
		auth, header = singleTokenShape(hints)
	}
	identity := func(name, role string, rank int) initIdentity {
		id := initIdentity{
			Name: name, Role: role, Rank: &rank, Auth: auth, Header: header,
			SecretEnv: secretEnvFor(name),
		}
		if grant != nil {
			g := *grant // each identity edits its own client_id / username
			id.Grant = &g
		}
		return id
	}
	var out []initIdentity
	for _, r := range hints.Roles {
		out = append(out, identity(r.Name, r.Name, r.Privilege))
	}
	if len(out) == 0 {
		out = append(out, identity("user", "user", 1), identity("admin", "admin", 3))
	}
	if !interactive {
		return out
	}
	seen := map[string]bool{}
	for _, id := range out {
		seen[id.Name] = true
	}
	for len(out) < 20 {
		e.errorf("Identity name (empty to finish): ")
		name, _ := e.readLine()
		if name = strings.TrimSpace(name); name == "" {
			break
		}
		if seen[name] {
			e.errorf("identity %q is already listed\n", name)
			continue
		}
		e.errorf("Role for %s (e.g. user, admin) [user]: ", name)
		role, _ := e.readLine()
		if role = strings.TrimSpace(role); role == "" {
			role = "user"
		}
		rank := defaultRank(role)
		e.errorf("Privilege for %s (0 lowest … 3 highest) [%d]: ", name, rank)
		if p, _ := e.readLine(); strings.TrimSpace(p) != "" {
			n, err := strconv.Atoi(strings.TrimSpace(p))
			if err != nil || n < 0 || n > project.MaxRank {
				e.errorf("privilege must be a number from 0 to %d; %s skipped\n", project.MaxRank, name)
				continue
			}
			rank = n
		}
		seen[name] = true
		out = append(out, identity(name, role, rank))
	}
	return out
}

// grantFromHints adds a token-minting grant when the spec's oauth2 scheme
// mints tokens itself.
func grantFromHints(hints api.AuthHints) *initGrant {
	for _, s := range hints.Schemes {
		if s.Kind != "oauth2" {
			continue
		}
		if s.GrantType != "client_credentials" && s.GrantType != "password" {
			continue
		}
		if s.TokenURL == nil || *s.TokenURL == "" {
			continue
		}
		g := &initGrant{
			Type: s.GrantType, TokenURL: *s.TokenURL,
			Scope: strings.Join(s.Scopes, " "),
		}
		// Minting needs the non-secret half too; the spec never holds it.
		if s.GrantType == "client_credentials" {
			g.ClientID = grantPlaceholder
		} else {
			g.Username = grantPlaceholder
		}
		return g
	}
	return nil
}

// secretEnvFor names the environment variable an identity's secret lives in.
func secretEnvFor(name string) string {
	var b strings.Builder
	for _, r := range strings.ToUpper(name) {
		if (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') {
			b.WriteRune(r)
		} else {
			b.WriteByte('_')
		}
	}
	return "AIDETECTOR_" + b.String() + "_TOKEN"
}

// identityEnvNames lists what the generated file expects in the environment.
func identityEnvNames(cfg initFile) []string {
	if cfg.TokenEnv != "" {
		return []string{cfg.TokenEnv}
	}
	out := make([]string, 0, len(cfg.Identities))
	for _, id := range cfg.Identities {
		out = append(out, id.SecretEnv)
	}
	return out
}

// defaultRank mirrors the server's inference for a role name
// (ROLE_RANKS in services/api/app/domain/privilege.py): higher means more
// privileged. It is only the prompt's default; the file records the answer.
func defaultRank(role string) int {
	switch strings.ToLower(strings.TrimSpace(role)) {
	case "admin", "administrator", "superuser", "root", "superadmin":
		return 3
	case "editor", "manager", "staff", "support", "moderator", "operator":
		return 2
	case "user", "member", "customer":
		return 1
	case "guest", "anonymous", "viewer", "readonly", "read_only", "read-only", "reader":
		return 0
	}
	return 1
}
