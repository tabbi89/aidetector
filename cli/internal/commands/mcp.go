package commands

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"

	"runpentests/cli/docs"
	"runpentests/cli/internal/api"
	"runpentests/cli/internal/config"
	"runpentests/cli/internal/mcp"
	"runpentests/cli/internal/project"
)

// The MCP server helps a coding agent set runpentests up for a project: it
// serves the guides, finds the spec, drafts and validates runpentests.yml, and
// says what the person should run next. It deliberately cannot start a scan —
// the authorization gate is one explicit act by a person, and an agent's tool
// call is not one — and it never takes, reads or returns a secret value.
//
// Every path an agent passes is confined to the directory the server started
// in, because suggest_config sends a file's text to the runpentests server.

// mcpGuides are the docs served as resources, in the order they are listed.
var mcpGuides = []struct{ file, title, description string }{
	{"setup.md", "Setting up runpentests for a project",
		"Start here: the steps from a repository to a validated runpentests.yml and the commands to hand over."},
	{"project-file.md", "runpentests.yml reference",
		"Every key in the project file, the three ways to describe authentication, and what the file can never hold."},
	{"levels-and-passes.md", "Levels and passes",
		"What quick, standard and deep do, and what each opt-in pass costs the target or in tokens."},
	{"local-runs.md", "Local runs",
		"Sending the scan from this machine: internal hosts, localhost, and reading the code."},
	{"distribution.md", "Installing and distributing runpentests",
		"Public CLI archives, the matching runner image, and the bundled MCP helper."},
	{"ci-gate.md", "CI gate",
		"Failing a pipeline on findings: flags, output formats and exit codes."},
	{"safety.md", "Safety rules",
		"The authorization gate, domain verification, opt-in writes and secret handling."},
}

func guideURI(file string) string {
	return "runpentests://docs/" + strings.TrimSuffix(file, ".md")
}

const mcpInstructions = "This server helps you set up runpentests, an active API security scanner, " +
	"for the project in the current directory. Read runpentests://docs/setup first. " +
	"Use find_spec, suggest_config and validate_config to produce a valid runpentests.yml, " +
	"then next_steps for the commands the person runs. You cannot start a scan from here: " +
	"the person running it must confirm they are authorized to test the target. " +
	"Never put a secret value in runpentests.yml, a command or your reply — only environment variable names."

func cmdMCP(ctx context.Context, e *Env, args []string) int {
	fs := e.newFlagSet("mcp")
	if _, err := parse(fs, args); err != nil {
		return e.parseFailed("mcp", fs, err)
	}
	root, err := e.workdir()
	if err != nil {
		return e.usage("%v", err)
	}
	srv, err := newMCPServer(e, root)
	if err != nil {
		return e.usage("%v", err)
	}
	if err := srv.Serve(ctx, e.Stdin, e.Stdout); err != nil {
		e.errorf("error: %v\n", err)
		return ExitFailed
	}
	return ExitOK
}

func newMCPServer(e *Env, root string) (*mcp.Server, error) {
	root, err := filepath.Abs(root)
	if err != nil {
		return nil, err
	}
	if real, err := filepath.EvalSymlinks(root); err == nil {
		root = real
	}
	t := &mcpTools{e: e, root: root}
	srv := &mcp.Server{
		Name:         "runpentests",
		Version:      Version,
		Instructions: mcpInstructions,
	}
	for _, g := range mcpGuides {
		data, err := docs.FS.ReadFile(g.file)
		if err != nil {
			return nil, fmt.Errorf("guide %s is missing from this build: %w", g.file, err)
		}
		srv.Resources = append(srv.Resources, mcp.Resource{
			URI: guideURI(g.file), Name: strings.TrimSuffix(g.file, ".md"), Title: g.title,
			Description: g.description, MimeType: "text/markdown", Text: string(data),
		})
	}
	setup, _ := docs.FS.ReadFile("setup.md")
	srv.Prompts = []mcp.Prompt{{
		Name:        "setup_runpentests",
		Title:       "Set up runpentests for this project",
		Description: "Walk through preparing runpentests.yml for this repository, ending with the commands to run.",
		Arguments: []mcp.PromptArgument{{
			Name: "target", Description: "the API's base URL, if you already know it",
		}},
		Render: func(args map[string]string) (string, error) {
			var b strings.Builder
			b.WriteString("Set up runpentests for the project in the current directory, following this guide. ")
			b.WriteString("Use the runpentests MCP tools for each step, and finish with next_steps.\n\n")
			if target := strings.TrimSpace(args["target"]); target != "" {
				fmt.Fprintf(&b, "The target is %s.\n\n", target)
			}
			b.Write(setup)
			return b.String(), nil
		},
	}}
	srv.Tools = t.tools()
	return srv, nil
}

type mcpTools struct {
	e    *Env
	root string // absolute, symlinks resolved
}

func (t *mcpTools) tools() []mcp.Tool {
	str := func(desc string) map[string]any { return map[string]any{"type": "string", "description": desc} }
	object := func(props map[string]any) map[string]any {
		return map[string]any{"type": "object", "properties": props, "additionalProperties": false}
	}
	return []mcp.Tool{
		{
			Name:  "find_spec",
			Title: "Find the API spec",
			Description: "List the OpenAPI / Swagger files in the project, most likely first " +
				"(the one runpentests would pick on its own leads). Vendored and build trees are skipped.",
			InputSchema: object(map[string]any{
				"dir": str("directory to search, relative to the project root (default: the root)"),
			}),
			ReadOnly: true,
			Call:     t.findSpec,
		},
		{
			Name:  "suggest_config",
			Title: "Draft runpentests.yml",
			Description: "Draft a runpentests.yml in exactly the shape `runpentests init` writes. " +
				"kind is public (no auth), single (one key) or roles (one identity per role); without it " +
				"the runpentests server's reading of the spec's securitySchemes decides, when logged in. " +
				"Sends the spec's text to the configured runpentests server, never to the target. " +
				"Returns the draft; it writes nothing.",
			InputSchema: object(map[string]any{
				"spec":   str("spec file, relative to the project root (default: what find_spec would pick)"),
				"target": str("the API's base URL"),
				"kind": map[string]any{
					"type": "string", "enum": []string{"public", "single", "roles"},
					"description": "how the API authenticates, if you have worked it out from the code",
				},
				"tenants": map[string]any{
					"type":        "boolean",
					"description": "roles only: the API is multi-tenant, so draft identities in two tenants (BOLA across them, BFLA within one)",
				},
			}),
			ReadOnly:  true,
			OpenWorld: true,
			Call:      t.suggestConfig,
		},
		{
			Name:  "validate_config",
			Title: "Validate runpentests.yml",
			Description: "Check a runpentests.yml with the CLI's own loader: the exact error if it " +
				"would be refused, otherwise a summary and warnings (missing spec file, too few " +
				"identities for the authorization checks, passes that write or spend tokens). Pass " +
				"content to check a draft before writing it; without content it checks the file on disk.",
			InputSchema: object(map[string]any{
				"content": str("the YAML text to check"),
				"path":    str("file to check, relative to the project root (default: runpentests.yml)"),
			}),
			ReadOnly: true,
			Call:     t.validateConfig,
		},
		{
			Name:  "server_status",
			Title: "runpentests server status",
			Description: "Whether this machine is logged in to a runpentests server (never the key), " +
				"and which passes that server can run.",
			InputSchema: object(map[string]any{}),
			ReadOnly:    true,
			OpenWorld:   true,
			Call:        t.serverStatus,
		},
		{
			Name:  "next_steps",
			Title: "Commands to hand over",
			Description: "The commands the person should run, in order, from the project's " +
				"runpentests.yml: logging in, the environment variables to export (names only) and " +
				"the scan. Give these to the person; do not run the scan yourself.",
			InputSchema: object(map[string]any{
				"path": str("project file, relative to the project root (default: runpentests.yml)"),
			}),
			ReadOnly: true,
			Call:     t.nextSteps,
		},
	}
}

// resolve turns an agent-supplied path into an absolute one inside the root,
// following symlinks, or refuses it.
func (t *mcpTools) resolve(p string) (string, error) {
	if p == "" {
		return t.root, nil
	}
	abs := p
	if !filepath.IsAbs(abs) {
		abs = filepath.Join(t.root, p)
	}
	abs = filepath.Clean(abs)
	real, err := filepath.EvalSymlinks(abs)
	if err != nil {
		if !errors.Is(err, os.ErrNotExist) {
			return "", err
		}
		real = abs // a file not written yet: judge the path as given
		if dir, derr := filepath.EvalSymlinks(filepath.Dir(abs)); derr == nil {
			real = filepath.Join(dir, filepath.Base(abs))
		}
	}
	if !t.inside(real) {
		return "", fmt.Errorf("%s is outside the project (%s); this server only reads inside it", p, t.root)
	}
	return real, nil
}

func (t *mcpTools) inside(p string) bool {
	rel, err := filepath.Rel(t.root, p)
	return err == nil && rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator)) && !filepath.IsAbs(rel)
}

func (t *mcpTools) rel(p string) string {
	if rel, err := filepath.Rel(t.root, p); err == nil {
		return filepath.ToSlash(rel)
	}
	return p
}

func decodeArgs(raw json.RawMessage, v any) error {
	dec := json.NewDecoder(strings.NewReader(string(raw)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		return fmt.Errorf("bad arguments: %v", err)
	}
	return nil
}

func (t *mcpTools) findSpec(_ context.Context, raw json.RawMessage) (any, error) {
	var args struct {
		Dir string `json:"dir"`
	}
	if err := decodeArgs(raw, &args); err != nil {
		return nil, err
	}
	dir, err := t.resolve(args.Dir)
	if err != nil {
		return nil, err
	}
	hits, err := project.FindSpecs(dir)
	if err != nil {
		return nil, err
	}
	out := map[string]any{"candidates": []string{}}
	if len(hits) == 0 {
		out["note"] = "no openapi.* / swagger.* / *.openapi.* file within three levels. " +
			"Leave spec: out to let runpentests fetch the target's own /openapi.json at run time, " +
			"or use a Postman collection or HAR capture as the spec."
		return out, nil
	}
	const maxCandidates = 20
	candidates := make([]string, 0, len(hits))
	for i, h := range hits {
		if i == maxCandidates {
			break
		}
		candidates = append(candidates, t.rel(h))
	}
	out["candidates"] = candidates
	out["suggested"] = candidates[0]
	return out, nil
}

// mcpDraftHeader heads a suggest_config draft. It is not initHeader: an agent,
// not `runpentests init`, writes this file.
const mcpDraftHeader = "# runpentests.yml — see `runpentests help init` and the project-file guide.\n" +
	"# Commit this file: it names environment variables, never secrets.\n"

func (t *mcpTools) suggestConfig(ctx context.Context, raw json.RawMessage) (any, error) {
	var args struct {
		Spec    string `json:"spec"`
		Target  string `json:"target"`
		Kind    string `json:"kind"`
		Tenants bool   `json:"tenants"`
	}
	if err := decodeArgs(raw, &args); err != nil {
		return nil, err
	}
	if args.Kind != "" && args.Kind != "public" && args.Kind != "single" && args.Kind != "roles" {
		return nil, fmt.Errorf("kind must be public, single or roles")
	}
	target := ""
	if args.Target != "" {
		var err error
		if target, err = project.NormalizeTarget(args.Target); err != nil {
			return nil, err
		}
	}
	specPath := ""
	if args.Spec != "" {
		p, err := t.resolve(args.Spec)
		if err != nil {
			return nil, err
		}
		specPath = p
	} else if p, err := project.FindSpec(t.root); err == nil && p != "" {
		specPath = p
	}

	out := map[string]any{}
	var notes []string
	var hints api.AuthHints
	haveHints := false
	if specPath != "" {
		text, err := readBounded(specPath, maxSpecBytes)
		if err != nil {
			return nil, err
		}
		out["spec"] = t.rel(specPath)
		h, why, ok := lookupAuthHints(ctx, t.e, text)
		if ok {
			hints, haveHints = h, true
			out["server_hints"] = h
		} else {
			out["server_hints_unavailable"] = why
			notes = append(notes, "Without the server's hints, read securitySchemes and the auth code yourself to choose kind.")
		}
	} else {
		notes = append(notes, "No spec file found: the draft leaves spec: out, so runpentests fetches the target's own spec at run time.")
	}

	kind, source := args.Kind, "argument"
	if kind == "" {
		kind, source = "roles", "default"
		if haveHints && (hints.Suggested == "public" || hints.Suggested == "single" || hints.Suggested == "roles") {
			kind, source = hints.Suggested, "server hints"
		}
	}
	specRel := ""
	if specPath != "" {
		specRel = t.rel(specPath)
	}
	if args.Tenants && kind != "roles" {
		return nil, fmt.Errorf("tenants needs kind roles")
	}
	cfg := draftInitFile(t.e, kind, target, specRel, hints, false, args.Tenants)
	data, err := yaml.Marshal(cfg)
	if err != nil {
		return nil, err
	}
	out["kind"] = kind
	out["kind_source"] = source
	out["draft"] = mcpDraftHeader + string(data)
	out["env"] = identityEnvNames(cfg)
	if strings.Contains(string(data), grantPlaceholder) {
		notes = append(notes, "Replace "+grantPlaceholder+" with the grant's client_id / username from the code or ask the person.")
	}
	if kind == "roles" && len(hints.Roles) == 0 {
		notes = append(notes, "The identities are a generic user/admin pair: rename them to the API's real roles.")
	}
	if target == "" {
		notes = append(notes, "No target: add target: with the staging base URL, or the person passes it on the command line.")
	}
	out["notes"] = append(notes, "Check the edited draft with validate_config before writing it.")
	return out, nil
}

// readBounded reads a file the agent named, refusing one larger than limit.
func readBounded(path string, limit int64) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, limit+1))
	if err != nil {
		return "", err
	}
	if int64(len(data)) > limit {
		return "", fmt.Errorf("%s is larger than %d MiB", filepath.Base(path), limit>>20)
	}
	return string(data), nil
}

// configSummary is what validate_config reports about a file that loads. It
// holds names and shapes only: an identity's secret is an env var name.
type configSummary struct {
	Target     string            `json:"target,omitempty"`
	Spec       string            `json:"spec,omitempty"`
	SpecFound  *bool             `json:"spec_found,omitempty"`
	Level      string            `json:"level,omitempty"`
	Passes     []string          `json:"passes,omitempty"`
	Checks     []string          `json:"checks,omitempty"`
	FailOn     string            `json:"fail_on,omitempty"`
	Auth       string            `json:"auth"`
	Identities []identitySummary `json:"identities"`
	Env        []string          `json:"env"`
}

type identitySummary struct {
	Name      string `json:"name"`
	Role      string `json:"role"`
	Rank      *int   `json:"rank,omitempty"`
	Auth      string `json:"auth"`
	Header    string `json:"header,omitempty"`
	SecretEnv string `json:"secret_env,omitempty"`
	Grant     string `json:"grant,omitempty"`
}

func (t *mcpTools) validateConfig(_ context.Context, raw json.RawMessage) (any, error) {
	var args struct {
		Content *string `json:"content"`
		Path    string  `json:"path"`
	}
	if err := decodeArgs(raw, &args); err != nil {
		return nil, err
	}
	file, dir, err := t.loadProject(args.Content, args.Path)
	if err != nil {
		return map[string]any{"valid": false, "error": err.Error()}, nil
	}
	summary, warnings := t.summarize(file, dir)
	return map[string]any{"valid": true, "summary": summary, "warnings": warnings}, nil
}

// loadProject parses the draft text, or reads the project file (path, else
// runpentests.yml / runpentests.yaml at the root). dir is what the file's
// relative paths resolve against.
func (t *mcpTools) loadProject(content *string, path string) (*project.File, string, error) {
	if content != nil {
		f, err := project.Parse([]byte(*content), project.FileName)
		return f, t.root, err
	}
	if path == "" {
		for _, name := range project.FileNames {
			if _, err := os.Stat(filepath.Join(t.root, name)); err == nil {
				path = name
				break
			}
		}
		if path == "" {
			return nil, "", fmt.Errorf("no %s in %s yet; pass content to check a draft", project.FileName, t.root)
		}
	}
	p, err := t.resolve(path)
	if err != nil {
		return nil, "", err
	}
	loaded, err := project.Load(p)
	if err != nil {
		return nil, "", err
	}
	return &loaded.File, loaded.Dir, nil
}

func (t *mcpTools) summarize(f *project.File, dir string) (configSummary, []string) {
	s := configSummary{
		Target: f.Target, Spec: f.Spec, Level: f.Level, Passes: f.Passes, Checks: f.Checks,
		FailOn: f.FailOn, Identities: []identitySummary{}, Env: []string{},
	}
	// The same decision as the target form: a source or local: true makes a
	// run local, and so does a loopback target unless local: false says not.
	warnings := []string{}
	if f.Spec != "" {
		p := f.Spec
		if !filepath.IsAbs(p) {
			p = filepath.Join(dir, p)
		}
		// Only inside the project: an existence check is still a read.
		if real, err := t.resolve(p); err != nil {
			warnings = append(warnings, fmt.Sprintf("spec %s is outside the project", f.Spec))
		} else {
			_, err := os.Stat(real)
			found := err == nil
			s.SpecFound = &found
			if !found {
				warnings = append(warnings, fmt.Sprintf("spec %s does not exist (relative to the project file)", f.Spec))
			}
		}
	}
	if f.Target == "" {
		warnings = append(warnings, "no target: the person must pass the URL (`runpentests URL`)")
	}
	ids := f.ExpandIdentities()
	switch {
	case f.Auth == "public":
		s.Auth = "public"
	case f.TokenEnv != "":
		s.Auth = "single"
	case len(ids) > 0:
		s.Auth = "identities"
	default:
		s.Auth = "unset"
		warnings = append(warnings, "no auth: public, token_env or identities: the scan will prompt for "+
			"identities in a terminal, or skip the authorization checks without one")
	}
	for _, id := range ids {
		is := identitySummary{
			Name: id.Name, Role: id.Role, Rank: id.Rank, Auth: id.Auth,
			Header: id.Header, SecretEnv: id.SecretEnv,
		}
		if id.Grant != nil {
			is.Grant = id.Grant.Type
			if id.Grant.ClientID == grantPlaceholder || id.Grant.Username == grantPlaceholder {
				warnings = append(warnings, fmt.Sprintf("identities[%s]: replace %s in the grant", id.Name, grantPlaceholder))
			}
		}
		s.Identities = append(s.Identities, is)
		if id.SecretEnv != "" {
			s.Env = append(s.Env, id.SecretEnv)
		}
	}
	if len(ids) == 1 {
		warnings = append(warnings, "one identity: BOLA and BFLA need two (a user and an admin, or two "+
			"accounts in different tenants) and are skipped with one")
	}
	if f.Schema != nil && f.Schema.PasswordEnv != "" {
		s.Env = append(s.Env, f.Schema.PasswordEnv)
	}
	for _, p := range f.Passes {
		name := strings.ReplaceAll(strings.ToLower(p), "_", "-")
		field, _ := passField(name)
		switch {
		case field == "mutate":
			warnings = append(warnings, "passes includes "+p+": the scan will change target data. "+
				"Keep it only if the person asked for it")
		case strings.HasPrefix(PassHelp[name], "AI"):
			warnings = append(warnings, "passes includes "+p+": it spends AI tokens on every run")
		}
	}
	if f.Level == "deep" {
		warnings = append(warnings, "level deep runs ZAP, Kali and the confirm tools: slow, with far more "+
			"traffic than the request budget")
	}
	return s, warnings
}

func (t *mcpTools) serverStatus(ctx context.Context, _ json.RawMessage) (any, error) {
	out := map[string]any{"cli_version": Version}
	path, err := t.e.configPath()
	if err != nil {
		out["logged_in"] = false
		out["note"] = err.Error()
		return out, nil
	}
	cfg, err := config.Load(path, t.e.Getenv)
	if err != nil {
		out["logged_in"] = false
		out["note"] = err.Error()
		return out, nil
	}
	if cfg.Server == "" {
		out["logged_in"] = false
		out["note"] = "not logged in: the person runs `runpentests login` (it prompts for an API key from Workspace → API tokens)"
		return out, nil
	}
	// A dev server with auth off is logged in without a key.
	out["server"] = cfg.Server
	out["api_key_set"] = cfg.APIKey != ""
	out["logged_in"] = true
	if cfg.Profile != "" {
		out["profile"] = cfg.Profile
	}
	c, err := t.e.client()
	if err != nil {
		out["reachable"] = false
		out["note"] = err.Error()
		return out, nil
	}
	if err := c.Ready(ctx); err != nil {
		out["reachable"] = false
		out["note"] = err.Error()
		return out, nil
	}
	out["reachable"] = true
	caps, err := c.Capabilities(ctx)
	if err != nil {
		out["passes"] = "unknown (the server has no /capabilities)"
		return out, nil
	}
	passes := map[string]any{}
	for field, cap := range caps.Passes {
		entry := map[string]any{"available": cap.Available}
		if cap.Reason != nil {
			entry["reason"] = reasonText(*cap.Reason)
		}
		passes[field] = entry
	}
	out["passes"] = passes
	premium := map[string]any{"available": caps.Premium.Available}
	if caps.Premium.Plan != "" {
		premium["plan"] = reasonText(caps.Premium.Plan)
	}
	out["premium"] = premium
	return out, nil
}

func (t *mcpTools) nextSteps(_ context.Context, raw json.RawMessage) (any, error) {
	var args struct {
		Path string `json:"path"`
	}
	if err := decodeArgs(raw, &args); err != nil {
		return nil, err
	}
	file, dir, err := t.loadProject(nil, args.Path)
	if err != nil {
		return nil, err
	}
	var steps []string
	if !t.loggedIn() {
		steps = append(steps, "runpentests login    # once; paste an API key from Workspace → API tokens")
	}
	summary, warnings := t.summarize(file, dir)
	steps = append(steps, "make runner-image   # once, in the runpentests repository: every run needs the runner image")
	env := append([]string(nil), summary.Env...)
	sort.Strings(env)
	for _, name := range env {
		steps = append(steps, "export "+name+"=...   # the secret itself; never commit it")
	}
	run := "runpentests"
	if file.Target == "" {
		run = "runpentests https://STAGING-URL"
	}
	if t.rel(dir) != "." {
		run = "cd " + t.rel(dir) + " && " + run
	}
	steps = append(steps, run+"    # asks you to confirm you are authorized to test the target, then scans")
	out := map[string]any{
		"steps": steps,
		"ci": "In CI, the same command with --authorized (the pipeline's owner answers the gate), and " +
			"RUNPENTESTS_SERVER / RUNPENTESTS_API_KEY plus each variable above as pipeline secrets. See runpentests://docs/ci-gate.",
		"reminder": "Give these to the person. Do not run the scan or add --authorized yourself.",
	}
	if len(warnings) > 0 {
		out["warnings"] = warnings
	}
	return out, nil
}

func (t *mcpTools) loggedIn() bool {
	path, err := t.e.configPath()
	if err != nil {
		return false
	}
	cfg, err := config.Load(path, t.e.Getenv)
	return err == nil && cfg.Server != ""
}
