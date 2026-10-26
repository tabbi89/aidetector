package commands

import (
	"bytes"
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"runpentests/cli/internal/api"
	"runpentests/cli/internal/project"
)

// The target form is the everyday way in:
//
//	runpentests https://api.example.com            scan it (reuse the scan for it, or create one)
//	runpentests https://api.example.com ./project  ...and read the code in ./project (a local run)
//	runpentests                                     run what ./runpentests.yml describes
//
// It composes the subcommands — find or create a scan, make sure it has a spec
// and identities, run it, show what it found — so it adds no server API of its
// own beyond telling the server which settings a project file owns.
//
// Precedence, setting by setting: CLI flags > runpentests.yml > the web's saved
// settings > defaults. Consent is never a setting: it is --authorized or a
// prompt naming the target, answered before this process sends anything.

// wellKnownSpecPaths are where frameworks publish their spec, tried in order
// when nothing else supplies one.
var wellKnownSpecPaths = []string{
	"/openapi.json", "/swagger.json", "/v3/api-docs", "/openapi.yaml",
	"/swagger/v1/swagger.json", "/api-docs", "/swagger.yaml",
}

// maxSpecBytes bounds a spec fetched from the target.
const maxSpecBytes = 10 << 20

var looksLikeSpec = regexp.MustCompile(`(?m)("openapi"|"swagger"|^openapi:|^swagger:)`)

var hexCommit = regexp.MustCompile(`^[0-9a-f]{7,64}$`)

func cmdTarget(ctx context.Context, e *Env, args []string) int {
	fs := e.newFlagSet("runpentests")
	authorized := fs.Bool("authorized", false, "I own or am authorized to security-test this target")
	passes := map[string]*bool{}
	for flagName := range RunFlags {
		passes[flagName] = fs.Bool(flagName, false, PassHelp[flagName])
	}
	levelFlag := fs.String("level", "", "how hard to look: quick | standard | deep (default quick)")
	checks := fs.String("checks", "", "comma-separated check keys to scope the run to")
	rps := fs.Int("rps", 0, "requests per second (1-100)")
	seed := fs.Int("seed", -1, "payload-rotation seed to reuse (from `runs --json` manifest.seed); default a fresh one")
	failOn, verified, newOnly, baseline, complete, minExercised := addGateFlags(fs)
	asJSON, outputFlag := addOutputFlags(fs, "print results as JSON")
	specFlag := fs.String("spec", "", "OpenAPI/Swagger/HAR/Postman file to scan with")
	configFlag := fs.String("config", "", "project file (default: runpentests.yml in the project directory)")
	noConfig := fs.Bool("no-config", false, "ignore runpentests.yml")
	fresh := fs.Bool("new", false, "create a new scan even if one exists for this target")
	image := fs.String("image", defaultRunnerImage(e), "runner image")
	var networks dockerNetworks
	fs.Var(&networks, "docker-network", "docker network the runner joins; repeat or comma-separate for several")
	secretsFile := fs.String("secrets-file", "", "JSON {name: secret} file, mode 0600")
	runnerServer := fs.String("runner-server", "", "server URL as the runner container sees it")
	resourceIDsFile := fs.String("resource-ids", "", "JSON/YAML file of known resource ids {name: id} for path parameters (stays on this machine)")
	pos, err := parse(fs, args)
	if err != nil {
		return e.parseFailed("target", fs, err)
	}
	output, code := e.resolveOutput(fs, *asJSON, *outputFlag)
	if code != ExitOK {
		return code
	}
	explicit := map[string]bool{}
	fs.Visit(func(f *flag.Flag) { explicit[f.Name] = true })

	// --- what was asked: a target, a project directory, a project file -------
	var targetArg, dirArg string
	for _, p := range pos {
		if info, err := os.Stat(p); err == nil && info.IsDir() {
			if dirArg != "" {
				return e.usage("give one project directory, not two (%s, %s)", dirArg, p)
			}
			dirArg = p
			continue
		}
		if !project.LooksLikeTarget(p) {
			return e.usage("%q is neither a URL nor a directory", p)
		}
		if targetArg != "" {
			return e.usage("give one target URL, not two (%s, %s)", targetArg, p)
		}
		targetArg = p
	}

	var file *project.Loaded
	if !*noConfig {
		switch {
		case *configFlag != "":
			file, err = project.Load(*configFlag)
		case dirArg != "":
			file, err = project.Find(dirArg)
		default:
			wd, werr := e.workdir()
			if werr != nil {
				return e.usage("%v", werr)
			}
			file, err = project.Find(wd)
		}
		if err != nil {
			return e.usage("%v", err)
		}
	}
	var pf project.File
	if file != nil {
		pf = file.File
		e.errorf("using %s\n", e.display(file.Path))
	}

	rawTarget := targetArg
	if rawTarget == "" {
		rawTarget = pf.Target
	}
	if rawTarget == "" {
		return e.usage("nothing to scan: give a target URL (runpentests https://api.example.com) " +
			"or set target: in runpentests.yml")
	}
	target, err := project.NormalizeTarget(rawTarget)
	if err != nil {
		return e.usage("%v", err)
	}

	sourceDir := ""
	switch {
	case dirArg != "":
		sourceDir = dirArg
	case pf.Source != "":
		sourceDir = file.Resolve(pf.Source)
	}
	if sourceDir != "" {
		if sourceDir, err = resolveSourceDir(sourceDir); err != nil {
			return e.usage("%v", err)
		}
	}

	// Flags win over the file, the file over the web.
	gp := gatePolicy{
		failOn:       pick(explicit["fail-on"], *failOn, pf.FailOn),
		verifiedOnly: *verified || (!explicit["verified-only"] && pf.VerifiedOnly),
		newOnly:      *newOnly || (!explicit["new-only"] && pf.NewOnly),
		baselineRun:  *baseline,
		quality: qualityPolicy{
			RequireComplete: *complete || (!explicit["require-complete"] && pf.RequireComplete),
			MinExercised:    pf.MinExercised,
		},
	}
	if explicit["min-exercised"] {
		gp.quality.MinExercised = *minExercised
	}
	if code := e.checkGateFlags(&gp); code != ExitOK {
		return code
	}
	if *seed < -1 || *seed >= 1<<31 {
		return e.usage("--seed must be between 0 and 2147483647")
	}
	resourceIDs, err := resolveResourceIDs(file, *resourceIDsFile)
	if err != nil {
		return e.usage("%v", err)
	}
	rate := pf.RPS
	if explicit["rps"] {
		rate = *rps
	}
	if rate != 0 && (rate < 1 || rate > 100) {
		return e.usage("--rps must be between 1 and 100")
	}
	level := pick(explicit["level"], *levelFlag, pf.Level)
	if level != "" && !validLevel(level) {
		return e.usage("--level must be one of quick, standard, deep")
	}

	body := map[string]any{"authorized": true}
	for flagName := range passes {
		if !*passes[flagName] {
			continue
		}
		field, ok := passField(flagName)
		if !ok {
			continue
		}
		body[field] = true
	}
	for _, p := range pf.Passes {
		if now, renamed := renamedPasses[p]; renamed {
			return e.usage("runpentests.yml: the %q pass is now called %q", p, now)
		}
		field, ok := passField(p)
		if !ok {
			return e.usage("runpentests.yml: unknown pass %q in passes", p)
		}
		body[field] = true
	}
	if level != "" {
		body["level"] = level
	}
	scope := pf.Checks
	if explicit["checks"] {
		scope = splitList(*checks)
	}
	if len(scope) > 0 {
		body["checks"] = scope
	}
	if rate != 0 {
		body["requests_per_second"] = rate
	}
	if *seed >= 0 {
		body["seed"] = *seed
	}

	c, err := e.client()
	if err != nil {
		return e.usage("%v", err)
	}

	// --- consent: before a single request goes to the target ------------------
	if code := e.consent(*authorized, "active security tests", func() (string, int) { return target, ExitOK }); code != ExitOK {
		return code
	}

	// --- the scan: pinned, reused, or new -----------------------------------
	scan, created, code := findOrCreateScan(ctx, e, c, target, pf.Scan, *fresh)
	if code != ExitOK {
		return code
	}
	discard := func() {
		if created {
			_ = c.DeleteScan(context.Background(), scan.ID)
		}
	}

	// --- the spec ------------------------------------------------------------
	specPath := *specFlag
	specOrigin := specPath
	if specPath == "" && pf.Spec != "" {
		specPath = file.Resolve(pf.Spec)
		specOrigin = e.display(specPath) + " (runpentests.yml)"
	}
	if specPath == "" {
		searchIn := sourceDir
		if searchIn == "" && file != nil {
			searchIn = file.Dir
		}
		if searchIn != "" {
			found, err := project.FindSpec(searchIn)
			if err != nil {
				discard()
				return e.usage("looking for a spec in %s: %v", searchIn, err)
			}
			if found != "" {
				specPath, specOrigin = found, e.display(found)+" (found in the project)"
			}
		}
	}
	var spec string
	switch {
	case specPath != "":
		data, err := os.ReadFile(specPath)
		if err != nil {
			discard()
			return e.usage("cannot read spec: %v", err)
		}
		spec = string(data)
	case !created && scan.SpecText != nil && *scan.SpecText != "":
		// The scan's saved spec stands: the web owns it.
	default:
		fetched, from, err := fetchSpec(ctx, target)
		if errors.Is(err, errTargetUnreachable) {
			discard()
			return e.usage("no spec: %v\nthe spec is fetched from this machine; if only the server can "+
				"reach %s, pass --spec FILE (or set spec: in runpentests.yml)", err, target)
		}
		if err != nil {
			discard()
			return e.usage("no spec: pass --spec FILE, set spec: in runpentests.yml, or publish one at %s "+
				"(tried %s)", target, strings.Join(wellKnownSpecPaths, ", "))
		}
		spec, specOrigin = fetched, from
	}
	if spec != "" && (scan.SpecText == nil || *scan.SpecText != spec) {
		withSpec, err := c.UploadSpec(ctx, scan.ID, spec)
		if err != nil {
			discard()
			return e.exitFor(err)
		}
		scan.Operations, scan.SpecText = withSpec.Operations, &spec
		e.errorf("spec: %s — %d operations\n", specOrigin, len(withSpec.Operations))
	}

	// --- identities ----------------------------------------------------------
	secrets, code := applyIdentities(ctx, e, c, &scan, pf, created)
	if code != ExitOK {
		discard()
		return code
	}

	// --- tell the server what the file owns ----------------------------------
	if file != nil {
		commit := e.gitHead(file.Dir)
		mc := api.ManagedConfig{
			Path: filepath.Base(file.Path), Digest: file.Digest,
			Fields: pf.Fields(), Identities: pf.IdentityNames(),
		}
		source := map[string]any{"path": mc.Path, "digest": mc.Digest}
		if commit != "" {
			mc.Commit = &commit
			source["commit"] = commit
		}
		if mc.Fields == nil {
			mc.Fields = []string{}
		}
		if err := c.SetManagedConfig(ctx, scan.ID, mc); err != nil {
			return e.exitFor(err)
		}
		body["config_source"] = source
	}

	// --- run, show -----------------------------------------------------------
	e.errorf("scan %s\n", scan.ID)
	schemaDir := ""
	if file != nil {
		schemaDir = file.Dir
	}
	ranRun := 0
	code = runLocal(ctx, e, c, scan.ID, body,
		localFlags{image: *image, networks: networks, secretsFile: *secretsFile,
			runnerServer: *runnerServer, source: sourceDir, secrets: secrets,
			schema: pf.Schema, schemaDir: schemaDir, resourceIDs: resourceIDs,
			onClaim: func(n int) { ranRun = n }},
		gatePolicy{}, outputTable)
	if code != ExitOK {
		return code
	}
	if gp.active() {
		// CI formats own stdout: a JUnit document or workflow commands must
		// not be preceded by the human table.
		if output == outputTable {
			showFindings(ctx, e, c, scan.ID)
		}
		return gate(ctx, e, c, scan.ID, ranRun, gp, output)
	}
	if output == outputJSON {
		findings, err := c.Findings(ctx, scan.ID)
		if err != nil {
			return e.exitFor(err)
		}
		return printJSON(e, findings)
	}
	return showFindings(ctx, e, c, scan.ID)
}

// findOrCreateScan picks the scan this run belongs to: the one runpentests.yml
// pins, else the latest one for the same target, else a new one. Reusing is
// the point — identities, triage and the diff all live on the scan.
func findOrCreateScan(ctx context.Context, e *Env, c *api.Client, target, pinned string, fresh bool) (api.Scan, bool, int) {
	if pinned != "" && !fresh {
		scan, err := c.GetScan(ctx, pinned)
		if err != nil {
			return api.Scan{}, false, e.exitFor(err)
		}
		if !project.SameTarget(scan.TargetBaseURL, target) {
			e.errorf("updating scan %s's target from %s to %s\n", scan.ID, scan.TargetBaseURL, target)
			if scan, err = c.UpdateTarget(ctx, scan.ID, target); err != nil {
				return api.Scan{}, false, e.exitFor(err)
			}
		}
		e.errorf("reusing scan %s (pinned in runpentests.yml)\n", scan.ID)
		return scan, false, ExitOK
	}
	if !fresh {
		all, err := c.ListScans(ctx)
		if err != nil {
			return api.Scan{}, false, e.exitFor(err)
		}
		if latest, count, ok := latestScanFor(all, target); ok {
			scan, err := c.GetScan(ctx, latest.ID)
			if err != nil {
				return api.Scan{}, false, e.exitFor(err)
			}
			note := ""
			if count > 1 {
				note = fmt.Sprintf(" — %d scans match; pin one with scan: in runpentests.yml", count)
			}
			e.errorf("reusing scan %s for %s%s\n", scan.ID, target, note)
			return scan, false, ExitOK
		}
	}
	scan, err := c.CreateScan(ctx, target)
	if err != nil {
		return api.Scan{}, false, e.exitFor(err)
	}
	e.errorf("created scan %s for %s\n", scan.ID, target)
	return scan, true, ExitOK
}

// applyIdentities makes the scan's identities match the file's, by name. An
// identity only the web knows is left alone. It returns the secrets found on
// this machine by identity name.
//
// Every run is local, so secrets stay here: an identity this has to create is
// created local-only — the shape alone, so the secret never reaches the server.
func applyIdentities(ctx context.Context, e *Env, c *api.Client, scan *api.Scan,
	pf project.File, created bool) (map[string]string, int) {
	secrets := map[string]string{}
	// auth: public says the API deliberately takes no identity: say nothing and
	// ask nothing, and leave whatever identities the web owns alone.
	if pf.Auth == "public" {
		return secrets, ExitOK
	}
	want := pf.ExpandIdentities()
	if len(want) == 0 {
		if len(scan.CredentialProfiles) > 0 {
			return secrets, ExitOK
		}
		if e.IsTTY() {
			added, code := promptIdentities(ctx, e, c, scan.ID, secrets)
			if code != ExitOK {
				return nil, code
			}
			if added > 0 {
				return secrets, ExitOK
			}
		}
		e.errorf("warning: this scan has no identities, so the authorization checks (BOLA, BFLA, " +
			"broken auth) will be skipped — add them under identities: in runpentests.yml or with " +
			"`runpentests cred add`\n")
		return secrets, ExitOK
	}

	byName := map[string]api.CredentialProfile{}
	for _, p := range scan.CredentialProfiles {
		byName[p.Name] = p
	}
	for _, id := range want {
		secret := ""
		if id.SecretEnv != "" {
			secret = e.Getenv(id.SecretEnv)
		}
		if secret != "" {
			secrets[id.Name] = secret
		}
		var header *string
		if id.Header != "" {
			h := id.Header
			header = &h
		}
		shape := shapeOf(id)
		existing, ok := byName[id.Name]
		if !ok && id.Auth != "none" {
			// The run reads the secret here, so the server only needs the
			// shape: the secret never crosses to it, not even once.
			cred := api.Credential{Name: id.Name, Role: id.Role, AuthType: id.Auth, HeaderName: header,
				LocalOnly: true, Privilege: shape.privilege, Tenant: shape.tenant, GrantType: shape.grantType,
				TokenURL: shape.tokenURL, GrantParams: shape.params}
			if err := c.AddCredential(ctx, scan.ID, cred); err != nil {
				return nil, e.exitFor(err)
			}
			e.errorf("identity %s (%s): added, local-only (its secret stays on this machine)\n", id.Name, id.Role)
			continue
		}
		if !ok {
			// auth: none — the server requires a value, and "none" never sends it.
			cred := api.Credential{Name: id.Name, Role: id.Role, AuthType: id.Auth, HeaderName: header,
				Secret: "-", Privilege: shape.privilege, Tenant: shape.tenant, GrantType: shape.grantType,
				TokenURL: shape.tokenURL, GrantParams: shape.params}
			if err := c.AddCredential(ctx, scan.ID, cred); err != nil {
				return nil, e.exitFor(err)
			}
			e.errorf("identity %s (%s): added\n", id.Name, id.Role)
			continue
		}
		shapeChanged := existing.Role != id.Role || existing.AuthType != id.Auth ||
			deref(existing.HeaderName) != id.Header || !sameShape(existing, shape)
		update := api.CredentialUpdate{Name: id.Name, Role: id.Role, AuthType: id.Auth, HeaderName: header,
			Privilege: shape.privilege, Tenant: shape.tenant, GrantType: shape.grantType,
			TokenURL: shape.tokenURL, GrantParams: shape.params}
		if !shapeChanged {
			continue
		}
		if err := c.UpdateCredential(ctx, scan.ID, existing.ID, update); err != nil {
			return nil, e.exitFor(err)
		}
		if shapeChanged {
			e.errorf("identity %s (%s): updated from runpentests.yml\n", id.Name, id.Role)
		}
	}
	return secrets, ExitOK
}

// identityShape is the credential shape a file identity maps to: the explicit
// privilege, the tenant and the token-minting grant, if any.
type identityShape struct {
	privilege *int
	tenant    *string
	grantType string // "static" when the secret is the token itself
	tokenURL  *string
	params    map[string]any
}

func shapeOf(id project.Identity) identityShape {
	s := identityShape{grantType: "static"}
	if id.Rank != nil {
		rank := *id.Rank
		s.privilege = &rank
	}
	if id.Tenant != "" {
		tenant := id.Tenant
		s.tenant = &tenant
	}
	if id.Grant != nil {
		g := id.Grant
		s.grantType = g.Type
		u := g.TokenURL
		s.tokenURL = &u
		params := map[string]any{}
		for _, kv := range [][2]string{
			{"client_id", g.ClientID}, {"username", g.Username}, {"scope", g.Scope},
			{"cookie_name", g.CookieName}, {"username_field", g.UsernameField},
			{"password_field", g.PasswordField}, {"format", g.Format},
			{"access_token_field", g.AccessTokenField},
		} {
			if kv[1] != "" {
				params[kv[0]] = kv[1]
			}
		}
		if len(params) > 0 {
			s.params = params
		}
	}
	return s
}

// sameShape compares what the server has with what the file asks for. An older
// server omits grant_type and grant_params; that is the static default, not a
// change, or every run would PATCH every identity.
func sameShape(existing api.CredentialProfile, want identityShape) bool {
	if !sameOptionalInt(existing.Privilege, want.privilege) {
		return false
	}
	if deref(existing.Tenant) != deref(want.tenant) {
		return false
	}
	haveGrant := existing.GrantType
	if haveGrant == "" {
		haveGrant = "static"
	}
	if haveGrant != want.grantType {
		return false
	}
	if deref(existing.TokenURL) != deref(want.tokenURL) {
		return false
	}
	if len(existing.GrantParams) == 0 && len(want.params) == 0 {
		return true
	}
	return reflect.DeepEqual(existing.GrantParams, want.params)
}

func sameOptionalInt(a, b *int) bool {
	if a == nil || b == nil {
		return a == nil && b == nil
	}
	return *a == *b
}

// promptIdentities asks for identities on a scan that has none. The
// authorization checks are the point of the tool, and they need two. For a
// local run the typed secret stays in secrets and the identity is created
// local-only, so it never reaches the server.
func promptIdentities(ctx context.Context, e *Env, c *api.Client, scanID string,
	secrets map[string]string) (int, int) {
	e.errorf("This scan has no identities. The authorization checks compare two users — " +
		"for example a normal user and an admin.\n")
	added := 0
	for added < 5 {
		e.errorf("Identity name (empty to finish): ")
		name, _ := e.readLine()
		if name = strings.TrimSpace(name); name == "" {
			break
		}
		e.errorf("Role for %s (e.g. user, admin): ", name)
		role, _ := e.readLine()
		if role = strings.TrimSpace(role); role == "" {
			role = "user"
		}
		e.errorf("Auth type [bearer]: ")
		auth, _ := e.readLine()
		if auth = strings.TrimSpace(auth); auth == "" {
			auth = "bearer"
		}
		if !project.AuthTypes[auth] {
			e.errorf("unknown auth type %q (bearer, header, api_key, basic, query, cookie, none)\n", auth)
			continue
		}
		var header *string
		if auth == "header" || auth == "api_key" || auth == "query" || auth == "cookie" {
			e.errorf("Header / query parameter / cookie name: ")
			h, _ := e.readLine()
			if h = strings.TrimSpace(h); h != "" {
				header = &h
			}
			if header == nil && (auth == "query" || auth == "cookie") {
				e.errorf("auth %s needs the name to send the secret in; %s skipped\n", auth, name)
				continue
			}
		}
		var privilege *int
		e.errorf("Privilege (0 lowest … 3 highest, empty = from role name): ")
		if p, _ := e.readLine(); strings.TrimSpace(p) != "" {
			n, err := strconv.Atoi(strings.TrimSpace(p))
			if err != nil || n < 0 || n > project.MaxRank {
				e.errorf("privilege must be a number from 0 to %d; %s skipped\n", project.MaxRank, name)
				continue
			}
			privilege = &n
		}
		secret := "-"
		if auth != "none" {
			s, err := e.ReadSecret(fmt.Sprintf("Secret for %s (input hidden): ", name))
			if err != nil || s == "" {
				e.errorf("no secret entered; %s skipped\n", name)
				continue
			}
			secret = s
		}
		cred := api.Credential{Name: name, Role: role, AuthType: auth, HeaderName: header,
			Secret: secret, Privilege: privilege}
		where := ""
		if auth != "none" {
			secrets[name] = secret
			cred.Secret, cred.LocalOnly = "", true
			where = ", local-only (its secret stays on this machine)"
		}
		if err := c.AddCredential(ctx, scanID, cred); err != nil {
			return added, e.exitFor(err)
		}
		e.errorf("identity %s (%s): added%s\n", name, role, where)
		added++
	}
	return added, ExitOK
}

// errTargetUnreachable means no well-known spec path answered at all.
var errTargetUnreachable = errors.New("this machine cannot reach the target")

// fetchSpec asks the target for its own spec at the usual addresses. It runs
// only after consent: it is a request to the target like any other.
func fetchSpec(ctx context.Context, target string) (string, string, error) {
	client := &http.Client{Timeout: 10 * time.Second}
	answered := false
	var lastErr error
	for _, p := range wellKnownSpecPaths {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, target+p, nil)
		if err != nil {
			return "", "", err
		}
		resp, err := client.Do(req)
		if err != nil {
			if ctx.Err() != nil {
				return "", "", ctx.Err()
			}
			lastErr = err
			continue
		}
		answered = true
		data, _ := io.ReadAll(io.LimitReader(resp.Body, maxSpecBytes+1))
		resp.Body.Close()
		if resp.StatusCode == http.StatusOK && len(data) <= maxSpecBytes && looksLikeSpec.Match(data) {
			return string(data), target + p, nil
		}
	}
	if !answered && lastErr != nil {
		// Not "no spec": this machine cannot reach the target at all — often a
		// hostname only the server's network resolves (a compose service name).
		return "", "", fmt.Errorf("%w: %v", errTargetUnreachable, lastErr)
	}
	return "", "", errors.New("the target publishes no spec at the usual paths")
}

// showFindings prints the run's findings, most severe first, and where to go next.
func showFindings(ctx context.Context, e *Env, c *api.Client, id string) int {
	findings, err := c.Findings(ctx, id)
	if err != nil {
		return e.exitFor(err)
	}
	var live []api.Finding
	verifiedCount := 0
	for _, f := range findings {
		if f.Verdict == "dismissed" {
			continue
		}
		live = append(live, f)
		if f.Confidence == "verified" {
			verifiedCount++
		}
	}
	sort.SliceStable(live, func(i, j int) bool {
		return severityRank[strings.ToLower(live[i].Severity)] > severityRank[strings.ToLower(live[j].Severity)]
	})
	for _, f := range live {
		e.printf("%-8s %-9s %-24s %s\n", f.Severity, f.Confidence, f.Check, printable(f.Title))
	}
	e.printf("%d finding(s), %d verified\n", len(live), verifiedCount)
	printLimits(ctx, e, c, id)
	printRunQuality(ctx, e, c, id, 0)
	e.errorf("view: %s\n", scanPageURL(e, c.Base(), id))
	e.errorf("details: runpentests findings %s · report: runpentests report %s --format html -o report.html\n", id, id)
	return ExitOK
}

// scanPageURL is the scan's page in the web UI. The hosted server serves the web
// and the API from one origin; a local `make up` puts the API on :8000 and the
// web on :3000. RUNPENTESTS_WEB_URL overrides both guesses.
func scanPageURL(e *Env, server, id string) string {
	base := strings.TrimRight(e.Getenv("RUNPENTESTS_WEB_URL"), "/")
	if base == "" {
		base = strings.TrimRight(server, "/")
		if u, err := url.Parse(base); err == nil && project.IsLoopbackTarget(base) && u.Port() == "8000" {
			u.Host = net.JoinHostPort(u.Hostname(), "3000")
			base = u.String()
		}
	}
	return base + "/scans/" + url.PathEscape(id)
}

// gitHead is the project's current commit, for the run record. Best effort: no
// git, or not a repository, is just "no commit".
func (e *Env) gitHead(dir string) string {
	if e.GitHead != nil {
		return e.GitHead(dir)
	}
	bin, err := exec.LookPath("git")
	if err != nil {
		return ""
	}
	var out bytes.Buffer
	cmd := exec.Command(bin, "-C", dir, "rev-parse", "HEAD")
	cmd.Stdout = &out
	if cmd.Run() != nil {
		return ""
	}
	head := strings.TrimSpace(out.String())
	if !hexCommit.MatchString(head) {
		return ""
	}
	return head
}

func (e *Env) workdir() (string, error) {
	if e.Dir != "" {
		return e.Dir, nil
	}
	return os.Getwd()
}

// display shortens a path to be relative to the working directory when it can.
func (e *Env) display(p string) string {
	wd, err := e.workdir()
	if err != nil {
		return p
	}
	if rel, err := filepath.Rel(wd, p); err == nil && !strings.HasPrefix(rel, "..") {
		return rel
	}
	return p
}

func pick(flagSet bool, flagValue, fileValue string) string {
	if flagSet {
		return flagValue
	}
	return fileValue
}

func splitList(s string) []string {
	var out []string
	for _, k := range strings.Split(s, ",") {
		if k = strings.TrimSpace(k); k != "" {
			out = append(out, k)
		}
	}
	return out
}

func deref(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}
