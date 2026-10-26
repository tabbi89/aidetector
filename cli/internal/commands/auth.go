package commands

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"runpentests/cli/internal/api"
)

// `runpentests auth check` asks, before a full scan, whether each identity's
// credential is accepted by the target. It runs in the same runner container
// and network as a scan — same egress rules, pins and grant minting — and
// sends a few GET requests per identity plus the same ones anonymously. No
// payload, no write, no redirect followed, no run opened, nothing uploaded.

// authRoute and authIdentity mirror the runner's report.
type authIdentity struct {
	Name     string `json:"name"`
	Role     string `json:"role"`
	Tenant   string `json:"tenant"`
	Auth     string `json:"auth"`
	State    string `json:"state"`
	Detail   string `json:"detail"`
	Statuses []*int `json:"statuses"`
}

type authReport struct {
	Target     string           `json:"target"`
	Reachable  bool             `json:"reachable"`
	Requests   int              `json:"requests"`
	Routes     []map[string]any `json:"routes"`
	Anonymous  []*int           `json:"anonymous"`
	Identities []authIdentity   `json:"identities"`
	Events     []map[string]any `json:"events"`
}

func cmdAuth(ctx context.Context, e *Env, args []string) int {
	if len(args) == 0 || wantsHelp(args) {
		if wantsHelp(args) {
			return e.printCommandHelp("auth", nil)
		}
		return e.usage("auth needs a subcommand: check [SCAN]")
	}
	if args[0] != "check" {
		return e.usage("unknown auth subcommand %q (try `runpentests auth check`)", args[0])
	}
	return authCheck(ctx, e, args[1:])
}

func authCheck(ctx context.Context, e *Env, args []string) int {
	fs := e.newFlagSet("auth check")
	authorized := fs.Bool("authorized", false, "I own or am authorized to send requests to this target")
	asJSON := fs.Bool("json", false, "print the report as JSON")
	image := fs.String("image", defaultRunnerImage(e), "runner image")
	var networks dockerNetworks
	fs.Var(&networks, "docker-network", "docker network the runner joins; repeat or comma-separate for several")
	secretsFile := fs.String("secrets-file", "", "JSON {name: secret} file, mode 0600")
	resourceIDsFile := fs.String("resource-ids", "", "JSON/YAML file of known resource ids for item routes (stays on this machine)")
	pos, err := parse(fs, args)
	if err != nil {
		return e.parseFailed("auth", fs, err)
	}
	if len(pos) > 1 {
		return e.usage("auth check takes at most one scan ID")
	}
	if e.Docker == nil {
		return e.usage("this build cannot start containers")
	}
	file, byName, code := projectContext(e)
	if code != ExitOK {
		return code
	}
	resourceIDs, err := resolveResourceIDs(file, *resourceIDsFile)
	if err != nil {
		return e.usage("%v", err)
	}
	c, err := e.client()
	if err != nil {
		return e.usage("%v", err)
	}
	id, code := resolveScan(ctx, e, c, argOrEmpty(pos), true)
	if code != ExitOK {
		return code
	}

	// Placeholders the project file still carries.
	placeholders := map[string]bool{}
	if file != nil {
		for _, ident := range file.ExpandIdentities() {
			if g := ident.Grant; g != nil && (g.ClientID == grantPlaceholder || g.Username == grantPlaceholder ||
				strings.Contains(g.TokenURL, grantPlaceholder)) {
				placeholders[ident.Name] = true
			}
		}
	}

	if code := e.consent(*authorized, "a few GET requests per identity", scanTarget(ctx, e, c, id)); code != ExitOK {
		return code
	}
	build := ""
	if *image == runnerImageDefault {
		build = "build it with `make runner-image` in the runpentests repository"
	}
	if code := ensureImage(ctx, e, *image, build); code != ExitOK {
		return code
	}
	if *image == runnerImageDefault {
		// An image older than --auth-check prints no report; say why up front.
		warnStaleRunner(ctx, e, *image)
	}

	check, err := c.ClaimAuthCheck(ctx, id)
	if err != nil {
		var apiErr *api.APIError
		if errors.As(err, &apiErr) && apiErr.Status == 404 && apiErr.Detail != "scan not found" {
			e.errorf("hint: auth checks run on the local runner; it is off on this server, or the " +
				"server is older than this CLI\n")
		}
		code := e.exitFor(err)
		ownershipHint(ctx, e, c, id, err)
		return code
	}
	secrets, err := collectSecrets(e, check, *secretsFile, byName)
	if err != nil {
		return e.usage("%v", err)
	}
	inner := map[string]any{}
	for k, v := range check {
		inner[k] = v
	}
	inner["target_base_url"] = rewriteLoopback(check.Str("target_base_url"))
	cfg := map[string]any{"check": inner, "secrets": secrets}
	if len(resourceIDs) > 0 {
		cfg["predefined_resource_ids"] = resourceIDs
	}
	stdin, err := json.Marshal(cfg)
	if err != nil {
		return e.usage("%v", err)
	}

	name := "runpentests-auth-" + shortID(id)
	lf := localFlags{image: *image, networks: networks}
	dockerCmd := append(dockerArgs(name, lf), "--auth-check")
	var stdout bytes.Buffer
	runErr := e.Docker(ctx, name, dockerCmd, bytes.NewReader(stdin), &stdout, e.Stderr)
	var report authReport
	if err := json.Unmarshal(bytes.TrimSpace(stdout.Bytes()), &report); err != nil {
		reason := "the runner printed no report (an image older than this CLI has no --auth-check: `make runner-image`)"
		if runErr != nil {
			reason += ": " + oneLine(runErr.Error())
		}
		e.errorf("error: %s\n", reason)
		return ExitFailed
	}
	// An identity runpentests.yml lists that the scan does not have yet was not
	// checked at all: say so, rather than a report that reads complete.
	onScan := map[string]bool{}
	for _, id := range report.Identities {
		onScan[id.Name] = true
	}
	if file != nil && file.Auth != "public" {
		for _, ident := range file.ExpandIdentities() {
			if !onScan[ident.Name] {
				report.Identities = append(report.Identities, authIdentity{
					Name: ident.Name, Role: ident.Role, Tenant: ident.Tenant, Auth: ident.Auth,
					State:  "not_on_scan",
					Detail: "listed in runpentests.yml but not on the scan yet — the next scan run adds it",
				})
			}
		}
	}
	for i := range report.Identities {
		if placeholders[report.Identities[i].Name] && report.Identities[i].State == "grant_failed" {
			report.Identities[i].Detail += " — the grant still says " + grantPlaceholder + " in runpentests.yml"
		}
	}
	if *asJSON {
		printJSON(e, report)
	} else {
		printAuthReport(e, report, placeholders)
	}
	switch {
	case !report.Reachable:
		return ExitFailed
	case !allAccepted(report):
		return ExitFindings
	}
	return ExitOK
}

func allAccepted(r authReport) bool {
	for _, id := range r.Identities {
		if id.State != "accepted" && id.State != "no_credential" {
			return false
		}
	}
	return true
}

func statusList(statuses []*int) string {
	parts := make([]string, len(statuses))
	for i, s := range statuses {
		if s == nil {
			parts[i] = "-"
		} else {
			parts[i] = fmt.Sprintf("%d", *s)
		}
	}
	return strings.Join(parts, " ")
}

func printAuthReport(e *Env, r authReport, placeholders map[string]bool) {
	var routes []string
	for _, route := range r.Routes {
		p, _ := route["path"].(string)
		routes = append(routes, "GET "+printable(p))
	}
	e.printf("routes checked: %s\n", strings.Join(routes, ", "))
	e.printf("%-20s  %-10s  %-8s  %-15s  %-12s  %s\n", "IDENTITY", "TENANT", "AUTH", "STATE", "STATUSES", "DETAIL")
	e.printf("%-20s  %-10s  %-8s  %-15s  %-12s  %s\n", "(anonymous)", "-", "-", "-", statusList(r.Anonymous), "the baseline every key is compared with")
	for _, id := range r.Identities {
		tenant := id.Tenant
		if tenant == "" {
			tenant = "-"
		}
		e.printf("%-20s  %-10s  %-8s  %-15s  %-12s  %s\n", printable(id.Name), printable(tenant),
			printable(id.Auth), printable(id.State), statusList(id.Statuses), printable(id.Detail))
	}
	for _, ev := range r.Events {
		if msg, _ := ev["message"].(string); msg != "" {
			e.errorf("  note: %s\n", printable(msg))
		}
	}
	if !r.Reachable {
		e.printf("the target did not answer from the runner: check the URL, and --docker-network if it is only reachable on one\n")
		return
	}
	for _, id := range r.Identities {
		switch id.State {
		case "missing_secret":
			e.printf("fix %s: export its secret_env variable, RUNPENTESTS_SECRET_%s, or pass --secrets-file\n",
				printable(id.Name), envName(id.Name))
		case "rejected":
			e.printf("fix %s: the target refused the credential — rotate it, or check auth/header in runpentests.yml\n",
				printable(id.Name))
		case "grant_failed":
			if placeholders[id.Name] {
				e.printf("fix %s: replace %s in its grant in runpentests.yml\n", printable(id.Name), grantPlaceholder)
			}
		}
	}
	e.printf("%d request(s) sent; a public 2xx never counts as proof that a key works\n", r.Requests)
}
