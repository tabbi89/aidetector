package commands

import (
	"context"
	"errors"
	"net/url"
	"regexp"
	"strings"
	"time"

	"runpentests/cli/internal/api"
)

// A public target is scanned only after its workspace proves it controls the
// host: a DNS TXT record proves the name, an HTTP token served from the target
// proves the machine. These commands drive the same workspace API the web's
// Workspace → Domains page uses. They never weaken the gate: every run still
// re-proves ownership live, and none of them starts a scan.

var uuidLike = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)

// domainVerifyPoll is how often `domains verify --wait` checks again. DNS
// propagation is minutes, not seconds; a variable so a test need not wait.
var domainVerifyPoll = 30 * time.Second

func cmdDomains(ctx context.Context, e *Env, args []string) int {
	if len(args) == 0 {
		return e.usage("domains needs a subcommand: list | add HOST | verify HOST | check [SCAN] | rm HOST --yes")
	}
	if wantsHelp(args) {
		return e.printCommandHelp("domains", nil)
	}
	switch args[0] {
	case "list":
		return domainsList(ctx, e, args[1:])
	case "add":
		return domainsAdd(ctx, e, args[1:])
	case "verify":
		return domainsVerify(ctx, e, args[1:])
	case "check":
		return domainsCheck(ctx, e, args[1:])
	case "rm":
		return domainsRm(ctx, e, args[1:])
	}
	return e.usage("unknown domains subcommand %q", args[0])
}

// hostAndURL reads a host argument. A URL is accepted for convenience: its
// host is the record, and the URL itself is where verify fetches the token.
func hostAndURL(raw string) (host, fetchURL string) {
	raw = strings.TrimSpace(raw)
	if strings.Contains(raw, "://") {
		if u, err := url.Parse(raw); err == nil && u.Hostname() != "" {
			return u.Hostname(), (&url.URL{Scheme: u.Scheme, Host: u.Host}).String()
		}
	}
	return raw, ""
}

// domainState is a record's state in one word.
func domainState(d api.Domain) string {
	switch {
	case d.VerifiedAt != nil && *d.VerifiedAt != "":
		return "verified"
	case d.LastCheckedAt != nil && *d.LastCheckedAt != "":
		return "failed"
	}
	return "pending"
}

// findDomain resolves a host or a record ID to the workspace's record. The
// server normalises the host (IDNA, case, trailing dot); an older server that
// ignores the filter is matched on the plain lower-case spelling instead.
func findDomain(ctx context.Context, e *Env, c *api.Client, ref string) (api.Domain, int) {
	if uuidLike.MatchString(ref) {
		all, err := c.Domains(ctx, "")
		if err != nil {
			return api.Domain{}, e.exitFor(err)
		}
		for _, d := range all {
			if strings.EqualFold(d.ID, ref) {
				return d, ExitOK
			}
		}
		return api.Domain{}, e.usage("no domain with ID %s in this workspace (see `runpentests domains list`)", ref)
	}
	host, _ := hostAndURL(ref)
	found, err := c.Domains(ctx, host)
	if err != nil {
		return api.Domain{}, e.exitFor(err)
	}
	plain := strings.TrimSuffix(strings.ToLower(host), ".")
	for _, d := range found {
		if d.Host == plain {
			return d, ExitOK
		}
	}
	// A non-ASCII name is stored in its punycode spelling, which only the
	// server computes: its filtered answer is the one record for that name.
	if !isASCII(plain) && len(found) == 1 && strings.Contains(found[0].Host, "xn--") {
		return found[0], ExitOK
	}
	return api.Domain{}, e.usage("%s is not listed in this workspace: add it with `runpentests domains add %s`",
		printable(host), printable(host))
}

func isASCII(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] >= 0x80 {
			return false
		}
	}
	return true
}

func domainsList(ctx context.Context, e *Env, args []string) int {
	fs := e.newFlagSet("domains list")
	asJSON := fs.Bool("json", false, "print JSON")
	pos, err := parse(fs, args)
	if err != nil {
		return e.parseFailed("domains", fs, err)
	}
	if len(pos) != 0 {
		return e.usage("domains list takes no arguments")
	}
	c, err := e.client()
	if err != nil {
		return e.usage("%v", err)
	}
	// Listing reads what is recorded; it never runs a check.
	all, err := c.Domains(ctx, "")
	if err != nil {
		return e.exitFor(err)
	}
	if *asJSON {
		return printJSON(e, all)
	}
	if len(all) == 0 {
		e.printf("no domains in this workspace (add one with `runpentests domains add HOST`)\n")
		return ExitOK
	}
	e.printf("%-40s  %-9s  %-16s  %s\n", "HOST", "STATE", "LAST CHECKED", "LAST ERROR")
	for _, d := range all {
		checked := "-"
		if d.LastCheckedAt != nil {
			checked = localStamp(*d.LastCheckedAt)
		}
		lastErr := "-"
		if d.LastError != nil && *d.LastError != "" {
			lastErr = printable(*d.LastError)
		}
		e.printf("%-40s  %-9s  %-16s  %s\n", printable(d.Host), domainState(d), checked, lastErr)
	}
	return ExitOK
}

func domainsAdd(ctx context.Context, e *Env, args []string) int {
	fs := e.newFlagSet("domains add")
	asJSON := fs.Bool("json", false, "print JSON")
	pos, err := parse(fs, args)
	if err != nil {
		return e.parseFailed("domains", fs, err)
	}
	if len(pos) != 1 {
		return e.usage("domains add needs exactly one host, such as api.example.com")
	}
	host, _ := hostAndURL(pos[0])
	c, err := e.client()
	if err != nil {
		return e.usage("%v", err)
	}
	d, err := c.AddDomain(ctx, host)
	if err != nil {
		var apiErr *api.APIError
		if errors.As(err, &apiErr) && apiErr.Status == 409 {
			e.errorf("hint: it is already listed — `runpentests domains verify %s` checks it\n", printable(host))
		}
		return e.domainErr(err)
	}
	if *asJSON {
		return printJSON(e, d)
	}
	printDomainInstructions(e, d)
	return ExitOK
}

// printDomainInstructions says exactly what to publish, from the server's own
// answer: the record name and value, and the token's path and body.
func printDomainInstructions(e *Env, d api.Domain) {
	e.printf("listed %s — publish both proofs, then verify:\n\n", printable(d.Host))
	if d.DNSRecordName != nil {
		e.printf("1. DNS: a TXT record\n     name:  %s\n     value: %s\n\n",
			printable(*d.DNSRecordName), printable(d.DNSRecordValue))
	} else {
		e.printf("1. DNS: none — %s is an IP address, which has no name to prove\n\n", printable(d.Host))
	}
	e.printf("2. HTTP: serve this body with status 200\n     path:  %s\n     body:  %s\n     check: %s\n\n",
		printable(d.HTTPPath), printable(d.Token), printable(d.HTTPURL))
	e.printf("then: runpentests domains verify %s\n", printable(d.Host))
	e.printf("(DNS changes can take minutes to propagate; add --wait 10m to keep checking)\n")
}

func domainsVerify(ctx context.Context, e *Env, args []string) int {
	fs := e.newFlagSet("domains verify")
	asJSON := fs.Bool("json", false, "print JSON")
	fetch := fs.String("url", "", "where to fetch the HTTP token (default https://HOST); must be on the same host")
	wait := fs.Duration("wait", 0, "keep checking until verified or this long has passed (max 1h)")
	pos, err := parse(fs, args)
	if err != nil {
		return e.parseFailed("domains", fs, err)
	}
	if len(pos) != 1 {
		return e.usage("domains verify needs exactly one host or domain ID")
	}
	if *wait < 0 || *wait > time.Hour {
		return e.usage("--wait must be between 0 and 1h")
	}
	_, fromArg := hostAndURL(pos[0])
	fetchURL := *fetch
	if fetchURL == "" {
		fetchURL = fromArg
	}
	c, err := e.client()
	if err != nil {
		return e.usage("%v", err)
	}
	d, code := findDomain(ctx, e, c, pos[0])
	if code != ExitOK {
		return code
	}
	now := e.Now
	if now == nil {
		now = time.Now
	}
	deadline := now().Add(*wait)
	for {
		// Each round is one explicit verify call: the server runs both proofs.
		d, err = c.VerifyDomain(ctx, d.ID, fetchURL)
		if err != nil {
			return e.domainErr(err)
		}
		verified := domainState(d) == "verified"
		if ctx.Err() != nil && !verified {
			e.errorf("interrupted; %s is not verified yet\n", printable(d.Host))
			return ExitFailed
		}
		if verified || *wait == 0 || now().After(deadline) {
			if *asJSON {
				printJSON(e, map[string]any{"domain": d, "state": domainState(d)})
			} else {
				printVerifyResult(e, d)
			}
			switch {
			case verified:
				return ExitOK
			case *wait > 0:
				e.errorf("still not verified after %s\n", *wait)
				return ExitTimeout
			}
			return ExitUsage
		}
		e.errorf("not verified yet (%s); checking again in %s\n", lastErrorOr(d, "pending"), domainVerifyPoll)
		select {
		case <-ctx.Done():
		case <-time.After(domainVerifyPoll):
		}
	}
}

func lastErrorOr(d api.Domain, fallback string) string {
	if d.LastError != nil && *d.LastError != "" {
		return printable(*d.LastError)
	}
	return fallback
}

func printVerifyResult(e *Env, d api.Domain) {
	for _, p := range d.LastChecks {
		mark, detail := "✓", ""
		if !p.OK {
			mark = "✗"
			if p.Detail != nil {
				detail = " — " + printable(*p.Detail)
			}
		}
		e.printf("%s %-4s%s\n", mark, strings.ToUpper(printable(p.Proof)), detail)
	}
	if domainState(d) == "verified" {
		e.printf("%s is verified; scans of it may run (each run still re-proves it)\n", printable(d.Host))
		return
	}
	e.printf("%s is not verified: %s\n", printable(d.Host), lastErrorOr(d, "no proof passed"))
	e.printf("fix what failed above, then run `runpentests domains verify %s` again\n", printable(d.Host))
}

// domainsCheck answers the scan's ownership question without contacting the
// target: whether a run needs proof, why not, or what to do next.
func domainsCheck(ctx context.Context, e *Env, args []string) int {
	fs := e.newFlagSet("domains check")
	asJSON := fs.Bool("json", false, "print JSON")
	pos, err := parse(fs, args)
	if err != nil {
		return e.parseFailed("domains", fs, err)
	}
	if len(pos) > 1 {
		return e.usage("domains check takes at most one scan ID")
	}
	c, err := e.client()
	if err != nil {
		return e.usage("%v", err)
	}
	id, code := resolveScan(ctx, e, c, argOrEmpty(pos), true)
	if code != ExitOK {
		return code
	}
	o, err := c.Ownership(ctx, id)
	if err != nil {
		return e.exitFor(err)
	}
	if *asJSON {
		return printJSON(e, o)
	}
	return printOwnership(e, o)
}

// printOwnership explains an ownership answer and returns ExitOK when a run
// would pass the ownership gate as recorded now, ExitUsage otherwise.
func printOwnership(e *Env, o api.Ownership) int {
	host := printable(o.Host)
	switch {
	case !o.Allowed:
		e.printf("%s cannot be scanned from this server: %s\n", host, printable(deref(o.Reason)))
		return ExitUsage
	case !o.Required:
		why := map[string]string{
			"private":   "it resolves only to private addresses",
			"allowlist": "the operator allowlisted it",
			"disabled":  "ownership verification is off on this server",
		}[deref(o.Exempt)]
		if why == "" {
			why = printable(deref(o.Exempt))
		}
		e.printf("%s needs no ownership proof: %s\n", host, why)
		return ExitOK
	case o.DomainID == nil:
		e.printf("%s is public, so this workspace must prove it controls it before scanning.\n", host)
		e.printf("next: runpentests domains add %s   (a workspace admin)\n", host)
		return ExitUsage
	case o.VerifiedAt == nil:
		e.printf("%s is listed but not verified: %s\n", host, printable(deref(o.LastError)))
		e.printf("next: runpentests domains verify %s   (a workspace admin)\n", host)
		return ExitUsage
	}
	e.printf("%s is verified for this workspace; each run re-proves it live\n", host)
	return ExitOK
}

func domainsRm(ctx context.Context, e *Env, args []string) int {
	fs := e.newFlagSet("domains rm")
	yes := fs.Bool("yes", false, "do not ask for confirmation")
	pos, err := parse(fs, args)
	if err != nil {
		return e.parseFailed("domains", fs, err)
	}
	if len(pos) != 1 {
		return e.usage("domains rm needs exactly one host or domain ID")
	}
	c, err := e.client()
	if err != nil {
		return e.usage("%v", err)
	}
	d, code := findDomain(ctx, e, c, pos[0])
	if code != ExitOK {
		return code
	}
	if !*yes {
		if !e.IsTTY() {
			return e.usage("refusing to remove without --yes (no terminal to confirm on)")
		}
		e.errorf("Remove %s? Scans of it will need ownership proof again. Type y to confirm: ", printable(d.Host))
		line, _ := e.readLine()
		if strings.ToLower(strings.TrimSpace(line)) != "y" {
			e.errorf("not removed\n")
			return ExitUsage
		}
	}
	if err := c.DeleteDomain(ctx, d.ID); err != nil {
		return e.domainErr(err)
	}
	e.printf("removed %s\n", printable(d.Host))
	return ExitOK
}

// domainErr adds the one hint a domain call needs beyond exitFor's: adding,
// verifying and removing are workspace-admin actions.
func (e *Env) domainErr(err error) int {
	var apiErr *api.APIError
	if errors.As(err, &apiErr) && apiErr.Status == 403 {
		e.errorf("hint: adding, verifying and removing domains needs a workspace admin's key\n")
	}
	return e.exitFor(err)
}

// ownershipHint follows a run the server refused for an unproven target with
// the exact next step. Advisory, best effort: the refusal already printed.
func ownershipHint(ctx context.Context, e *Env, c *api.Client, scanID string, err error) {
	var apiErr *api.APIError
	if !errors.As(err, &apiErr) || apiErr.Status != 422 || !strings.HasPrefix(apiErr.Detail, "target not verified") {
		return
	}
	o, oerr := c.Ownership(ctx, scanID)
	if oerr != nil {
		e.errorf("hint: prove this workspace controls the target with `runpentests domains add HOST` " +
			"and `runpentests domains verify HOST`\n")
		return
	}
	e.errorf("hint: ")
	printOwnershipTo(e, o)
}

// printOwnershipTo prints the ownership explanation on stderr.
func printOwnershipTo(e *Env, o api.Ownership) {
	saved := e.Stdout
	e.Stdout = e.Stderr
	defer func() { e.Stdout = saved }()
	printOwnership(e, o)
}
