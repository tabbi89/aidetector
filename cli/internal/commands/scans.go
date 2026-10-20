package commands

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"aidetector/cli/internal/api"
	"aidetector/cli/internal/project"
)

func cmdScans(ctx context.Context, e *Env, args []string) int {
	if len(args) == 0 {
		return e.usage("scans needs a subcommand: list | show [ID] | rm ID --yes")
	}
	if wantsHelp(args) {
		return e.printCommandHelp("scans", nil)
	}
	switch args[0] {
	case "list":
		return scansList(ctx, e, args[1:])
	case "show":
		return scansShow(ctx, e, args[1:])
	case "rm":
		return scansRm(ctx, e, args[1:])
	}
	return e.usage("unknown scans subcommand %q", args[0])
}

func scansList(ctx context.Context, e *Env, args []string) int {
	fs := e.newFlagSet("scans list")
	asJSON := fs.Bool("json", false, "print JSON")
	target := fs.String("target", "", "show only scans for this target URL")
	fullIDs := fs.Bool("full-ids", false, "print the whole scan ID, not its first 8 characters")
	if _, err := parse(fs, args); err != nil {
		return e.parseFailed("scans", fs, err)
	}
	c, err := e.client()
	if err != nil {
		return e.usage("%v", err)
	}
	scans, err := c.ListScans(ctx)
	if err != nil {
		return e.exitFor(err)
	}
	if *target != "" {
		var filtered []api.ScanSummary
		for _, s := range scans {
			if project.SameTarget(s.TargetBaseURL, *target) {
				filtered = append(filtered, s)
			}
		}
		scans = filtered
	}
	if *asJSON {
		return printJSON(e, scans)
	}
	width := 8
	if *fullIDs {
		width = 36
	}
	e.printf("%-*s  %-9s  %4s %4s %4s %4s  %-16s  %s\n",
		width, "ID", "STATUS", "CRIT", "HIGH", "MED", "LOW", "LAST RUN", "TARGET")
	for _, s := range scans {
		id := shortID(s.ID)
		if *fullIDs {
			id = s.ID
		}
		e.printf("%-*s  %-9s  %4d %4d %4d %4d  %-16s  %s\n",
			width, id, s.Status,
			s.FindingCounts.Critical, s.FindingCounts.High,
			s.FindingCounts.Medium, s.FindingCounts.Low,
			formatLastRun(s.LastRunAt), s.TargetBaseURL)
	}
	return ExitOK
}

// formatLastRun renders a timestamp the way a person reads a clock, in local time.
func formatLastRun(v *string) string {
	if v == nil || *v == "" {
		return "-"
	}
	t, err := time.Parse(time.RFC3339, *v)
	if err != nil {
		return *v
	}
	return t.Local().Format("2006-01-02 15:04")
}

func scansShow(ctx context.Context, e *Env, args []string) int {
	fs := e.newFlagSet("scans show")
	asJSON := fs.Bool("json", false, "print JSON")
	pos, err := parse(fs, args)
	if err != nil {
		return e.parseFailed("scans", fs, err)
	}
	if len(pos) > 1 {
		return e.usage("scans show takes at most one scan ID")
	}
	c, err := e.client()
	if err != nil {
		return e.usage("%v", err)
	}
	id, code := resolveScan(ctx, e, c, argOrEmpty(pos), true)
	if code != ExitOK {
		return code
	}
	scan, err := c.GetScan(ctx, id)
	if err != nil {
		return e.exitFor(err)
	}
	if *asJSON {
		return printJSON(e, scan)
	}
	e.printf("id:         %s\ntarget:     %s\nstatus:     %s (%d%%)\noperations: %d\n",
		scan.ID, scan.TargetBaseURL, scan.Status, scan.Progress, len(scan.Operations))
	if scan.FailureReason != nil && *scan.FailureReason != "" {
		e.printf("failure:    %s\n", printable(*scan.FailureReason))
	}
	// The summary is a convenience: a scan is still worth showing when a
	// count query fails, so a read error is a note, not a failed command.
	if s, err := c.FindingSummary(ctx, id); err == nil {
		sev := func(key string) int { return s.Severity[key] }
		e.printf("findings:   %d (%d active, %d dismissed) · critical %d high %d medium %d low %d info %d · verified critical/high %d/%d\n",
			s.Total, s.Active, s.Dismissed,
			sev("critical"), sev("high"), sev("medium"), sev("low"), sev("info"),
			s.VerifiedCritical, s.VerifiedHigh)
	} else {
		e.errorf("findings summary unavailable: %v\n", err)
	}
	e.printf("identities: %d\n", len(scan.CredentialProfiles))
	e.printf("ai spend:   $%.4f\n", scan.CostUSD)
	return ExitOK
}

func scansRm(ctx context.Context, e *Env, args []string) int {
	fs := e.newFlagSet("scans rm")
	yes := fs.Bool("yes", false, "do not ask for confirmation")
	pos, err := parse(fs, args)
	if err != nil {
		return e.parseFailed("scans", fs, err)
	}
	if len(pos) != 1 {
		return e.usage("scans rm needs exactly one scan ID")
	}
	c, err := e.client()
	if err != nil {
		return e.usage("%v", err)
	}
	id, code := resolveScan(ctx, e, c, pos[0], false)
	if code != ExitOK {
		return code
	}
	// A prefix is fine when the prompt shows what it resolved to; an unattended
	// delete must name the scan in full, so a short typo cannot erase another.
	if *yes && id != pos[0] {
		return e.usage("scans rm --yes needs the full scan ID (%q is %s)", pos[0], id)
	}
	// Deleting is permanent: ask unless told not to, and never guess in a pipe.
	if !*yes {
		if !e.IsTTY() {
			return e.usage("refusing to delete without --yes (no terminal to confirm on)")
		}
		e.errorf("Delete scan %s and all of its data? Type y to confirm: ", id)
		line, _ := e.readLine()
		if strings.ToLower(strings.TrimSpace(line)) != "y" {
			e.errorf("not deleted\n")
			return ExitUsage
		}
	}
	if err := c.DeleteScan(ctx, id); err != nil {
		return e.exitFor(err)
	}
	e.printf("deleted %s\n", id)
	return ExitOK
}

func cmdScan(ctx context.Context, e *Env, args []string) int {
	if len(args) == 0 || args[0] != "create" {
		if wantsHelp(args) {
			return e.printCommandHelp("scan", nil)
		}
		return e.usage("scan needs a subcommand: create --target URL --spec FILE")
	}
	fs := e.newFlagSet("scan create")
	target := fs.String("target", "", "base URL of the API to test")
	spec := fs.String("spec", "", "OpenAPI/Swagger/HAR/Postman file to ingest")
	if _, err := parse(fs, args[1:]); err != nil {
		return e.parseFailed("scan", fs, err)
	}
	if *target == "" || *spec == "" {
		return e.usage("scan create needs --target URL and --spec FILE")
	}
	content, err := os.ReadFile(*spec)
	if err != nil {
		return e.usage("cannot read spec: %v", err)
	}
	c, err := e.client()
	if err != nil {
		return e.usage("%v", err)
	}
	scan, err := c.CreateScan(ctx, *target)
	if err != nil {
		return e.exitFor(err)
	}
	withSpec, err := c.UploadSpec(ctx, scan.ID, string(content))
	if err != nil {
		// Don't leave an empty scan behind that the user never asked to keep.
		_ = c.DeleteScan(ctx, scan.ID)
		return e.exitFor(err)
	}
	e.printf("%s\n", withSpec.ID)
	e.errorf("created scan for %s with %d operations\n", withSpec.TargetBaseURL, len(withSpec.Operations))
	return ExitOK
}

func cmdCred(ctx context.Context, e *Env, args []string) int {
	if wantsHelp(args) {
		return e.printCommandHelp("cred", nil)
	}
	if len(args) == 0 {
		return e.usage("cred needs a subcommand: add | list | rm")
	}
	switch args[0] {
	case "add":
		return credAdd(ctx, e, args[1:])
	case "list":
		return credList(ctx, e, args[1:])
	case "rm":
		return credRm(ctx, e, args[1:])
	}
	return e.usage("unknown cred subcommand %q", args[0])
}

func credAdd(ctx context.Context, e *Env, args []string) int {
	fs := e.newFlagSet("cred add")
	name := fs.String("name", "", "a label for this identity")
	role := fs.String("role", "", "the role it plays, e.g. user or admin")
	authType := fs.String("auth-type", "bearer", "bearer | header | api_key | basic | query | cookie | none")
	header := fs.String("header-name", "", "header, query parameter or cookie to send the secret in (header/api_key/query/cookie)")
	privilege := fs.Int("privilege", -1, "explicit privilege, 0 lowest … 3 highest (default: from the role name)")
	updateFlag := fs.Bool("update", false, "update the identity with this name instead of failing when it exists")
	secretStdin := fs.Bool("secret-stdin", false, "read the secret from stdin (one line)")
	localOnly := fs.Bool("local-only", false, "keep the secret on this machine: only `run --local` can use the identity")
	pos, err := parse(fs, args)
	if err != nil {
		return e.parseFailed("cred", fs, err)
	}
	if len(pos) != 1 || *name == "" || *role == "" {
		return e.usage("cred add needs a scan ID, --name and --role")
	}
	if *localOnly && *secretStdin {
		return e.usage("--local-only sends no secret; drop --secret-stdin (a local run reads it here)")
	}
	if *privilege != -1 && (*privilege < 0 || *privilege > project.MaxRank) {
		return e.usage("--privilege must be from 0 (lowest) to %d (highest)", project.MaxRank)
	}

	// The secret is never a flag: it would land in shell history and ps output.
	var secret string
	switch {
	case *localOnly, *authType == "none":
	case *secretStdin:
		if secret, err = e.readLine(); err != nil || secret == "" {
			return e.usage("--secret-stdin: expected the secret on one line of stdin")
		}
	case e.IsTTY():
		if secret, err = e.ReadSecret("Secret (input hidden): "); err != nil || secret == "" {
			return e.usage("no secret entered")
		}
	default:
		return e.usage("no terminal to prompt on: pass --secret-stdin")
	}

	cred := api.Credential{Name: *name, Role: *role, AuthType: *authType, Secret: secret, LocalOnly: *localOnly}
	if *authType == "none" && !*localOnly {
		// The server requires a value for a stored identity; "none" never sends it.
		cred.Secret = "-"
	}
	if *header != "" {
		cred.HeaderName = header
	}
	if *privilege >= 0 {
		cred.Privilege = privilege
	}
	c, err := e.client()
	if err != nil {
		return e.usage("%v", err)
	}
	id, code := resolveScan(ctx, e, c, pos[0], false)
	if code != ExitOK {
		return code
	}
	if err := c.AddCredential(ctx, id, cred); err != nil {
		if *updateFlag && isConflict(err) {
			return updateExistingCredential(ctx, e, c, id, cred, err)
		}
		return e.exitFor(err)
	}
	where := ""
	if *localOnly {
		where = ", local-only: its secret stays here"
	}
	e.printf("added credential %q (%s%s)\n", *name, *role, where)
	return ExitOK
}

// updateExistingCredential is `cred add --update`: an identity with that name
// already exists, so PATCH its shape instead of leaving the add refused.
func updateExistingCredential(ctx context.Context, e *Env, c *api.Client, scanID string,
	cred api.Credential, addErr error) int {
	scan, err := c.GetScan(ctx, scanID)
	if err != nil {
		return e.exitFor(err)
	}
	var existing *api.CredentialProfile
	for i := range scan.CredentialProfiles {
		if scan.CredentialProfiles[i].Name == cred.Name {
			existing = &scan.CredentialProfiles[i]
			break
		}
	}
	if existing == nil {
		return e.exitFor(addErr)
	}
	update := api.CredentialUpdate{Name: cred.Name, Role: cred.Role, AuthType: cred.AuthType,
		HeaderName: cred.HeaderName, Privilege: cred.Privilege}
	if cred.Secret != "" {
		secret := cred.Secret
		update.Secret = &secret
	}
	if err := c.UpdateCredential(ctx, scanID, existing.ID, update); err != nil {
		return e.exitFor(err)
	}
	e.printf("updated credential %q (%s)\n", cred.Name, cred.Role)
	return ExitOK
}

// isConflict reports a 409, which for `cred add` means the name is taken.
func isConflict(err error) bool {
	var apiErr *api.APIError
	return errors.As(err, &apiErr) && apiErr.Status == 409
}

func credList(ctx context.Context, e *Env, args []string) int {
	fs := e.newFlagSet("cred list")
	asJSON := fs.Bool("json", false, "print JSON")
	pos, err := parse(fs, args)
	if err != nil {
		return e.parseFailed("cred", fs, err)
	}
	if len(pos) > 1 {
		return e.usage("cred list takes at most one scan ID")
	}
	c, err := e.client()
	if err != nil {
		return e.usage("%v", err)
	}
	id, code := resolveScan(ctx, e, c, argOrEmpty(pos), true)
	if code != ExitOK {
		return code
	}
	scan, err := c.GetScan(ctx, id)
	if err != nil {
		return e.exitFor(err)
	}
	if *asJSON {
		return printJSON(e, scan.CredentialProfiles)
	}
	e.printf("%-20s  %-8s  %-8s  %-16s  %-4s  %-6s  %s\n",
		"NAME", "ROLE", "AUTH", "HEADER", "PRIV", "SECRET", "ID")
	for _, p := range scan.CredentialProfiles {
		header := "-"
		if p.HeaderName != nil && *p.HeaderName != "" {
			header = *p.HeaderName
		}
		// An explicit privilege shows its number; null is inferred from the role.
		priv := "-"
		if p.Privilege != nil {
			priv = strconv.Itoa(*p.Privilege)
		}
		// Where the secret lives decides which runs can use the identity.
		where := "server"
		if p.LocalOnly {
			where = "local"
		}
		e.printf("%-20s  %-8s  %-8s  %-16s  %-4s  %-6s  %s\n",
			p.Name, p.Role, p.AuthType, header, priv, where, shortID(p.ID))
	}
	return ExitOK
}

func credRm(ctx context.Context, e *Env, args []string) int {
	fs := e.newFlagSet("cred rm")
	yes := fs.Bool("yes", false, "do not ask for confirmation")
	pos, err := parse(fs, args)
	if err != nil {
		return e.parseFailed("cred", fs, err)
	}
	if len(pos) != 2 {
		return e.usage("cred rm needs a scan ID and an identity name or ID")
	}
	c, err := e.client()
	if err != nil {
		return e.usage("%v", err)
	}
	scanID, code := resolveScan(ctx, e, c, pos[0], false)
	if code != ExitOK {
		return code
	}
	scan, err := c.GetScan(ctx, scanID)
	if err != nil {
		return e.exitFor(err)
	}
	cred, code := matchCredential(e, scan.CredentialProfiles, pos[1])
	if code != ExitOK {
		return code
	}
	// Removing an identity changes what the authorization checks can test.
	if !*yes {
		if !e.IsTTY() {
			return e.usage("refusing to remove an identity without --yes (no terminal to confirm on)")
		}
		e.errorf("Remove identity %s from scan %s? Type y to confirm: ", cred.Name, shortID(scanID))
		line, _ := e.readLine()
		if strings.ToLower(strings.TrimSpace(line)) != "y" {
			e.errorf("not removed\n")
			return ExitUsage
		}
	}
	if err := c.DeleteCredential(ctx, scanID, cred.ID); err != nil {
		return e.exitFor(err)
	}
	e.printf("removed identity %s\n", cred.Name)
	return ExitOK
}

// matchCredential finds an identity by exact name, then by ID prefix.
func matchCredential(e *Env, creds []api.CredentialProfile, ref string) (api.CredentialProfile, int) {
	for _, p := range creds {
		if p.Name == ref {
			return p, ExitOK
		}
	}
	lower := strings.ToLower(ref)
	if !idPrefix.MatchString(lower) {
		return api.CredentialProfile{}, e.usage("%q is not an identity name or ID prefix", ref)
	}
	var matches []api.CredentialProfile
	for _, p := range creds {
		if strings.HasPrefix(strings.ToLower(p.ID), lower) {
			matches = append(matches, p)
		}
	}
	switch len(matches) {
	case 0:
		return api.CredentialProfile{}, e.usage("no identity matches %q", ref)
	case 1:
		return matches[0], ExitOK
	}
	return api.CredentialProfile{}, e.usage("%q matches %d identities; use more characters", ref, len(matches))
}

func printJSON(e *Env, v any) int {
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return e.usage("%v", err)
	}
	fmt.Fprintln(e.Stdout, string(b))
	return ExitOK
}
