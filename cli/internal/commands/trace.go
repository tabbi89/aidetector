package commands

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"strconv"
	"strings"

	"runpentests/cli/internal/api"
)

const (
	tracePageSize = 500 // the server's per-page maximum
	maxTracePages = 20  // a trace longer than this is not a terminal's job
	traceRouteCol = 70  // route column width, in runes
)

// cmdRunTrace prints a run's request/response log: a filterable table, or one
// request in full. The bodies, routes and headers came from the scanned
// target, so text output goes through printable before it reaches a terminal.
func cmdRunTrace(ctx context.Context, e *Env, args []string) int {
	fs := e.newFlagSet("runs trace")
	check := fs.String("check", "", "only requests from this check")
	identity := fs.String("identity", "", "only requests sent as this identity")
	status := fs.String("status", "", "only this status code (403), class (2xx/3xx/4xx/5xx), or error (no response)")
	method := fs.String("method", "", "only this HTTP method")
	route := fs.String("route", "", "only routes containing this substring")
	limit := fs.Int("limit", 50, "how many rows to print (1-1000)")
	seq := fs.Int("seq", 0, "print one request in full, by its sequence number")
	asJSON := fs.Bool("json", false, "print the rows as JSON")
	pos, err := parse(fs, args)
	if err != nil {
		return e.parseFailed("runs", fs, err)
	}
	if len(pos) > 2 {
		return e.usage("runs trace takes a scan ID and a run number")
	}
	if *limit < 1 || *limit > 1000 {
		return e.usage("--limit must be between 1 and 1000")
	}
	if *seq < 0 {
		return e.usage("--seq must be a positive request sequence number")
	}
	statusMatch, err := traceStatusMatcher(*status)
	if err != nil {
		return e.usage("%v", err)
	}

	// Two positionals are scan and run. One that parses as a positive integer
	// is the run on the project's scan; anything else is the scan, latest run.
	var scanRef, runArg string
	switch len(pos) {
	case 1:
		if n, err := strconv.Atoi(pos[0]); err == nil && n > 0 {
			runArg = pos[0]
		} else {
			scanRef = pos[0]
		}
	case 2:
		scanRef, runArg = pos[0], pos[1]
	}
	run := 0
	if runArg != "" {
		n, err := strconv.Atoi(runArg)
		if err != nil || n < 1 {
			return e.usage("run number %q is not a positive integer", runArg)
		}
		run = n
	}

	c, err := e.client()
	if err != nil {
		return e.usage("%v", err)
	}
	id, code := resolveScan(ctx, e, c, scanRef, true)
	if code != ExitOK {
		return code
	}
	if run == 0 {
		// The server lists runs newest first (run_number desc), so a page of
		// one is the latest run.
		runs, err := c.Runs(ctx, id, 1)
		if err != nil {
			return e.exitFor(err)
		}
		for _, r := range runs {
			if r.RunNumber > run {
				run = r.RunNumber
			}
		}
		if run == 0 {
			return e.usage("scan %s has no runs", shortID(id))
		}
	}

	rows, total, code := fetchTrace(ctx, e, c, id, run)
	if code != ExitOK {
		return code
	}

	if *seq > 0 {
		for _, r := range rows {
			if r.Sequence != *seq {
				continue
			}
			if *asJSON {
				if r.Raw != nil {
					return printJSON(e, r.Raw)
				}
				return printJSON(e, r)
			}
			printTraceRow(e, r)
			return ExitOK
		}
		return e.usage("run %d has no request #%d in its trace", run, *seq)
	}

	matches := func(r api.MutationRow) bool {
		if *check != "" && !strings.EqualFold(r.Check, *check) {
			return false
		}
		if *identity != "" && !strings.EqualFold(r.Identity, *identity) {
			return false
		}
		if *method != "" && !strings.EqualFold(r.Method, *method) {
			return false
		}
		if *route != "" && !strings.Contains(r.Route, *route) {
			return false
		}
		return statusMatch == nil || statusMatch(r.Response.Status)
	}
	var shown []api.MutationRow
	matched := 0
	for _, r := range rows {
		if !matches(r) {
			continue
		}
		matched++
		if len(shown) < *limit {
			shown = append(shown, r)
		}
	}

	if *asJSON {
		raw := make([]map[string]any, 0, len(shown))
		for _, r := range shown {
			raw = append(raw, r.Raw)
		}
		return printJSON(e, raw)
	}
	e.printf("%-5s  %-7s  %-12s  %7s  %-12s  %-20s  %s\n",
		"SEQ", "METHOD", "STATUS", "MS", "IDENTITY", "CHECK", "ROUTE")
	for _, r := range shown {
		e.printf("%-5d  %-7s  %-12s  %7s  %-12s  %-20s  %s\n",
			r.Sequence, printable(r.Method), traceStatus(r), traceElapsed(r),
			printable(r.Identity), printable(r.Check), truncateRoute(printable(r.Route)))
	}
	// Say both numbers: a filter that matched 40 but printed 5 must not read
	// as "only 5 requests were refused".
	e.printf("%d shown · %d match · %d request(s) in the run\n", len(shown), matched, total)
	if len(shown) > 0 {
		e.errorf("detail: runpentests runs trace %s %d --seq <N>\n", shortID(id), run)
	}
	return ExitOK
}

// fetchTrace reads pages of 500 until the run's trace is exhausted, capped so
// a pathological log cannot make this read forever.
func fetchTrace(ctx context.Context, e *Env, c *api.Client, id string, run int) ([]api.MutationRow, int, int) {
	var rows []api.MutationRow
	total := 0
	offset := 0
	for page := 0; page < maxTracePages; page++ {
		p, err := c.RunTrace(ctx, id, run, offset, tracePageSize)
		if err != nil {
			return nil, 0, e.exitFor(err)
		}
		total = p.Total
		rows = append(rows, p.Rows...)
		offset += len(p.Rows)
		if len(p.Rows) == 0 || offset >= total {
			break
		}
	}
	return rows, total, ExitOK
}

// traceStatusMatcher accepts a code (403), a class (4xx) or "error" (no
// response came back), or nil for "any".
func traceStatusMatcher(s string) (func(*int) bool, error) {
	if s == "" {
		return nil, nil
	}
	if strings.EqualFold(s, "error") {
		return func(st *int) bool { return st == nil }, nil
	}
	if len(s) == 3 && (s[2] == 'x' || s[2] == 'X') && s[0] >= '2' && s[0] <= '5' {
		class := int(s[0] - '0')
		return func(st *int) bool { return st != nil && *st/100 == class }, nil
	}
	n, err := strconv.Atoi(s)
	if err != nil || n < 100 || n > 599 {
		return nil, fmt.Errorf("--status must be a code like 403, a class 2xx/3xx/4xx/5xx, or error")
	}
	return func(st *int) bool { return st != nil && *st == n }, nil
}

// printTraceRow prints one request in full, for --seq.
func printTraceRow(e *Env, r api.MutationRow) {
	e.printf("#%d %s %s\n", r.Sequence, printable(r.Method), printable(r.Route))
	e.printf("%s · %s · %s · %s\n",
		printable(r.Check), printable(r.Identity), printable(r.Pass), traceElapsedMS(r))
	e.printf("request:\n")
	e.printf("  headers: %s\n", headerNames(r.Request.Headers))
	if len(r.Request.QueryFields) > 0 {
		fields := make([]string, len(r.Request.QueryFields))
		for i, f := range r.Request.QueryFields {
			fields[i] = printable(f)
		}
		e.printf("  query: %s\n", strings.Join(fields, ", "))
	}
	if r.Request.JSONBody != "" {
		e.printf("  json_body:\n%s", indentBlock(printable(prettyJSON(r.Request.JSONBody))))
	}
	e.printf("  content_bytes: %d\n", r.Request.ContentBytes)
	e.printf("response:\n")
	e.printf("  status: %s\n", traceStatus(r))
	e.printf("  content_type: %s\n", printable(r.Response.ContentType))
	e.printf("  headers: %s\n", headerNames(r.Response.Headers))
	e.printf("  body_bytes: %d\n", r.Response.BodyBytes)
	if r.Response.Truncated {
		e.printf("  truncated: yes\n")
	}
	if r.Response.BodyOmitted {
		e.printf("  body omitted: yes (not text, or the run's body budget was spent)\n")
	}
	if r.Response.Body != "" {
		e.printf("  body:\n%s", indentBlock(printable(r.Response.Body)))
	}
}

// traceStatus is the response status, or — when none came back — the
// transport failure's class (ReadTimeout, ConnectError) rather than a bare "-".
func traceStatus(r api.MutationRow) string {
	if r.Response.Status == nil {
		if r.Error != nil && *r.Error != "" {
			return printable(*r.Error)
		}
		return "-"
	}
	return strconv.Itoa(*r.Response.Status)
}

func traceElapsed(r api.MutationRow) string {
	if r.ElapsedMS == nil {
		return "-"
	}
	return fmt.Sprintf("%.0f", *r.ElapsedMS)
}

func traceElapsedMS(r api.MutationRow) string {
	if r.ElapsedMS == nil {
		return "-"
	}
	return fmt.Sprintf("%.0fms", *r.ElapsedMS)
}

// headerNames lists header names only: values may hold a credential and are
// not something a trace needs to reprint.
func headerNames(h map[string]string) string {
	if len(h) == 0 {
		return "-"
	}
	names := make([]string, 0, len(h))
	for name := range h {
		names = append(names, printable(name))
	}
	sort.Strings(names)
	return strings.Join(names, ", ")
}

// prettyJSON re-indents a JSON body when it parses; anything else is shown as
// it came.
func prettyJSON(s string) string {
	var v any
	if json.Unmarshal([]byte(s), &v) != nil {
		return s
	}
	data, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return s
	}
	return string(data)
}

// truncateRoute keeps the route column readable in a terminal.
func truncateRoute(s string) string {
	r := []rune(s)
	if len(r) <= traceRouteCol {
		return s
	}
	return string(r[:traceRouteCol-1]) + "…"
}

// printable removes terminal control characters from text that came from the
// scanned target, so a hostile response cannot inject ANSI/OSC sequences into
// the user's terminal. Newline and tab survive because they are layout.
func printable(s string) string {
	return strings.Map(func(r rune) rune {
		if r == '\n' || r == '\t' {
			return r
		}
		if r < 0x20 || r == 0x7f || (r >= 0x80 && r <= 0x9f) {
			return -1
		}
		return r
	}, s)
}
