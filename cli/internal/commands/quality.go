package commands

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"

	"runpentests/cli/internal/api"
)

// Execution quality: did the run actually test the API? An empty findings list
// means "clean" only when the run reached the endpoints and they answered.
// A run whose every request came back 401 or 404 finds nothing too, and a
// pipeline gated on findings alone passes it. This is the second half of the
// gate: opt-in (--require-complete, --min-exercised), judged on the run's own
// coverage and gaps, never on request or finding counts.

// Endpoint states, from one coverage row.
const (
	endpointExercised  = "exercised"   // answered at least one 2xx
	endpointNo2xx      = "no_2xx"      // answered, but never with a 2xx (auth, path or body was wrong)
	endpointNoResponse = "no_response" // requests went out, nothing came back
	endpointUntested   = "untested"    // in scope, no request was sent
	endpointUnknown    = "unknown"     // the run predates response outcomes
	endpointExcluded   = "excluded"    // opted out of the scan
)

// Quality statuses.
const (
	qualityPass         = "pass"
	qualityFail         = "fail"
	qualityUnknown      = "unknown"       // no policy asked, and the data cannot say
	qualityNotEvaluated = "not_evaluated" // no policy asked; informational only
)

// qualityCaveat is printed with every summary: being answered is not being safe.
const qualityCaveat = "exercised means the endpoint answered at least one request with a 2xx; " +
	"it does not mean every check ran there or that the endpoint is safe"

// qualityPolicy is what the pipeline asked for. The zero value asks nothing.
type qualityPolicy struct {
	// RequireComplete fails a run that did not do what it was asked: a check
	// that did not finish, a requested tool that did not run, an exhausted
	// request budget, an identity left out, or nothing exercised at all.
	RequireComplete bool `json:"require_complete"`
	// MinExercised (1-100) fails a run that exercised a smaller share of its
	// in-scope endpoints. Zero is off.
	MinExercised int `json:"min_exercised"`
}

func (p qualityPolicy) active() bool { return p.RequireComplete || p.MinExercised > 0 }

// exercisedShare is the endpoint arithmetic, with its parts shown.
type exercisedShare struct {
	Exercised int `json:"exercised"`
	// InScope is the enabled endpoints of the run: the denominator.
	InScope int `json:"in_scope"`
	// Percent is nil when it cannot be computed: no in-scope endpoint, or a run
	// that did not record response outcomes. Unknown is never 100%.
	Percent  *float64 `json:"percent"`
	Excluded int      `json:"excluded"`
}

// runQuality is the assessment of one run, in a shape CI can rely on.
type runQuality struct {
	Status    string         `json:"status"`
	Run       int            `json:"run"`
	RunStatus string         `json:"run_status"`
	Share     exercisedShare `json:"exercised"`
	// Endpoints counts in-scope endpoints by state.
	Endpoints map[string]int `json:"endpoints"`
	// Complete is nil when completeness cannot be judged (no run).
	Complete *bool `json:"complete"`
	// Incomplete says what the run was asked to do and did not.
	Incomplete []string `json:"incomplete"`
	// Notes are not failures: checks with nothing to test in this API.
	Notes    []string      `json:"notes"`
	Policy   qualityPolicy `json:"policy"`
	Failures []string      `json:"failures"`
	Caveat   string        `json:"caveat"`
}

// endpointState names what one coverage row says about its endpoint.
func endpointState(r api.CoverageRow) string {
	switch {
	case !r.Enabled:
		return endpointExcluded
	case r.Exercised == nil:
		if r.Requests == 0 {
			return endpointUntested
		}
		return endpointUnknown
	case *r.Exercised:
		return endpointExercised
	case r.Requests == 0:
		return endpointUntested
	case r.Responses != nil && *r.Responses == 0:
		return endpointNoResponse
	default:
		return endpointNo2xx
	}
}

// assessQuality judges a run from its record and coverage. Pure.
func assessQuality(run *api.ScanRun, rows []api.CoverageRow, policy qualityPolicy) runQuality {
	q := runQuality{
		Endpoints: map[string]int{
			endpointExercised: 0, endpointNo2xx: 0, endpointNoResponse: 0,
			endpointUntested: 0, endpointUnknown: 0,
		},
		Incomplete: []string{}, Notes: []string{}, Failures: []string{},
		Policy: policy, Caveat: qualityCaveat,
	}
	if run == nil {
		q.Status = qualityUnknown
		q.Incomplete = append(q.Incomplete, "the scan has no finished run to judge")
		return finishQuality(q, policy)
	}
	q.Run, q.RunStatus = run.RunNumber, run.Status

	for _, r := range rows {
		state := endpointState(r)
		if state == endpointExcluded {
			q.Share.Excluded++
			continue
		}
		q.Share.InScope++
		q.Endpoints[state]++
	}
	q.Share.Exercised = q.Endpoints[endpointExercised]
	if q.Share.InScope > 0 && q.Endpoints[endpointUnknown] == 0 {
		pct := 100 * float64(q.Share.Exercised) / float64(q.Share.InScope)
		q.Share.Percent = &pct
	}

	complete := true
	add := func(format string, a ...any) {
		complete = false
		q.Incomplete = append(q.Incomplete, fmt.Sprintf(format, a...))
	}
	if run.Status != "completed" {
		add("run %d ended %s", run.RunNumber, run.Status)
	}
	if len(run.Gaps.FailedChecks) > 0 {
		add("did not finish: %s", printableList(run.Gaps.FailedChecks))
	}
	if len(run.Gaps.NotRun) > 0 {
		add("requested but did not run: %s", printableList(run.Gaps.NotRun))
	}
	if run.Gaps.BudgetExhausted {
		add("the request budget ran out before every check finished")
	}
	if len(run.Gaps.IdentitiesMissing) > 0 {
		add("identities left out of the run: %s", printableList(run.Gaps.IdentitiesMissing))
	}
	switch {
	case q.Share.InScope == 0 && len(rows) == 0:
		add("the run recorded no endpoint coverage")
	case q.Share.InScope == 0:
		add("every endpoint was excluded")
	case q.Share.Percent != nil && q.Share.Exercised == 0:
		// The all-401 / all-404 / unreachable run: nothing in it was a test.
		add("no in-scope endpoint answered with a 2xx (%d no 2xx, %d no response, %d untested)",
			q.Endpoints[endpointNo2xx], q.Endpoints[endpointNoResponse], q.Endpoints[endpointUntested])
	case q.Share.Exercised == 0 && q.Endpoints[endpointUnknown] > 0:
		// A run recorded without response outcomes: an all-401 run looks the
		// same, so "complete" cannot be claimed for it.
		add("whether any endpoint answered with a 2xx is unknown: the run did not record response outcomes")
	}
	q.Complete = &complete
	if len(run.Gaps.SkippedChecks) > 0 {
		q.Notes = append(q.Notes, fmt.Sprintf("%d check(s) had nothing to test in this API: %s",
			len(run.Gaps.SkippedChecks), printableList(run.Gaps.SkippedChecks)))
	}
	return finishQuality(q, policy)
}

// finishQuality applies the policy. With no policy the status only describes.
func finishQuality(q runQuality, policy qualityPolicy) runQuality {
	if policy.RequireComplete {
		switch {
		case q.Complete == nil:
			q.Failures = append(q.Failures, "completeness is unknown")
		case !*q.Complete:
			q.Failures = append(q.Failures, "the run is incomplete")
		}
	}
	if policy.MinExercised > 0 {
		switch {
		case q.Share.Percent == nil:
			// Strict policy never counts unknown as covered.
			q.Failures = append(q.Failures, fmt.Sprintf(
				"exercised share is unknown (needed %d%%)", policy.MinExercised))
		case *q.Share.Percent < float64(policy.MinExercised):
			q.Failures = append(q.Failures, fmt.Sprintf("%s exercised, below the required %d%%",
				shareLabel(q.Share), policy.MinExercised))
		}
	}
	switch {
	case len(q.Failures) > 0:
		q.Status = qualityFail
	case policy.active():
		q.Status = qualityPass
	case q.Status == "":
		q.Status = qualityNotEvaluated
	}
	return q
}

// shareLabel is "8/10 (80%)", or "8/10 (unknown)" when it cannot be computed.
func shareLabel(s exercisedShare) string {
	if s.Percent == nil {
		return fmt.Sprintf("%d/%d (unknown)", s.Exercised, s.InScope)
	}
	return fmt.Sprintf("%d/%d (%.0f%%)", s.Exercised, s.InScope, *s.Percent)
}

func printableList(items []string) string {
	out := make([]string, len(items))
	for i, s := range items {
		out[i] = printable(s)
	}
	sort.Strings(out)
	return strings.Join(out, ", ")
}

// loadQuality fetches a run (0: the newest) and its coverage, and judges it.
// An older server without the single-run route falls back to the run list.
func loadQuality(ctx context.Context, c *api.Client, id string, runNumber int, policy qualityPolicy) (runQuality, error) {
	run, err := fetchRun(ctx, c, id, runNumber)
	if err != nil {
		return runQuality{}, err
	}
	if run == nil {
		return assessQuality(nil, nil, policy), nil
	}
	rows := run.Coverage
	if rows == nil {
		if rows, err = c.Coverage(ctx, id, run.RunNumber); err != nil {
			return runQuality{}, err
		}
	}
	return assessQuality(run, rows, policy), nil
}

// fetchRun returns run runNumber of the scan (0: the newest), or nil when the
// scan has none.
func fetchRun(ctx context.Context, c *api.Client, id string, runNumber int) (*api.ScanRun, error) {
	if runNumber > 0 {
		run, err := c.Run(ctx, id, runNumber)
		if err == nil {
			return &run, nil
		}
		var apiErr *api.APIError
		if !errors.As(err, &apiErr) || apiErr.Status != 404 || apiErr.Detail != "Not Found" {
			return nil, err
		}
		// FastAPI's bare "Not Found": an older server without the route.
	}
	// The newest run is the first of a page of one; a named run on an older
	// server without the single-run route needs the history to find it.
	limit := 1
	if runNumber > 0 {
		limit = 200
	}
	runs, err := c.Runs(ctx, id, limit)
	if err != nil {
		return nil, err
	}
	for i := range runs {
		if runNumber == 0 || runs[i].RunNumber == runNumber {
			return &runs[i], nil
		}
	}
	if runNumber > 0 {
		return nil, fmt.Errorf("run %d of scan %s not found", runNumber, shortID(id))
	}
	return nil, nil
}

// printQualitySummary writes the human summary. w is stdout in a gate's table
// and stderr after an everyday scan, where stdout is the findings table.
func printQualitySummary(write func(string, ...any), q runQuality) {
	head := "scan quality"
	switch q.Status {
	case qualityPass:
		head += ": PASS"
	case qualityFail:
		head += ": FAIL"
	case qualityUnknown:
		head += ": unknown"
	}
	if q.Run > 0 {
		head += fmt.Sprintf(" (run %d)", q.Run)
	}
	write("%s\n", head)
	if q.Share.InScope > 0 || q.Share.Excluded > 0 {
		write("  endpoints exercised: %s", shareLabel(q.Share))
		if q.Share.Excluded > 0 {
			write(", %d excluded", q.Share.Excluded)
		}
		write("\n")
		var parts []string
		for _, state := range []string{endpointNo2xx, endpointNoResponse, endpointUntested, endpointUnknown} {
			if n := q.Endpoints[state]; n > 0 {
				parts = append(parts, fmt.Sprintf("%d %s", n, strings.ReplaceAll(state, "_", " ")))
			}
		}
		if len(parts) > 0 {
			write("  not exercised: %s\n", strings.Join(parts, ", "))
		}
	}
	for _, m := range q.Incomplete {
		write("  incomplete: %s\n", m)
	}
	for _, m := range q.Notes {
		write("  note: %s\n", m)
	}
	for _, m := range q.Failures {
		write("  ✗ %s\n", m)
	}
	write("  (%s)\n", q.Caveat)
}
