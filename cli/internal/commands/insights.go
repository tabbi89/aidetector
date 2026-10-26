package commands

import (
	"context"
	"fmt"
	"sort"
	"strings"

	"runpentests/cli/internal/api"
)

// cmdCost prints what the scan's AI steps spent: the total, the per-model
// rollup the server computed, and a per-phase rollup built from the ledger.
func cmdCost(ctx context.Context, e *Env, args []string) int {
	fs := e.newFlagSet("cost")
	asJSON := fs.Bool("json", false, "print JSON")
	pos, err := parse(fs, args)
	if err != nil {
		return e.parseFailed("cost", fs, err)
	}
	if len(pos) > 1 {
		return e.usage("cost takes at most one scan ID")
	}
	c, err := e.client()
	if err != nil {
		return e.usage("%v", err)
	}
	id, code := resolveScan(ctx, e, c, argOrEmpty(pos), true)
	if code != ExitOK {
		return code
	}
	cost, err := c.Cost(ctx, id)
	if err != nil {
		return e.exitFor(err)
	}
	if *asJSON {
		return printJSON(e, cost)
	}
	printCost(e, cost)
	return ExitOK
}

func printCost(e *Env, cost api.Cost) {
	if len(cost.Models) == 0 && len(cost.Entries) == 0 {
		e.printf("no AI spend on this scan\n")
		return
	}
	e.printf("total: $%.4f\n", cost.TotalUSD)
	if len(cost.Models) > 0 {
		e.printf("\nmodels:\n")
		e.printf("%-28s  %5s  %10s  %10s  %8s  %s\n",
			"MODEL", "CALLS", "TOKENS IN", "TOKENS OUT", "USD", "PHASES")
		for _, m := range cost.Models {
			phases := make([]string, len(m.Phases))
			for i, p := range m.Phases {
				phases[i] = printable(p)
			}
			if len(phases) == 0 {
				phases = []string{"-"}
			}
			e.printf("%-28s  %5d  %10d  %10d  %8s  %s\n",
				printable(m.Model), m.Calls, m.TokensIn, m.TokensOut,
				fmt.Sprintf("$%.4f", m.CostUSD), strings.Join(phases, ", "))
		}
	}
	if totals := phaseTotals(cost.Entries); len(totals) > 0 {
		e.printf("\nphases:\n")
		e.printf("%-20s  %5s  %10s  %10s  %8s\n", "PHASE", "CALLS", "TOKENS IN", "TOKENS OUT", "USD")
		for _, t := range totals {
			e.printf("%-20s  %5d  %10d  %10d  %8s\n",
				printable(t.phase), t.calls, t.tokensIn, t.tokensOut,
				fmt.Sprintf("$%.4f", float64(t.micros)/1e6))
		}
	}
}

// phaseTotal is the ledger aggregated by phase. A ledger row is one AI call,
// so the row count is the call count.
type phaseTotal struct {
	phase     string
	calls     int
	tokensIn  int
	tokensOut int
	micros    int64
}

func phaseTotals(entries []api.LedgerEntry) []phaseTotal {
	byPhase := map[string]*phaseTotal{}
	var order []string
	for _, entry := range entries {
		t, ok := byPhase[entry.Phase]
		if !ok {
			t = &phaseTotal{phase: entry.Phase}
			byPhase[entry.Phase] = t
			order = append(order, entry.Phase)
		}
		t.calls++
		t.tokensIn += entry.TokensIn
		t.tokensOut += entry.TokensOut
		t.micros += entry.CostMicros
	}
	totals := make([]phaseTotal, 0, len(order))
	for _, phase := range order {
		totals = append(totals, *byPhase[phase])
	}
	sort.SliceStable(totals, func(i, j int) bool { return totals[i].phase < totals[j].phase })
	return totals
}

// cmdCoverage prints what a run did to each endpoint. Requests alone say
// little: an endpoint that answered every request with 401 or 404 was reached
// but never tested, so each row says whether it was exercised (answered a 2xx).
func cmdCoverage(ctx context.Context, e *Env, args []string) int {
	fs := e.newFlagSet("coverage")
	asJSON := fs.Bool("json", false, "print JSON")
	untested := fs.Bool("untested", false, "only endpoints that received no requests")
	inconclusive := fs.Bool("inconclusive", false, "only in-scope endpoints that were not exercised (no 2xx, no response, untested or unknown)")
	runNumber := fs.Int("run", 0, "an archived run number (default: the latest run)")
	pos, err := parse(fs, args)
	if err != nil {
		return e.parseFailed("coverage", fs, err)
	}
	if len(pos) > 1 {
		return e.usage("coverage takes at most one scan ID")
	}
	if *runNumber < 0 {
		return e.usage("--run must be a run number")
	}
	c, err := e.client()
	if err != nil {
		return e.usage("%v", err)
	}
	id, code := resolveScan(ctx, e, c, argOrEmpty(pos), true)
	if code != ExitOK {
		return code
	}
	rows, err := c.Coverage(ctx, id, *runNumber)
	if err != nil {
		return e.exitFor(err)
	}
	sort.SliceStable(rows, func(i, j int) bool {
		if rows[i].Path != rows[j].Path {
			return rows[i].Path < rows[j].Path
		}
		return rows[i].Method < rows[j].Method
	})
	counts := map[string]int{}
	shown := make([]coverageOut, 0, len(rows))
	for _, r := range rows {
		state := endpointState(r)
		counts[state]++
		if *untested && r.Requests != 0 {
			continue
		}
		if *inconclusive && (state == endpointExercised || state == endpointExcluded) {
			continue
		}
		shown = append(shown, coverageOut{CoverageRow: r, State: state})
	}
	if *asJSON {
		return printJSON(e, shown)
	}
	e.printf("%-7s  %-40s  %8s  %-14s  %8s  %s\n", "METHOD", "PATH", "REQUESTS", "STATUS", "FINDINGS", "CHECKS")
	for _, r := range shown {
		path := printable(r.Path)
		if !r.Enabled {
			path += " (excluded)"
		}
		checks := "-"
		if len(r.Checks) > 0 {
			names := make([]string, len(r.Checks))
			for i, key := range r.Checks {
				names[i] = printable(key)
			}
			checks = strings.Join(names, ", ")
		}
		e.printf("%-7s  %-40s  %8d  %-14s  %8d  %s\n",
			printable(r.Method), path, r.Requests, coverageStatus(r.CoverageRow, r.State), r.Findings, checks)
	}
	inScope := len(rows) - counts[endpointExcluded]
	e.printf("%d endpoint(s) shown; of %d in scope: %d exercised, %d no 2xx, %d no response, %d never probed",
		len(shown), inScope, counts[endpointExercised], counts[endpointNo2xx],
		counts[endpointNoResponse], counts[endpointUntested])
	if n := counts[endpointUnknown]; n > 0 {
		e.printf(", %d unknown (the run predates response outcomes)", n)
	}
	e.printf("\n")
	return ExitOK
}

// coverageOut is a coverage row with its state named, for --json.
type coverageOut struct {
	api.CoverageRow
	State string `json:"state"`
}

// coverageStatus is the STATUS cell: the state plus the 2xx share behind it.
func coverageStatus(r api.CoverageRow, state string) string {
	switch state {
	case endpointExercised:
		if r.OK != nil && r.Responses != nil {
			return fmt.Sprintf("ok %d/%d", *r.OK, *r.Responses)
		}
		return "exercised"
	case endpointNo2xx:
		if r.Responses != nil {
			return fmt.Sprintf("no 2xx 0/%d", *r.Responses)
		}
		return "no 2xx"
	case endpointNoResponse:
		return "no response"
	case endpointUntested:
		return "not probed"
	case endpointExcluded:
		return "-"
	}
	return "unknown"
}
