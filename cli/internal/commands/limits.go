package commands

import (
	"context"
	"slices"
	"sort"
	"strings"

	"aidetector/cli/internal/api"
)

// runLimits is what the run's events say limited it, in the order a person
// should fix them. A run prints forty progress lines; the two that matter — "every
// request answered 404", "this key was rejected" — scroll past among the rest,
// and the findings table under them reads like a result. This is the short list
// printed after the table, so the last thing on screen is what to change.
type runLimits struct {
	// problems are lines that change what the findings mean, worst first.
	problems []string
	// unreached is set when the run never reached the API at all: the findings
	// are then about an error page, not the API.
	unreached bool
	// skipped are checks that had nothing to work against. Mostly the API's
	// shape (no checkout endpoint, nothing to page), so one line, not a list.
	skipped []string
}

// severe stages come first: each means part of the run tested nothing real.
var severeStages = map[string]bool{
	"target_unreached":      true,
	"target_health":         true,
	"check_failed":          true,
	"auth_grant_failed":     true,
	"credential_unreadable": true,
	"egress_blocked":        true,
}

// limitedStages narrowed the run without voiding it.
var limitedStages = map[string]bool{
	"budget_exhausted":       true,
	"identities_unavailable": true,
	"resource_setup_skipped": true,
	"agent_idle":             true,
	// Something the scan created may still be on the target.
	"cleanup_failed": true,
}

func readLimits(events []api.Event) runLimits {
	var out runLimits
	var severe, limited []string
	for _, ev := range events {
		msg := printable(ev.Message)
		switch {
		case severeStages[ev.Stage]:
			// The stage, not the wording, says the run never reached the API.
			out.unreached = out.unreached || ev.Stage == "target_unreached"
			severe = append(severe, msg)
		case ev.Stage == "check_skipped":
			// "bola did not run: …", or "discovery bola did not run: …" from
			// the second pass over discovered endpoints.
			fields := strings.Fields(msg)
			if len(fields) > 1 && fields[0] == "discovery" {
				fields = fields[1:]
			}
			if len(fields) > 0 && !slices.Contains(out.skipped, fields[0]) {
				out.skipped = append(out.skipped, fields[0])
			}
		case ev.Stage == "resource_setup_note" && strings.HasPrefix(msg, "resource setup failed"):
			limited = append(limited, msg)
		case limitedStages[ev.Stage], strings.HasSuffix(ev.Stage, "_skipped"):
			limited = append(limited, msg)
		}
	}
	for _, m := range severe {
		out.problems = append(out.problems, "✗ "+m)
	}
	for _, m := range limited {
		out.problems = append(out.problems, "! "+m)
	}
	sort.Strings(out.skipped)
	return out
}

// printLimits writes the summary to stderr (stdout stays the findings table).
// It says nothing about a run nothing limited.
func printLimits(ctx context.Context, e *Env, c *api.Client, id string) {
	events, err := c.Events(ctx, id)
	if err != nil {
		return // the summary is a convenience; the run's result stands without it
	}
	l := readLimits(events)
	if len(l.problems) == 0 && len(l.skipped) == 0 {
		return
	}
	if len(l.problems) > 0 {
		e.errorf("\nwhat limited this run (fix ✗ first):\n")
		for _, p := range l.problems {
			e.errorf("  %s\n", p)
		}
	}
	if n := len(l.skipped); n > 0 {
		// Indented under the problems it follows; a line of its own otherwise.
		indent := ""
		if len(l.problems) > 0 {
			indent = "  "
		}
		e.errorf("%s%d check(s) had nothing to test in this API: %s — the \"did not run\" lines "+
			"above say what each needs\n", indent, n, strings.Join(l.skipped, ", "))
	}
	if l.unreached {
		e.errorf("the findings above are not a result: the run never reached the API\n")
	}
}
