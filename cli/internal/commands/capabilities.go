package commands

import (
	"fmt"
	"sort"

	"aidetector/cli/internal/api"
)

// passColumn is where a pass's state starts in `status`.
const passColumn = 18 // fits --security-review, the longest pass flag

// passFlag names the flag that sets a RunRequest field. The capabilities answer
// is keyed by field (security_review), while the user knows the flag
// (--security-review).
func passFlag(field string) (string, bool) {
	for flagName, f := range RunFlags {
		if f == field {
			return flagName, true
		}
	}
	return "", false
}

// capabilityLine renders one pass as `  --zap            available`,
// `unavailable — reason` or `available (note: reason)`.
func capabilityLine(flagName string, available bool, reason *string) string {
	label := fmt.Sprintf("  %-*s", passColumn, "--"+flagName)
	text := ""
	if reason != nil {
		text = reasonText(*reason)
	}
	switch {
	case !available:
		if text == "" {
			text = "no reason given"
		}
		return fmt.Sprintf("%s unavailable — %s", label, text)
	case text != "":
		return fmt.Sprintf("%s available (note: %s)", label, text)
	default:
		return fmt.Sprintf("%s available", label)
	}
}

// printCapabilities prints the `passes:` section of `status`. Every pass the
// server answered for is listed; a pass it did not mention is left out, so an
// older server's shorter answer is not shown as a wall of "unavailable".
func printCapabilities(e *Env, caps api.Capabilities) {
	lines := make([]string, 0, len(caps.Passes)+1)
	for field, cap := range caps.Passes {
		if field == "premium" {
			continue // a tenant entitlement, printed below
		}
		flagName, ok := passFlag(field)
		if !ok {
			continue // a field this CLI has no flag for
		}
		lines = append(lines, capabilityLine(flagName, cap.Available, cap.Reason))
	}
	// Premium is a tenant entitlement, not a deployment pass: the server keeps
	// it outside `passes`, but it is still a flag with an availability.
	if caps.Premium.Available && caps.Premium.Plan != "" {
		lines = append(lines, fmt.Sprintf("  %-*s available (plan: %s)",
			passColumn, "--premium", reasonText(caps.Premium.Plan)))
	} else {
		lines = append(lines, capabilityLine("premium", caps.Premium.Available, caps.Premium.Reason))
	}
	sort.Strings(lines)
	e.printf("passes:\n")
	for _, line := range lines {
		e.printf("%s\n", line)
	}
}

// reasonText keeps a server-supplied reason printable and on the one line it is
// printed on (oneLine collapses the newlines printable keeps for traces).
func reasonText(s string) string { return oneLine(printable(s)) }
