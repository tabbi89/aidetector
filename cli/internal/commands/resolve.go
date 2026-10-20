package commands

import (
	"context"
	"regexp"
	"sort"
	"strings"

	"aidetector/cli/internal/api"
	"aidetector/cli/internal/project"
)

// A scan ID is a UUID; a prefix of at least four hex characters is enough to
// name one when the list narrows it to a single scan.
var (
	fullID   = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)
	idPrefix = regexp.MustCompile(`^[0-9a-f-]{4,}$`)
)

// resolveScan turns a scan reference into a full ID. A full UUID costs no API
// call; a prefix is matched against the list. With allowDefault and no
// reference, the project file names the scan: its pinned scan:, else the
// latest scan for its target:, which is the same choice the target form makes.
func resolveScan(ctx context.Context, e *Env, c *api.Client, ref string, allowDefault bool) (string, int) {
	if ref != "" {
		if fullID.MatchString(ref) {
			return ref, ExitOK
		}
		lower := strings.ToLower(ref)
		if !idPrefix.MatchString(lower) {
			if len(lower) < 4 && strings.Trim(lower, "0123456789abcdef-") == "" {
				return "", e.usage("%q is too short: give at least 4 characters of the scan ID", ref)
			}
			return "", e.usage("%q is not a scan ID or ID prefix", ref)
		}
		return resolvePrefix(ctx, e, c, ref, lower)
	}
	if !allowDefault {
		name := e.cmd
		if name == "" {
			name = "this command"
		}
		return "", e.usage("%s needs a scan ID", name)
	}

	wd, err := e.workdir()
	if err != nil {
		return "", e.usage("%v", err)
	}
	file, err := project.Find(wd)
	if err != nil {
		return "", e.usage("%v", err)
	}
	if file != nil {
		if file.Scan != "" {
			e.errorf("scan %s (from aidetector.yml)\n", shortID(file.Scan))
			return file.Scan, ExitOK
		}
		if file.Target != "" {
			all, err := c.ListScans(ctx)
			if err != nil {
				return "", e.exitFor(err)
			}
			scan, _, ok := latestScanFor(all, file.Target)
			if ok {
				e.errorf("scan %s (from aidetector.yml)\n", shortID(scan.ID))
				return scan.ID, ExitOK
			}
		}
	}
	return "", e.usage("give a scan ID (or run inside a project with aidetector.yml)")
}

func resolvePrefix(ctx context.Context, e *Env, c *api.Client, ref, lower string) (string, int) {
	all, err := c.ListScans(ctx)
	if err != nil {
		return "", e.exitFor(err)
	}
	var matches []api.ScanSummary
	for _, s := range all {
		if strings.HasPrefix(strings.ToLower(s.ID), lower) {
			matches = append(matches, s)
		}
	}
	switch len(matches) {
	case 0:
		return "", e.usage("no scan matches %q (aidetector scans list)", ref)
	case 1:
		return matches[0].ID, ExitOK
	}
	e.usage("%q matches %d scans:", ref, len(matches))
	for i, s := range matches {
		if i == 5 {
			break
		}
		e.errorf("  %s  %s\n", s.ID, s.TargetBaseURL)
	}
	e.errorf("use more characters\n")
	return "", ExitUsage
}

// latestScanFor picks the most recently run scan for target. The bool says
// whether there was one at all; the count is how many targets matched.
func latestScanFor(scans []api.ScanSummary, target string) (api.ScanSummary, int, bool) {
	var matches []api.ScanSummary
	for _, s := range scans {
		if project.SameTarget(s.TargetBaseURL, target) {
			matches = append(matches, s)
		}
	}
	if len(matches) == 0 {
		return api.ScanSummary{}, 0, false
	}
	// Latest run first; a scan that never ran sorts last. Stable keeps the
	// server's order (newest created first) on a tie.
	sort.SliceStable(matches, func(i, j int) bool {
		return deref(matches[i].LastRunAt) > deref(matches[j].LastRunAt)
	})
	return matches[0], len(matches), true
}

func argOrEmpty(pos []string) string {
	if len(pos) == 0 {
		return ""
	}
	return pos[0]
}
