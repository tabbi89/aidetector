package commands

import (
	"net/http/httptest"
	"strings"
	"testing"
)

func newHelpHarness(t *testing.T) *harness {
	t.Helper()
	srv := httptest.NewServer((&fake{}).handler())
	t.Cleanup(srv.Close)
	return newHarness(t, srv, "", false)
}

func TestRunHelpListsThePassesAndExitsZero(t *testing.T) {
	h := newHelpHarness(t)
	if got := h.run("run", "-h"); got != ExitOK {
		t.Fatalf("exit = %d, want %d; stderr = %q", got, ExitOK, h.errOut.String())
	}
	out := h.out.String()
	if !strings.Contains(out, "--writes") || !strings.Contains(out, "change target data") {
		t.Fatalf("help should describe --writes:\n%s", out)
	}
	if !strings.Contains(out, "passes (every pass is off unless you set it):") {
		t.Errorf("the passes should have their own group:\n%s", out)
	}
	if h.errOut.Len() != 0 {
		t.Errorf("help must go to stdout, stderr = %q", h.errOut.String())
	}
}

func TestHelpForACommandPrintsItsFlags(t *testing.T) {
	h := newHelpHarness(t)
	if got := h.run("help", "findings"); got != ExitOK {
		t.Fatalf("exit = %d, want %d; stderr = %q", got, ExitOK, h.errOut.String())
	}
	if out := h.out.String(); !strings.Contains(out, "--min-severity") {
		t.Fatalf("help findings should list --min-severity:\n%s", out)
	}
}

func TestSubcommandHelp(t *testing.T) {
	h := newHelpHarness(t)
	if got := h.run("scans", "-h"); got != ExitOK {
		t.Fatalf("scans -h: exit = %d, want %d", got, ExitOK)
	}
	h = newHelpHarness(t)
	if got := h.run("scans", "list", "-h"); got != ExitOK {
		t.Fatalf("scans list -h: exit = %d, want %d", got, ExitOK)
	}
	if out := h.out.String(); !strings.Contains(out, "--json") {
		t.Fatalf("scans list -h should list --json:\n%s", out)
	}
}

func TestHelpForAnUnknownCommandIsAUsageError(t *testing.T) {
	h := newHelpHarness(t)
	if got := h.run("help", "nope"); got != ExitUsage {
		t.Fatalf("exit = %d, want %d", got, ExitUsage)
	}
}

func TestVersionIsPrintedByEverySpelling(t *testing.T) {
	for _, args := range [][]string{{"version"}, {"--version"}, {"-v"}} {
		h := newHelpHarness(t)
		if got := h.run(args...); got != ExitOK {
			t.Fatalf("%v: exit = %d, want %d", args, got, ExitOK)
		}
		if out := h.out.String(); !strings.Contains(out, "aidetector dev") {
			t.Fatalf("%v: out = %q, want the version", args, out)
		}
	}
}

func TestStatusPrintsTheCLIVersionFirst(t *testing.T) {
	h := newHelpHarness(t)
	if got := h.run("status"); got != ExitOK {
		t.Fatalf("exit = %d, want %d; stderr = %q", got, ExitOK, h.errOut.String())
	}
	if out := h.out.String(); !strings.HasPrefix(out, "cli: "+Version+"\n") {
		t.Fatalf("status should print the CLI version first, out = %q", out)
	}
}

func TestAnUnknownFlagIsAUsageErrorWithoutTheFlagList(t *testing.T) {
	h := newHelpHarness(t)
	if got := h.run("run", "--bogus", "s1"); got != ExitUsage {
		t.Fatalf("exit = %d, want %d", got, ExitUsage)
	}
	errOut := h.errOut.String()
	if strings.Contains(errOut, "--writes") {
		t.Fatalf("an unknown flag must not dump the flag list:\n%s", errOut)
	}
	if !strings.Contains(errOut, "flag provided but not defined") ||
		!strings.Contains(errOut, "aidetector help run") {
		t.Fatalf("stderr should name the error and where the usage is:\n%s", errOut)
	}
}

func TestEveryPassHasHelpTextAndNoStaleEntry(t *testing.T) {
	for name := range RunFlags {
		if PassHelp[name] == "" {
			t.Errorf("pass %q has no PassHelp entry", name)
		}
	}
	for name := range PassHelp {
		if _, ok := RunFlags[name]; !ok {
			t.Errorf("PassHelp has an entry for %q, which is not a pass flag", name)
		}
	}
}

// The top-level help is hand-written; a command removed from Run must leave it
// too (it once kept advertising `schedule` after the command was gone).
func TestTopLevelHelpNamesOnlyRealCommands(t *testing.T) {
	start := strings.Index(helpText, "\ncommands:\n")
	end := strings.Index(helpText, "\nprofiles:")
	if start < 0 || end < start {
		t.Fatal("helpText should have a commands: block followed by profiles:")
	}
	var names []string
	for _, line := range strings.Split(helpText[start+len("\ncommands:\n"):end], "\n") {
		// A command line is indented two spaces; continuation lines are deeper.
		if !strings.HasPrefix(line, "  ") || strings.HasPrefix(line, "   ") {
			continue
		}
		names = append(names, strings.Fields(line)[0])
	}
	if len(names) < 10 {
		t.Fatalf("parsed too few commands from helpText: %v", names)
	}
	for _, name := range names {
		h := newHelpHarness(t)
		if got := h.run("help", name); got != ExitOK {
			t.Errorf("helpText lists %q, but `aidetector help %s` exits %d: %s",
				name, name, got, h.errOut.String())
		}
	}
}
