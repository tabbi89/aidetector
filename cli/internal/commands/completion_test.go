package commands

import (
	"context"
	"net/http/httptest"
	"os"
	"regexp"
	"strings"
	"testing"
)

func TestCompletionScriptsMentionTheInterface(t *testing.T) {
	srv := httptest.NewServer((&fake{}).handler())
	defer srv.Close()

	markers := map[string]string{
		"bash": "complete -F",
		"zsh":  "#compdef runpentests",
		"fish": "complete -c runpentests",
	}
	for shell, marker := range markers {
		t.Run(shell, func(t *testing.T) {
			h := newHarness(t, srv, "", false)
			if got := h.run("completion", shell); got != ExitOK {
				t.Fatalf("exit = %d\n%s", got, h.errOut.String())
			}
			out := h.out.String()
			if !strings.Contains(out, marker) {
				t.Fatalf("%s script should contain %q:\n%s", shell, marker, out)
			}
			for _, want := range []string{"--writes", "cancel", "--seq"} {
				if !strings.Contains(out, want) {
					t.Fatalf("%s script is missing %q:\n%s", shell, want, out)
				}
			}
		})
	}
}

func TestCompletionScriptsCompleteFlagValues(t *testing.T) {
	srv := httptest.NewServer((&fake{}).handler())
	defer srv.Close()
	for _, shell := range []string{"bash", "zsh", "fish"} {
		h := newHarness(t, srv, "", false)
		if got := h.run("completion", shell); got != ExitOK {
			t.Fatalf("%s: exit = %d\n%s", shell, got, h.errOut.String())
		}
		out := h.out.String()
		for _, want := range []string{"pdf", "pentest", "sarif", "critical", "medium", "quick", "deep"} {
			if !strings.Contains(out, want) {
				t.Fatalf("%s script is missing the value %q:\n%s", shell, want, out)
			}
		}
	}
}

// Every flag a command prints in its own help must reach the completion
// script, so a new flag cannot leave completion behind.
func TestCompletionCoversEveryCommandFlag(t *testing.T) {
	script := bashCompletion(completionEntries(context.Background()))
	for _, entry := range completionEntries(context.Background()) {
		for _, flag := range entry.flags {
			if !strings.Contains(script, "--"+flag) {
				t.Errorf("%s: completion is missing --%s", entry.path, flag)
			}
		}
	}
}

func TestCompletionRefusesAnUnknownShell(t *testing.T) {
	srv := httptest.NewServer((&fake{}).handler())
	defer srv.Close()
	for _, args := range [][]string{
		{"completion"},
		{"completion", "tcsh"},
	} {
		h := newHarness(t, srv, "", false)
		if got := h.run(args...); got != ExitUsage {
			t.Errorf("%v: exit = %d, want %d", args, got, ExitUsage)
		}
	}
}

func TestHelpForCompletionShowsInstallExamples(t *testing.T) {
	srv := httptest.NewServer((&fake{}).handler())
	defer srv.Close()
	h := newHarness(t, srv, "", false)
	if got := h.run("help", "completion"); got != ExitOK {
		t.Fatalf("exit = %d\n%s", got, h.errOut.String())
	}
	out := h.out.String()
	for _, want := range []string{"completion zsh", "bash_completion.d", "fish/completions/runpentests.fish"} {
		if !strings.Contains(out, want) {
			t.Fatalf("completion help is missing %q:\n%s", want, out)
		}
	}
}

// Every command Run dispatches must be in the completion table, or a shell
// would never offer it.
func TestCompletionKnowsEveryCommand(t *testing.T) {
	src, err := os.ReadFile("root.go")
	if err != nil {
		t.Fatal(err)
	}
	known := map[string]bool{}
	for _, r := range completionRoots {
		known[r.name] = true
	}
	for _, m := range regexp.MustCompile(`(?m)^\tcase "([a-z]+)":\n\t\treturn cmd`).FindAllStringSubmatch(string(src), -1) {
		if !known[m[1]] {
			t.Errorf("command %q is dispatched by Run but missing from completionRoots", m[1])
		}
	}
}
