package commands

import "runtime"

// Version is this build's version: "dev" unless the Makefile stamps it with
// -ldflags "-X runpentests/cli/internal/commands.Version=...".
var Version = "dev"

// RunnerImage is stamped into release binaries alongside Version. Releases
// use a fully qualified, digest-pinned image; local builds keep the build hint.
var RunnerImage = ""

// cmdVersion prints the build and the platform it runs on — the first thing to
// ask for in a bug report.
func cmdVersion(e *Env, args []string) int {
	fs := e.newFlagSet("version")
	if _, err := parse(fs, args); err != nil {
		return e.parseFailed("version", fs, err)
	}
	e.printf("runpentests %s (%s/%s, %s)\n", Version, runtime.GOOS, runtime.GOARCH, runtime.Version())
	return ExitOK
}
