package commands

import "runtime"

// Version is this build's version: "dev" unless the Makefile stamps it with
// -ldflags "-X aidetector/cli/internal/commands.Version=...".
var Version = "dev"

// cmdVersion prints the build and the platform it runs on — the first thing to
// ask for in a bug report.
func cmdVersion(e *Env, args []string) int {
	fs := e.newFlagSet("version")
	if _, err := parse(fs, args); err != nil {
		return e.parseFailed("version", fs, err)
	}
	e.printf("aidetector %s (%s/%s, %s)\n", Version, runtime.GOOS, runtime.GOARCH, runtime.Version())
	return ExitOK
}
