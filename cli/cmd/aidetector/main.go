// Command aidetector drives an aidetector server from the terminal: create a
// scan, run it, wait for it, and gate a pipeline on what it found.
package main

import (
	"context"
	"os"
	"os/signal"

	"aidetector/cli/internal/commands"
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	os.Exit(commands.Run(ctx, os.Args[1:], commands.DefaultEnv()))
}
