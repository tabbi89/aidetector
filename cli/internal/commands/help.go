package commands

import (
	"context"
	"flag"
	"strings"
	"time"

	"aidetector/cli/internal/config"
)

// commandDoc is one command's help: the invocation, a one-line synopsis, a
// short description and a few example lines. The flags are deliberately not
// here — the command builds its own flag set and help.go prints that, so a
// flag added to a command shows up in its help without a second list.
type commandDoc struct {
	Invocation  string   // the command line, without the leading "aidetector"
	Synopsis    string   // one line, under the invocation
	Description string   // one to three sentences
	Examples    []string // complete command lines
}

var commandDocs = map[string]commandDoc{
	"init": {
		Invocation: "init [URL] [--spec FILE] [--force] [--yes]",
		Synopsis:   "write an aidetector.yml that fits the API",
		Description: "Find a spec on this machine (--spec, else openapi.* / swagger.* in the " +
			"current directory), ask the server what it says about authentication, and write " +
			"one of three shorthands: auth: public, token_env: AIDETECTOR_TOKEN, or one identity " +
			"per role. It never calls the target and never writes a secret, only the environment " +
			"variables to export.",
		Examples: []string{
			"aidetector init https://api.example.com",
			"aidetector init --spec docs/openapi.yaml --yes",
			"aidetector init --force",
		},
	},
	"login": {
		Invocation: "login [flags]",
		Synopsis:   "log in to a server and save it as a profile",
		Description: "Check that the server answers and the key works, then save both in a " +
			"profile (--profile, else the current one, else \"default\") and make it current. " +
			"Without --server it logs in to " + config.DefaultServer + ". " +
			"The key is never a flag: it comes from a hidden prompt, stdin or AIDETECTOR_API_KEY.",
		Examples: []string{
			"aidetector login",
			"aidetector login --server https://scan.internal.example --profile self-hosted",
			`echo "$KEY" | aidetector login --key-stdin`,
		},
	},
	"logout": {
		Invocation: "logout",
		Synopsis:   "remove the current profile",
		Description: "Delete the current profile — its server and key — and leave the others " +
			"alone. No profile is current afterwards. Environment variables are untouched.",
		Examples: []string{"aidetector logout"},
	},
	"status": {
		Invocation: "status",
		Synopsis:   "show the selected profile, its server and whether it is reachable",
		Description: "Print the CLI version, the selected profile, the configured server, " +
			"whether a key is saved (never the key) and whether the server answers. An " +
			"AIDETECTOR_PROFILE or AIDETECTOR_SERVER override is marked as such.",
		Examples: []string{"aidetector status", "AIDETECTOR_PROFILE=staging aidetector status"},
	},
	"profile": {
		Invocation: "profile list | profile use NAME | profile rm NAME [--yes]",
		Synopsis:   "manage saved server profiles",
		Description: "A profile is one server and its key, so one machine can talk to several. " +
			"`login --profile NAME` saves one; `use` makes it current; AIDETECTOR_PROFILE " +
			"selects one for a single command. `list` shows whether a key is set, never the key.",
		Examples: []string{
			"aidetector profile list",
			"aidetector profile use staging",
			"aidetector profile rm staging --yes",
		},
	},
	"scans": {
		Invocation: "scans list [--target URL] | scans show [ID] | scans rm ID --yes",
		Synopsis:   "list, show and delete scans",
		Description: "Manage the scans on the server: list them, show one, or delete one and " +
			"all of its data. Deleting is permanent and asks first. An ID may be its first 4+ " +
			"characters; where it is optional, aidetector.yml picks the scan.",
		Examples: []string{
			"aidetector scans list",
			"aidetector scans show 3f0c1a2b",
			"aidetector scans rm 3f0c1a2b --yes",
		},
	},
	"scan": {
		Invocation: "scan create --target URL --spec FILE",
		Synopsis:   "create a scan and ingest a spec",
		Description: "Create a scan for a target and ingest its OpenAPI, Swagger, HAR or " +
			"Postman spec. Prints the new scan's ID for the other commands.",
		Examples: []string{"aidetector scan create --target https://api.example.com --spec openapi.json"},
	},
	"cred": {
		Invocation: "cred add ID --name N --role R --auth-type T [--header-name H] | cred list [ID] | cred rm ID NAME --yes",
		Synopsis:   "attach, list and remove a scan's identities",
		Description: "Add a credential profile the authorization checks compare — for example " +
			"a normal user and an admin. The secret is never a flag: it comes from a hidden " +
			"prompt or --secret-stdin.",
		Examples: []string{
			"aidetector cred add 3f0c1a2b --name alice --role user --auth-type bearer",
			"aidetector cred list 3f0c1a2b",
			`echo "$ADMIN_TOKEN" | aidetector cred add 3f0c1a2b --name admin --role admin --secret-stdin`,
		},
	},
	"run": {
		Invocation: "run ID [flags]",
		Synopsis:   "run a scan from this machine and wait for it",
		Description: "Run a scan from this machine: the engine runs in a container here, every " +
			"request to the target leaves from here, and the results, the request log and any " +
			"AI analysis go to the service. Consent is answered before any request reaches the " +
			"target: --authorized, or a y to a prompt naming it. --level picks how hard to look " +
			"(quick, standard, deep); --ai adds the AI passes and spends tokens. Every pass stays " +
			"off unless you ask for it. With --fail-on, --output picks the gate format: table, " +
			"json, github workflow commands, or junit XML.",
		Examples: []string{
			"aidetector run 3f0c1a2b --authorized",
			"aidetector run 3f0c1a2b --authorized --level standard",
			"aidetector run 3f0c1a2b --authorized --writes --ai",
			"aidetector run 3f0c1a2b --authorized --fail-on high --verified-only",
			"aidetector run 3f0c1a2b --authorized --fail-on high --output github",
			"aidetector run 3f0c1a2b --authorized --source . --docker-network app_internal,app_egress",
		},
	},
	"wait": {
		Invocation: "wait [ID] [flags]",
		Synopsis:   "attach to a scan's current run, then gate on it",
		Description: "Follow a run that is still going — one started from the web, or a run " +
			"whose AI analysis continues on the service after you stopped waiting — or read " +
			"the one that already finished, and gate on it. Ctrl-C detaches and leaves the run " +
			"going. --output picks the gate format: table, json, github workflow commands, or junit XML.",
		Examples: []string{
			"aidetector wait 3f0c1a2b --fail-on high",
			"aidetector wait 3f0c1a2b --fail-on high --output junit > aidetector.xml",
		},
	},
	"cost": {
		Invocation: "cost [ID] [--json]",
		Synopsis:   "show what a scan's AI steps spent",
		Description: "Print the scan's AI total, a per-model table and a per-phase total " +
			"aggregated from the call ledger. A scan that ran no AI step says so.",
		Examples: []string{
			"aidetector cost 3f0c1a2b",
			"aidetector cost 3f0c1a2b --json",
		},
	},
	"coverage": {
		Invocation: "coverage [ID] [--json] [--untested]",
		Synopsis:   "show what the latest run did to each endpoint",
		Description: "One line per endpoint with its requests, findings and the checks that " +
			"exercised it. A row with no requests was in scope but never probed; --untested " +
			"shows only those.",
		Examples: []string{
			"aidetector coverage 3f0c1a2b",
			"aidetector coverage 3f0c1a2b --untested",
		},
	},
	"runs": {
		Invocation: "runs [ID] [flags] | runs trace [ID] [RUN] [flags]",
		Synopsis:   "list a scan's run history, or one run's request log",
		Description: "One line per run: status, start, duration, findings, requests, who sent " +
			"the traffic and which passes ran — then any tool that did not run or a spent " +
			"request budget, which is why a finding can read as not retested. `trace` prints " +
			"the run's redacted request/response log, filterable and pageable; `--seq N` shows " +
			"one request in full.",
		Examples: []string{
			"aidetector runs 3f0c1a2b",
			"aidetector runs trace 3f0c1a2b --status 4xx --identity alice",
			"aidetector runs trace 3f0c1a2b 2 --seq 41",
		},
	},
	"cancel": {
		Invocation:  "cancel ID",
		Synopsis:    "stop a scan at its next check boundary",
		Description: "Ask the server to stop a scan. The run ends cancelled rather than failed.",
		Examples:    []string{"aidetector cancel 3f0c1a2b"},
	},
	"findings": {
		Invocation: "findings [ID] [flags] | findings show [ID] FINDING [--json] | " +
			"findings dismiss|confirm|reopen [SCAN] FINDING...",
		Synopsis: "list a scan's findings, show one, or triage it",
		Description: "Print a scan's findings, most severe first. A finding a person dismissed " +
			"is marked, and the gate never counts it. `show` prints one finding's evidence, " +
			"remediation and references, by its ID or fingerprint prefix. `dismiss`, `confirm` " +
			"and `reopen` set a finding's verdict; the server remembers it against the " +
			"fingerprint, so it carries to later runs. `reopen` makes it unreviewed.",
		Examples: []string{
			"aidetector findings show 3f0c1a2b 9d41",
			"aidetector findings dismiss 3f0c1a2b 9d41 --yes",
			"aidetector findings confirm 3f0c1a2b 9d41",
			"aidetector findings reopen 3f0c1a2b 9d41",
			"aidetector findings 3f0c1a2b --min-severity high",
		},
	},
	"diff": {
		Invocation:  "diff [ID] [flags]",
		Synopsis:    "compare the two latest runs of a scan",
		Description: "Show what is new, fixed, not retested and unchanged between the two latest runs.",
		Examples:    []string{"aidetector diff 3f0c1a2b", "aidetector diff 3f0c1a2b --json"},
	},
	"report": {
		Invocation: "report [ID] --format FORMAT [-o FILE]",
		Synopsis:   "download a report",
		Description: "Download the scan's report in one of the server's formats. A report lists " +
			"weaknesses in an API, so the file is written owner-only. Without -o it is " +
			"aidetector-<id8>.<ext>, and an existing file is never overwritten.",
		Examples: []string{
			"aidetector report 3f0c1a2b --format sarif -o results.sarif",
			"aidetector report 3f0c1a2b --format html -o -",
		},
	},
	"completion": {
		Invocation: "completion bash|zsh|fish",
		Synopsis:   "print a shell completion script",
		Description: "Print a completion script for bash, zsh or fish to stdout. It is generated " +
			"from this build's commands and flags, so install it after upgrading the binary. " +
			"Source it or write it where your shell looks for completions.",
		Examples: []string{
			`aidetector completion zsh > "${fpath[1]}/_aidetector"`,
			"aidetector completion bash > /etc/bash_completion.d/aidetector",
			"aidetector completion fish > ~/.config/fish/completions/aidetector.fish",
		},
	},
	"mcp": {
		Invocation: "mcp",
		Synopsis:   "serve the setup tools and guides to a coding agent (MCP over stdio)",
		Description: "Run a Model Context Protocol server on stdin/stdout for Claude Code, Cursor " +
			"or another agent, started in the project's directory. It serves the setup guides " +
			"and tools that find the spec, draft and validate aidetector.yml, and list the " +
			"commands to run. It cannot start a scan and never handles a secret value; it reads " +
			"only inside the directory it was started in.",
		Examples: []string{
			"claude mcp add aidetector -- aidetector mcp",
			"claude mcp add --scope project aidetector -- aidetector mcp",
		},
	},
	"version": {
		Invocation: "version",
		Synopsis:   "print the CLI version",
		Description: "Print the CLI version, the platform it runs on and the Go toolchain " +
			"that built it.",
		Examples: []string{"aidetector version", "aidetector --version"},
	},
	"target": {
		Invocation: "[URL] [DIR] [flags]",
		Synopsis:   "scan an API in one step — the everyday form",
		Description: "Scan an API: reuse or create its scan, find a spec and identities, run it " +
			"and print what it found. A directory also reads that code in a local run; no " +
			"argument runs what ./aidetector.yml describes. With --fail-on, --output picks " +
			"the gate format: table, json, github workflow commands, or junit XML.",
		Examples: []string{
			"aidetector https://api.example.com",
			"aidetector https://api.example.com ./my-project",
			"aidetector --authorized      # inside a project: run what aidetector.yml says",
			"aidetector --authorized --fail-on high --output github",
		},
	},
}

// commandHelp implements `aidetector help CMD`. Asking the command itself for
// -h is what builds the flag set, so there is one list of flags, not two.
func commandHelp(ctx context.Context, e *Env, name string) int {
	if _, ok := commandDocs[name]; !ok {
		return e.usage("unknown command %q (try `aidetector help`)", name)
	}
	if name == "target" {
		return cmdTarget(ctx, e, []string{"-h"})
	}
	return Run(ctx, []string{name, "-h"}, *e)
}

// wantsHelp reports whether args ask for help before any subcommand, as in
// `aidetector scans -h`.
func wantsHelp(args []string) bool {
	return len(args) > 0 && (args[0] == "-h" || args[0] == "--help")
}

// printCommandHelp prints the command's help, then its flags, to stdout.
func (e *Env) printCommandHelp(cmd string, fs *flag.FlagSet) int {
	doc, ok := commandDocs[cmd]
	if !ok {
		return e.usage("unknown command %q (try `aidetector help`)", cmd)
	}
	e.printf("aidetector %s\n  %s\n\n%s\n", doc.Invocation, doc.Synopsis, doc.Description)
	if len(doc.Examples) > 0 {
		e.printf("\nexamples:\n")
		for _, ex := range doc.Examples {
			e.printf("  %s\n", ex)
		}
	}
	e.printFlags(fs)
	return ExitOK
}

// printFlags prints a flag set in two groups: ordinary flags, and the run
// passes, which are all off by default and cost the target real traffic.
func (e *Env) printFlags(fs *flag.FlagSet) {
	if fs == nil {
		return
	}
	var plain, passes []*flag.Flag
	fs.VisitAll(func(f *flag.Flag) {
		if _, ok := passField(f.Name); ok {
			passes = append(passes, f)
		} else {
			plain = append(plain, f)
		}
	})
	if len(plain) > 0 {
		e.printf("\nflags:\n")
		for _, f := range plain {
			e.printFlag(f)
		}
	}
	if len(passes) > 0 {
		e.printf("\npasses (every pass is off unless you set it):\n")
		for _, f := range passes {
			e.printFlag(f)
		}
	}
}

// flagColumn is where a flag's usage starts; the format adds two spaces.
const flagColumn = 25

// printFlag prints one flag as `  --name VALUE   usage (default: x)`.
func (e *Env) printFlag(f *flag.Flag) {
	label := "  --" + f.Name
	if v := flagValueName(f); v != "" {
		label += " " + v
	}
	_, usage := flag.UnquoteUsage(f)
	if def := flagDefault(f); def != "" {
		usage += " (default: " + def + ")"
	}
	e.printf("%-*s  %s\n", flagColumn, label, usage)
}

// flagPlaceholders names what a flag takes. The flag package can only say
// "string", which tells a reader nothing about --checks or --fail-on.
var flagPlaceholders = map[string]string{
	"auth-type": "TYPE", "check": "KEY", "checks": "KEYS", "config": "FILE",
	"docker-network": "NETWORK", "every": "DURATION", "fail-on": "SEV",
	"format": "FORMAT", "header-name": "HEADER", "identity": "NAME", "image": "IMAGE",
	"level":  "LEVEL",
	"method": "METHOD", "min-severity": "SEV", "name": "NAME", "o": "FILE",
	"output": "FORMAT", "profile": "NAME", "role": "ROLE", "route": "TEXT",
	"runner-server": "URL", "secrets-file": "FILE", "server": "URL", "source": "DIR",
	"spec": "FILE", "status": "CODE", "target": "URL",
}

// flagValueName is the placeholder after --name: nothing for a boolean, a
// backquoted name from the usage, the table above, else the flag's type.
func flagValueName(f *flag.Flag) string {
	if b, ok := f.Value.(interface{ IsBoolFlag() bool }); ok && b.IsBoolFlag() {
		return ""
	}
	if strings.Contains(f.Usage, "`") {
		name, _ := flag.UnquoteUsage(f)
		return name
	}
	if name, ok := flagPlaceholders[f.Name]; ok {
		return name
	}
	if g, ok := f.Value.(flag.Getter); ok {
		switch g.Get().(type) {
		case time.Duration:
			return "DURATION"
		case int:
			return "N"
		}
	}
	return "VALUE"
}

// flagDefault is the default to show: only a non-zero, non-empty one.
func flagDefault(f *flag.Flag) string {
	switch f.DefValue {
	case "", "false", "0", "0s":
		return ""
	}
	return f.DefValue
}
