# aidetector CLI

A single static binary that drives an aidetector server from the terminal — create a
scan, run it, and gate a pipeline on what it found. Every run it starts sends its traffic
from **this machine**, in a locked-down container; the service keeps the record (findings,
the full request log), runs the AI analysis and renders the reports.

Go is **not** required on your machine: everything builds and tests in the official
`golang:1.23` image.

```bash
make cli            # build cli/bin/aidetector for this machine
make cli-all        # macOS, Linux and Windows binaries into cli/bin
make test-cli       # gofmt + vet + race-enabled tests
make cli-contract   # refresh cli/testdata/openapi.json from the running api
```

## Quick start

You only need the CLI for the extras. The web **Run** button already does the quick scan;
the CLI adds the AI passes and can read your project's code.

**Once:**

```bash
make install-cli      # puts aidetector in /usr/local/bin
make runner-image     # only if you will scan with your code (the "." below)
aidetector login      # paste an API key from Workspace → API tokens
```

**Then pick one:**

| I want to… | Run |
| --- | --- |
| scan my live API | `aidetector https://my.site` |
| …and point findings at my code | `cd my-project && aidetector https://my.site .` |
| look harder than the quick scan | add `--level standard` (or `deep`) |
| allow tests that change target data | add `--writes` |
| add the AI passes | add `--ai` |
| fail CI on a high finding | add `--authorized --fail-on high` |

It asks you to confirm you own the target, runs, prints the findings and a `view:` link to
the scan's page.

**Or set it once** in `my-project/aidetector.yml`:

```yaml
target: https://my.site
level: standard
passes: [ai]
```

and from then on just run `aidetector` in that folder.

The AI passes need `DEEPSEEK_API_KEY` set on the server; without it they are skipped (the
scan still runs). `--writes` is never implied by a level: it is the one
flag that lets a run change target data.

**A full pipeline, step by step** — the same commands, against a local server:

```bash
aidetector login --server http://127.0.0.1:8000 --no-key     # local dev, auth off
aidetector login                                              # https://aidetector.com; prompts for the API key

ID=$(aidetector scan create --target https://api.example.com --spec openapi.json)
aidetector cred add $ID --name alice --role user  --auth-type bearer     # secret: prompt
echo "$ADMIN_TOKEN" | aidetector cred add $ID --name admin --role admin \
    --auth-type bearer --secret-stdin

aidetector run $ID --authorized --level standard --fail-on high --verified-only
aidetector findings $ID --min-severity high
aidetector report $ID --format sarif -o results.sarif
```

Everything below is the detail.

## The everyday form

```bash
aidetector login                                        # once; the server defaults to https://aidetector.com

aidetector https://api.example.com                      # scan this API
aidetector https://api.example.com ./my-project         # ...and read the code in ./my-project
aidetector                                              # inside a project: run what aidetector.yml says
```

`aidetector URL` does what the subcommands below do, in one step:

1. **Asks for consent** naming the target (or takes `--authorized`), before any request goes
   to it.
2. **Finds the scan.** It reuses the scan whose target matches (case, trailing slash and
   default ports don't matter; the one with the latest run wins). That keeps identities,
   triage and the diff. `--new` forces a fresh scan; `scan: <id>` in `aidetector.yml` pins one.
3. **Finds a spec**, first match wins: `--spec FILE`, `spec:` in `aidetector.yml`, an
   `openapi.*` / `swagger.*` / `*.openapi.*` file in the project (three levels deep,
   vendored trees skipped), the scan's saved spec, then the target's own `/openapi.json`,
   `/swagger.json`, `/v3/api-docs` and similar. An unchanged spec is not re-uploaded, so the
   operation selection made in the web survives.
4. **Checks identities.** A scan with none prompts for them in a terminal. Without a
   terminal it warns that the authorization checks will be skipped.
5. **Runs it, waits, prints the findings.** `--fail-on`, `--verified-only` and `--new-only`
   gate exactly as with `run`.

**A directory adds your code**, as with `run --source DIR`: the project is mounted
read-only into the runner and findings carry file:line citations.

Every run option of `run` works here too: `--level quick|standard|deep`, `--writes` and
`--ai`, plus the advanced pass flags (`--agent`, `--zap`, …). `--writes` and
every pass stay off unless asked for; a level never turns writes on.

## aidetector.yml — the project file

Commit this at the root of the repository, and `aidetector` alone (or
`aidetector --authorized` in CI) does the right thing:

```yaml
target: https://staging.example.com
spec: openapi.yaml            # relative to this file
level: standard               # quick | standard | deep
fail_on: high
identities:
  - { name: alice, role: user,  secret_env: ALICE_TOKEN }
  - { name: admin, role: admin, auth: header, header: X-Api-Key, secret_env: ADMIN_TOKEN }
```

`aidetector init [URL]` writes a starting file from the spec's `securitySchemes`. The file
names environment variables, never secrets, and never holds consent. Every key, the three
ways to describe authentication (`auth: public`, `token_env:`, `identities:`), token-minting
grants and how the file and the web share settings are in
[docs/project-file.md](docs/project-file.md).

## Set it up with your coding agent

`aidetector mcp` is a Model Context Protocol server for Claude Code, Cursor or any other
MCP client. Started in a project, it gives the agent the guides in [docs/](docs/) and tools
to find the spec, draft and validate `aidetector.yml` with this CLI's own loader, and list
the commands for you to run:

```bash
claude mcp add --scope project aidetector -- aidetector mcp   # writes .mcp.json; commit it for the team
```

Other clients take the same command (`aidetector`, args `["mcp"]`). Then ask the agent to
"set up aidetector for this project". The agent follows
[docs/setup.md](docs/setup.md), which is also the server's `setup_aidetector` prompt.

The server **cannot start a scan**: the person running it must still confirm they are
authorized to test the target. It never takes or returns a secret value, only environment
variable names, and reads only inside the directory it was started in. The one thing it
sends anywhere is the spec's text, to your aidetector server, for the same auth hints
`init` uses.

## Commands

| command | does |
| --- | --- |
| `login [--server URL] [--profile NAME]` / `logout` / `status` | save a server (default https://aidetector.com) as a profile, remove the current profile, and check the connection |
| `profile list` · `profile use NAME` · `profile rm NAME --yes` | manage saved server profiles (one server and key each) |
| `init [URL] [--spec FILE] [--yes] [--force]` | write an `aidetector.yml` shaped by the spec's auth (public, one key, or roles) |
| `scans list [--target URL] [--full-ids]` · `show [ID]` · `rm ID --yes` | manage scans |
| `scan create --target URL --spec FILE` | create a scan and ingest a spec (OpenAPI, Swagger, HAR, Postman) |
| `cred add ID … [--privilege N] [--update]` · `cred list [ID]` · `cred rm ID NAME\|ID --yes` | manage identities (the secret is write-only on the server) |
| `run ID [--level L] [--writes] [--ai] [pass flags]` | run a scan from this machine and wait for it, AI analysis included |
| `wait ID [--fail-on SEV]` | attach to a run still going (or its result), then gate |
| `cancel ID` | stop a running scan at the next check boundary |
| `findings [ID] [--check KEY]` · `findings show [ID] FINDING` · `findings dismiss\|confirm\|reopen [SCAN] FINDING…` | list results, show one in full (ID or fingerprint prefix), or triage findings |
| `cost [ID] [--json]` | AI spend: total, per model and per phase |
| `coverage [ID] [--json] [--untested]` | what the latest run did to each endpoint; `--untested` lists the never-probed |
| `diff [ID]` | compare the two latest runs |
| `runs [ID] [--limit N]` | run history: status, duration, requests, passes, gaps |
| `runs trace [ID] [RUN] [--check KEY] [--identity N] [--status S] [--seq N]` | one run's redacted request/response log |
| `report [ID] --format pdf\|html\|pentest\|sarif\|json [-o FILE]` | download a report (default `aidetector-<id8>.<ext>`) |
| `completion bash\|zsh\|fish` | print a shell completion script (generated from this build) |
| `mcp` | serve the setup guides and tools to a coding agent over stdio ([above](#set-it-up-with-your-coding-agent)) |
| `version` | print the CLI version (also `--version` / `-v`) |

A scan ID may be the full UUID or its first 4+ hex characters. Where `[ID]` is
optional, `scan:` in `aidetector.yml` (or else the latest scan for its `target:`)
picks the scan.

`aidetector help <command>` prints that command's flags, what each pass costs, and
examples — `aidetector run -h` does the same.

The everyday choices are three words: `--level quick|standard|deep` (how hard to look),
`--writes` (allow tests that change target data; a level never implies it) and `--ai` (the
AI passes that fit the level; spends tokens). The advanced pass flags mirror the server's
`RunRequest`, and **every pass is off unless you ask for it** — what each one does and costs
is in [docs/levels-and-passes.md](docs/levels-and-passes.md).

## Use it as a CI gate

```bash
aidetector run "$SCAN_ID" --authorized \
    --fail-on high --verified-only --new-only
```

Exit codes: `0` clean, `1` findings reached `--fail-on`, `2` usage/auth, `3` failed,
`4` timeout. `--output github|junit|json` for CI-native reports, `report --format sarif` for
code scanning. Details in [docs/ci-gate.md](docs/ci-gate.md).

## Recurring scans

The CLI has no schedules: every run sends its traffic from the machine that starts it, so a
recurring scan is a CI job (or cron entry) that runs `aidetector --authorized` on that
interval. The web's schedules are server runs and stay in the web.

## How a run works

Every run sends the scan from **your machine** in a locked-down throwaway container, so it
can reach internal hosts and read your code; the results, the request log and the AI
analysis live on the service. Secrets stay on this machine and reach
the container on stdin only. Setup, secret lookup order and limits are in
[docs/local-runs.md](docs/local-runs.md).

## Safety

The authorization gate stays (no file key or default skips it), public targets need
verified ownership, writes are opt-in, secrets are never flags or file values, and the
request budget stays. The full list is in [docs/safety.md](docs/safety.md).

## Configuration

`login` saves a named profile in your user config directory: one server and its API
key, plus which profile is current. Save several and switch between them:

```bash
aidetector login                                                    # profile "default", https://aidetector.com
aidetector login --server https://staging.example.com --profile staging
aidetector profile list          # NAME, SERVER, KEY set/none; * marks the current one
aidetector profile use staging   # make staging current
AIDETECTOR_PROFILE=staging aidetector status   # ...or just for one command
aidetector profile rm staging --yes
aidetector logout                # removes the current profile only
```

A profile name is 1–32 lowercase letters, digits, `-` or `_`, starting with a letter
or digit. `login` without `--profile` writes to the current profile (or `default` when
none is current) and makes it current. `profile list` never prints a key, only
whether one is set. Removing a profile asks first and refuses without a terminal
unless you pass `--yes`; the last profile gone deletes the file.

The environment still wins over the file, so CI needs no file at all:

- `AIDETECTOR_PROFILE` selects a saved profile for this command (an unknown name is
  a usage error listing the known ones).
- `AIDETECTOR_SERVER` and `AIDETECTOR_API_KEY` override the selected profile's values.
- `AIDETECTOR_CONFIG` points at a different config file.

The file is written `0600` in a `0700` directory and refused on read if anyone else
can open it. A flat `{server, api_key}` file from an earlier version still loads as
the `default` profile.

## How it stays in sync with the server

The client is hand-written, because FastAPI emits OpenAPI 3.1 and the Go generators only
partly support it. Two tests keep it honest:

- **Go** — `internal/api/contract_test.go` fails if a route the client calls is not in
  the server's OpenAPI document; `internal/commands/contract_test.go` fails if a
  `RunRequest` boolean the server accepts can't be sent (or a flag names a field the
  server dropped).
- **Python** — `services/api/tests/test_cli_contract_snapshot.py` fails when
  `cli/testdata/openapi.json` stops matching the live app, so the Go tests can never be
  reading a stale snapshot. When the API contract changes: `make cli-contract`, then
  `make test-cli`, and commit both.

Adding a run flag to the engine therefore means: one `RunOptions` field, one checkbox in
`RunPanel`, and one entry in `RunFlags` (`internal/commands/run.go`).
