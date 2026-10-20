# CLI local lane — the plan

**Direction (the user's words):** "from cli all the tests should be run from local,
reports and ai analysis is done on official service, we also record the tests."

So the CLI lane becomes one shape: **every request to the target leaves from the CLI
machine; the official service (runpentests.com) holds the record, does the AI and
renders the reports.** The web stays the fast lane and keeps server runs; this plan is
about the CLI only.

Read with `CLAUDE.md` (its safety constraints are binding) and
`docs/roadmap/cli-heavy-lane-handoff.md` (how the local runner came to be).

State this was written against: `main` @ `fc5931b`, production on `c7488df`.

---

## Where it stands — cheapmonit as the worked example

`make scan` in `/Users/tomaszlopusiewicz/htdocs/cheapmonit` (target `http://caddy/api/v1`,
level `standard`, writes on, schema context on) on 2026-10-19:

| Goal | What happened | Gap |
| --- | --- | --- |
| Tests run locally | 31 engine checks ran from the laptop's runner container | ZAP, Kali (nuclei/ffuf/katana/arjun), the confirm tools and testssl are refused at claim (`run_levels.LOCAL_REFUSED`) |
| | `oob_injection`, `unsafe_consumption`: "did not run: no out-of-band collector" | the runner has no OAST collector; production sets no `OAST_SERVER` |
| | `genai_payloads`, `adaptive`, `resource_refine` refused | the AI sits inside the testing loop and only runs server-side |
| | a URL-only `aidetector URL` still runs on the server unless the target is loopback | two lanes in the CLI (`--local` / `--no-local`, `target.go` `useLocal`) |
| Tests recorded | 202 requests made; `aidetector runs trace` shows "0 request(s) in the run" | `RunnerComplete` has no trace or manifest field; `append_finding` gets `probe=None`, so findings carry no `trace` links |
| AI on the service | `ai spend: $0.0000` | after an upload only `security_review` runs (`workers/tasks.py:review_local_run`); adjudication never runs for a local run |
| Reports on the service | `aidetector report` works from uploaded findings | without the trace a report cannot show the requests behind a finding |

Two bugs, not design gaps, were found on the way and are fixed: routes doubled to
`/api/v1/api/v1/...` after a target change (`fc5931b`, needs a deploy plus re-saving the
scan's target), and cheapmonit's Caddy not answering `Host: caddy` (cheapmonit's
`docker-compose.local.yml`, uncommitted there).

---

## Invariants every step keeps

These are CLAUDE.md rules restated for this lane; a step that cannot keep one stops.

- **One explicit authorization per run.** The claim (`POST /scans/{id}/local-runs`) answers
  `_require_run_authorization`, the target guard and ownership; nothing below adds a way to
  start traffic without it.
- **Secrets stay on the CLI machine.** Credential and schema secrets reach containers on
  stdin only, never argv, env or the server. The container holds the per-run token, never
  the API key.
- **The request budget is the server's to issue.** Anything that sends target traffic counts
  against it or against a separately issued, separately reported budget (the adjunct
  wall-clock budget is one).
- **Writes stay behind `mutate`.** No step turns on a write by default.
- **A pass that did not run never reads as clean.** Every refusal, skip or tool failure
  lands in `gaps` (`not_run`, `skipped_checks`, `failed_checks`) so the diff says
  `not_retested`.
- **Identity and remediation are the server's** (`append_finding`), never the runner's.
- **Redaction twice:** in the runner with the secrets it holds, then pattern-only on the
  server over whatever crossed the wire.
- **AI failures degrade.** No AI problem fails a run or blocks an upload.

---

## Step 1 — Record the tests (upload the trace and manifest)

**Goal.** A local run is as inspectable as a server run: the trace tab, evidence links and
report evidence work.

**Design.**
- Runner: add `trace` (`probe.mutations`, already redacted by the runner's `Redactor` and
  bounded by `_BODY_BUDGET`, ~1 MB) and `manifest` (`methodology.finish_manifest`) to the
  bundle `app/runner/main.py` builds.
- Schema: `RunnerComplete.trace: list[TraceRow]` with a row model mirroring the server's
  row keys and per-field caps (row count ≤ the issued budget + discovery headroom, body
  samples ≤ 4000 chars), and `manifest: dict` validated by shape.
- Server (`routes/runner.py:runner_complete`): re-redact every row pattern-only, store on
  `ScanRun.mutations`, then stamp findings' `trace` links. `append_finding` takes a probe
  today; give `_trace_links` a rows-only path (it only reads `probe.mutations`) so the
  route passes the uploaded rows.
- Reject a trace whose row count exceeds the issued budget, like `requests` today.

**Touch points.** `app/runner/main.py`, `app/api/schemas/runner.py`,
`app/api/routes/runner.py`, `app/engine/run_record.py`, `cli/testdata/openapi.json`
(`make cli-contract`).

**Tests.** A runner-complete test uploads rows carrying a secret-shaped value and asserts
it is masked; an over-budget trace is 422; a finding gets `trace` links to its rows;
`GET /scans/{id}/runs/{n}/trace` pages the uploaded rows. The layering test still imports
`app/runner/main.py` with SQLAlchemy blocked.

**Done when** the cheapmonit run shows its 200-odd rows in `aidetector runs trace` and the
web trace tab, and a finding links to the requests that made it.

**Size:** small–medium. No migration (`ScanRun.mutations` and `manifest` exist).

---

## Step 2 — AI analysis after upload (adjudication on the service)

**Goal.** `--ai` on a local run gets the same verdicts and evidence-specific fixes as a
server run, with no target traffic from the server.

**Design.**
- Drop `adjudicate` from `LOCAL_REFUSED`.
- After `runner_complete` commits, enqueue a worker task (sibling of `review_local_run`)
  that runs `ai_phases.adjudicate_findings` over the stored findings, then
  `run_record.apply_triage` again so a person still outranks the model. Token ledger and
  budget reservations (`0047`) as on the server path.
- The run reads `completed` at once; adjudication is a follow-up shown as in progress
  (like `security_review` today), so a slow model never holds the CLI. `--wait` waits for
  it only when `adjudicate` was requested.
- Combine with `security_review` into one post-upload task so there is one place that
  decides what AI runs after a local upload.

**Touch points.** `app/scans/run_levels.py`, `app/api/routes/runner.py`,
`app/workers/tasks.py`, `app/engine/ai_phases.py`, CLI wait/summary
(`cli/internal/commands/local.go`), web run status.

**Tests.** A local run with `adjudicate` sets verdicts via `FakeCascade`; a broken cascade
leaves `unreviewed` and an `ai_skipped` event; a triage verdict set before the upload
still wins; spend shows in `/cost`.

**Done when** `make scan ARGS="--authorized --ai"` in cheapmonit ends with verdicts on its
BOLA/BFLA/SSRF findings and non-zero AI spend.

**Size:** small–medium. No migration.

---

## Step 3 — The CLI runs locally, always

**Goal.** One path in the CLI: every scan it starts is a local run.

**Design.**
- `aidetector URL [DIR]` and `aidetector run` become local runs by default; remove
  `--no-local` and the server branch in `target.go`. `aidetector.yml`'s `local:` key
  becomes redundant (accepted and ignored for a release, with a note, then refused).
- `--local` stays accepted as a no-op for scripts.
- The CLI checks for Docker and the runner image up front and says how to get them
  (`make runner-image`, or a published image tag) instead of failing after the claim.
- Server side unchanged: the web fast lane still runs on the server; the API still
  accepts every flag.

**Decision needed — schedules.** `aidetector schedule` creates *server-side* scheduled
runs, which contradicts "all tests local". Options: (a) the CLI stops offering
`schedule` and the docs show a cron / CI job running `aidetector` instead; (b) keep it
as the one server-run path, labelled as such. Recommendation: (a), since a CI job is how
a local-lane user schedules anyway.

**Touch points.** `cli/internal/commands/target.go`, `run.go`, `schedule.go`,
`cli/internal/project` (the `local:` key), `cli/docs/*.md`, `cli/README.md`, the mcp
tool list if it names lanes.

**Tests.** Go tests: a URL-only run claims a local run; `--no-local` is a usage error
naming the change; a missing image fails before the claim. `TestGuidesMirrorTheProjectFileAndTheFlags`.

**Done when** no CLI command can start server-side target traffic (apart from what the
schedules decision keeps).

**Size:** small. CLI only.

---

## Step 4 — Out-of-band collector from the service

**Goal.** Blind SSRF / RCE / XXE / ESI and `unsafe_consumption` run on local scans.

**Design.**
- The service runs `interactsh-server` publicly (it is already a compose profile, `oob`)
  under its own domain (e.g. `oast.runpentests.com`), with a token.
- The claim returns `oast: {server, token}` when configured. The runner image is built
  with `WITH_INTERACTSH=1` and starts `InteractshClient` against it; the session keypair
  lives in the runner, so callbacks correlate there.
- The target must reach the OAST domain over the internet. A target with no egress
  (cheapmonit's `internal` network) cannot call back; that is reported as the check's
  `inapplicable` reason, not as a clean result.
- The OAST token is per-deployment, not a tenant secret; still pass it on stdin.

**Touch points.** `app/api/routes/runner.py` (claim), `app/api/schemas/runner.py`,
`app/runner/main.py`, `app/engine/oob.py`, `services/api/Dockerfile` (runner build arg),
`deploy/` (interactsh service, DNS), `docs`.

**Decision needed.** Hosting a public interactsh server means DNS delegation (NS records
for the OAST domain) on the production host. Confirm the domain.

**Tests.** Runner test with a fake `spawn` that emits a callback; claim carries `oast`
only when configured; a runner with no collector still reports both checks as skipped.

**Done when** a local scan of the bundled vulnerable target records a verified OOB
finding through the service's collector.

**Size:** medium (most of it is deployment).

---

## Step 5 — Heavy tools locally (ZAP, Kali, confirm tools, testssl)

**Goal.** The deep level works on the CLI lane, with every tool's traffic leaving from the
CLI machine.

**Resolved architecture (worked out 2026-10-19 on `cli-heavy-tools-local`).** Two
corrections to the first sketch, each from reading the code:

1. **No new `services/tools` image.** The confirm tools (sqlmap/dalfox/commix/tplmap) and
   testssl are not HTTP services — `app/engine/*_confirm.py` and `testssl_scan.py` shell
   out to a local binary named by `*_BIN`. The runner already sends target traffic from
   its own container, so the simplest correct home for these is **inside the runner image**
   (`services/api/Dockerfile` already documents the `*_BIN` apt installs as build args).
   They then run in-process in the runner with no sibling and no Docker socket — the same
   posture as the engine tier. Only ZAP and Kali are real network services, and those the
   CLI starts as **siblings** (existing images: `ghcr.io/zaproxy/zaproxy`, `services/kali`)
   on the `--docker-network`, passing their URLs to the runner as `zap_base_url` /
   `kali_base_url`.

2. **The confirm tools select targets from engine *findings*, which differ by lane.**
   `select_sqli_targets(cast(list[Finding], scan.findings))` reads ORM `Finding` objects;
   in the runner the findings are dicts in `journal.findings`. So the confirm passes cannot
   move to the runner unchanged — the selectors must read a lane-neutral shape (a small
   dataclass, or the finding dicts the runner already has). ZAP, Kali and testssl do **not**
   select from findings, so they move first and the confirm tools are a second slice.

**The DB-free split (the foundation, verifiable on its own).** `app/engine/adjuncts.py`
imports `Session`, `Scan`, `Finding` at module level, so it cannot be in `PURE_MODULES`.
Split the execution core — `AdjunctUnavailable`, `_reported`, `run_adjunct`,
`require_binary`, `AdjunctPhase`, and the pass builders `run_zap`/`run_kali`/`run_testssl`
— into a DB-free module whose functions take an **`AdjunctSink`** Protocol instead of
`(db, scan, emit)`:

```
class AdjunctSink(Protocol):
    progress: int
    target_base_url: str
    operations: Sequence[TargetOperation]
    def record(self, findings: Sequence[EngineFinding]) -> None: ...
    def event(self, stage: str, pct: int, message: str) -> None: ...
```

The server builds a sink wrapping `(db, scan, redactor)` whose `record` is
`append_findings` + `db.commit()` (today's behaviour, so the existing adjunct tests still
pass unchanged); the runner builds one wrapping the journal whose `record` calls
`journal.record` per finding. Add the new module to `PURE_MODULES` in
`tests/test_layering.py`. This slice changes no behaviour and is fully covered by the
current `test_adjunct_gating.py` / `test_run_gaps.py` — do it and commit it before any
runner wiring.

**Then, per slice:**
- The runner runs the phase as the worker does: one wall-clock budget
  (`adjunct_budget_seconds`), cancellation between passes, `<tool>_skipped` / `gaps.not_run`
  for anything that did not run, the pin-drift check before each pass. `discovery_probe`
  already runs in the runner.
- The claim issues the adjunct wall-clock budget alongside the request budget, drops the
  now-runnable passes from `LOCAL_REFUSED` as each lands, and the upload reports time used.
- The CLI starts the ZAP/Kali siblings on the `--docker-network`, waits for health, passes
  the URLs into the runner config, and tears them down on exit (Ctrl-C included). Images
  pinned by digest, pulled on first use with a size prompt (the step-3 `ensureImage` path
  already exists for the runner image — reuse it).

**Order:** DB-free split → runner ZAP/Kali via sibling URLs → confirm tools + testssl baked
into the runner image (with the selector-shape fix) → shrink `LOCAL_REFUSED` to nothing.

**Touch points.** New `app/engine/adjunct_run.py` (pure); `app/engine/adjuncts.py` becomes
the server shim; `tests/test_layering.py`; `app/runner/main.py`; `app/api/routes/runner.py`
(claim budget + tool URLs in config); `services/api/Dockerfile` (confirm/testssl binaries);
`cli/internal/commands/local.go` (sibling lifecycle); `run_levels.py`; docs.

**Decision needed.** Whether `--level deep` downloads the ZAP/Kali images (~1–2 GB) on first
use or the CLI asks first. Recommendation: ask once per image, reusing `ensureImage`.

**Verification gap (important).** ZAP, Kali and the confirm tools cannot be exercised
end-to-end in the dev container used so far — there are no such images/binaries to point at,
and this touches the precision/detection gates. The verifiable-here parts are: the DB-free
split (existing adjunct tests + layering test), the claim/budget/`LOCAL_REFUSED` changes
(API tests), the runner phase with **fake** ZAP/Kali HTTP doubles, and the Go sibling-args
tests (no socket mount, right networks, teardown). A real `--level deep` run against the
bundled vulnerable target must be done where the images are available before this is called
done.

**Size:** large. The DB-free split is the safe first commit; the rest is per-slice.

---

## Step 6 — AI inside the testing loop, served by the service

**Goal.** `genai_payloads`, `adaptive` and `resource_refine` work on local runs.

**Design.**
- Same pattern as `POST /runner/runs/{id}/plan`: the runner asks the service, the service
  calls the model, meters it, and returns structured proposals; the runner sends the
  traffic. One token-auth endpoint per mode, or one `POST /runner/runs/{id}/ai` with a
  `mode`.
- What the runner sends is redacted, bounded and evidence-shaped (status, field names,
  error excerpts), never raw response bodies, and the service treats it as data, never
  instructions (the guard in `ai_runtime/plan_agent.py`).
- Each proposal still runs through the engine's grading; the model never marks a finding
  verified.
- Per-run AI call cap issued at claim, like the request budget; spend lands in the run's
  ledger.

**Touch points.** `app/api/routes/runner.py`, `app/runner/main.py`,
`app/engine/adaptive/` (`runner.py`, `policy.py`), the `genai_payloads` path in
`app/engine/ai_phases.py`, `resource_bootstrap.py` (`_ai_propose`),
`run_levels.py`.

**Tests.** Runner tests with a fake service endpoint; an endpoint refusal or timeout leaves
the deterministic path and an `ai_skipped` event; caps enforced server-side.

**Done when** a local premium run with `--ai` spends tokens on these modes and its
findings carry the same grading as a server run's.

**Size:** medium.

---

## Suggested order

1. **Step 1** and **Step 2**: contained and independent; together they give cheapmonit a
   recorded, AI-reviewed report. They can run in parallel (different files, apart from
   `runner_complete`, so land 1 first or coordinate).
2. **Step 3**: small, and simplest once 1–2 make local runs complete.
3. **Step 4**: mostly deployment; unblocks the OOB checks.
4. **Step 5**: the big one, tool by tool.
5. **Step 6**: last; needs 2's post-upload AI plumbing and benefits from 5.

## Decisions to make before starting

| # | Decision | Recommendation |
| --- | --- | --- |
| 1 | CLI `schedule` (step 3) | drop it from the CLI; document cron/CI |
| 2 | OAST domain and DNS (step 4) | a subdomain of runpentests.com with NS delegation |
| 3 | First-use image download for deep (step 5) | ask once per image |
| 4 | Keep `--local` as a no-op (step 3) | yes, for one release |
