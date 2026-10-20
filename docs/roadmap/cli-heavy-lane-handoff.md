# CLI heavy lane — handoff for the next session

Everything a fresh session needs to continue. Read this, then `CLAUDE.md` (the safety
constraints there are binding), then `cli/README.md`.

State as of `main` @ `1de1075`. **Nothing is pushed to any remote.** The working tree was
clean when this was written.

---

## 1. What was decided (the user's directions, in their words where it matters)

- **Two lanes.** The web/server path is the **fast lane**: engine tier only, ~6 s,
  deterministic. The **CLI is the heavy lane** and "can do the heavy scans".
- **Evolve, don't rebuild.** The user asked whether to rebuild along the lines of
  [vxcontrol/pentagi](https://github.com/vxcontrol/pentagi) and chose to **keep the graded
  engine** (verified vs heuristic evidence, fingerprint identity, diff, triage, the
  precision gates) as the verification backbone, and *borrow* ideas from pentagi. Their
  reasoning matters: an autonomous LLM agent does not guarantee the precision this
  product's `tests/test_precision.py` / `safeapp` discipline exists to protect.
- **Bounded agent, not autonomous multi-agent.** One agent drives the existing engine plus
  a few sandboxed tools, with hard caps. No Neo4j/Graphiti, no multi-provider routing.
- **Whitebox.** The CLI "can execute inside the repository / project and has access to the
  codebase". The point is source-aware analysis (confirm a finding against code, explain it
  with file:line, steer which checks/params to probe) — what pentagi (blackbox) lacks.
- **"Skip allowing adding repository in the web"** — the monitoring page's GitHub
  repo/token fields were removed (done). The backend connector still exists, unused.
- **Scans must be able to originate from the CLI machine** ("Go client … run all the prepared
  tests … nothing executed on the server") — done for the engine tier as `run --local`.
- **AI = DeepSeek only, turn Opus off** — done: `PLANNER_PROVIDER=deepseek` is the default.
- **Go** for the CLI ("what is the best tool … golang"). Go is **not installed on the host**;
  everything builds in the `golang:1.23` image via `make`.
- Work is done inline in the main session; delegating to Flash (`scripts/flash`) is no
  longer the default and happens only when asked.

---

## 2. What is built and merged to `main`

| Area | What | Where |
| --- | --- | --- |
| Fast-lane web | Run panel offers only schema fuzzing, test-writes, premium; no preset turns on ZAP/Kali/confirm/AI; monitoring GitHub fields removed | `apps/web/app/components/RunPanel.tsx`, `checkScope.ts`, `apps/web/app/monitoring/page.tsx` |
| DeepSeek-only AI | `settings.planner_provider` (`deepseek` default, `anthropic` opt-in); every agent mode is one direct DeepSeek completion; no Agent SDK / `claude` CLI / `.venv-ai` needed | `app/ai/planner.py`, `ai_runtime/plan_agent.py`, `app/core/config.py` |
| AI subprocess hardening | Env **allowlist**, so VAULT_KEY/DATABASE_URL/etc. never reach the AI subprocess | `app/ai/subprocess_env.py` |
| Kali fix | nuclei remediation/CVE/CWE/references forwarded; info-level matches graded heuristic | `services/kali/app/main.py`, `app/engine/kali.py` |
| DB-free engine core | `_run_engine_checks`, id seeding, resource setup, cleanup, discovery probe | `app/engine/execution.py` (in `PURE_MODULES`) |
| Run identity | `ScanRun.executor`, `run_token_hash` (migration `0036`); hashed per-run token | `app/models/scan.py`, `app/scans/run_token.py` |
| Ingest API | claim `POST /scans/{id}/local-runs`; token-auth `POST /runner/runs/{id}/{events,heartbeat,complete,fail}`; bundle validation | `app/api/routes/runner.py` |
| Lifecycle | reaper clears a dead run's token; diff `executor_changed`; web "local runner" chip | `app/scans/reaper.py`, `RunInsights.tsx` |
| Runner | one-shot container, engine tier w/o a DB, HTTP-backed `RunJournal` | `app/runner/main.py` (in `PURE_MODULES`), `make runner-image` |
| Go CLI | login/status, scans, scan create, cred add, run, cancel, findings, diff, report, CI exit codes, `run --local` | `cli/` |
| Drift guards | Go contract tests + `tests/test_cli_contract_snapshot.py` against `cli/testdata/openapi.json` | see §6 |

Merged branches (all local, all contained in `main`): `fix/kali-nuclei-metadata`,
`feat/web-two-lane`, `feat/deepseek-planner`, `feat/cli-heavy-lane`, `feat/go-cli`,
`feat/local-runner-entrypoint`. **`master` is 122 commits behind `main` and missing files the
code needs — base everything on `main`.**

---

## 3. What remains

### 3a. Small, do first
1. **`cred add --shape-only`.** Today `cred add` must send a secret to the server
   (`CredentialCreate.secret` is required), because the claim returns credential *shapes*
   from the server's profiles. For a local run the server's copy is ignored, but the secret
   has still reached the server once — the one place the "secrets stay local" story leaks.
   Send a placeholder + flag the profile as local-only (needs a server-side marker so the
   server runner never uses it, and so it shows as local-only in the UI).
2. **Push and open PRs.** Nothing is on a remote. Decide: one PR for `main`, or per-branch.
3. **Web `SchedulePanel`** still lists the heavy/AI passes (`apps/web/app/scans/[id]/SchedulePanel.tsx`
   lines ~27–30). The fast-lane trim only covered `RunPanel`/presets. Decide whether a
   schedule should be fast-lane-only too (it is a standing run request, so it answers the same
   gates — see CLAUDE.md "Scheduling").

### 3b. Phase 3 — the heavy runner's intelligence (BUILT on `feat/agent-phase3`)

**Status: all four slices built, merged on branch `feat/agent-phase3`, every gate
green (pytest 1801 / ruff / mypy / web build / `make test-cli`, single head `0037`).**
Each slice is its own commit and keeps the layering + precision discipline. The
new code lives in `services/api/app/agent/` (all four modules are in
`PURE_MODULES` — DB-free).

- **Slice 1 — whitebox source** (`app/agent/source.py`). Bounded index of the
  project mounted read-only (`run --local --source DIR` → `-v DIR:/src:ro`): text
  extensions only, skip list + a `.gitignore` subset, per-file/total caps, never
  follows symlinks. `annotate_findings` attaches `evidence['source']` file:line
  citations (not a fingerprint key, so identity is unchanged); snippets redacted
  at the boundary. Runner emits `whitebox_source` / `whitebox_skipped`.
- **Slice 2 — sandboxed tools** (`app/agent/sandbox.py`). Curated allowlist
  (nuclei/ffuf/sqlmap) → fixed image + fixed arg shape + pure parser; the agent
  names only a tool + target, never an image/flag/shell. Hardened containers,
  byte-capped output, graded conservatively (sqlmap-confirm = verified, else
  heuristic). Emits only keys with remediation entries; the ingest widens its
  accepted-key set with `SANDBOX_CHECK_KEYS`. **Off unless `AGENT_SANDBOX_ENABLED`
  and `docker` present** — see the caveat below.
- **Slice 3 — bounded agent loop** (`app/agent/loop.py`) + a new off-by-default
  `agent` run flag (RunOptions / RunRequest / `lib/api.ts` / CLI `RunFlags` /
  contract snapshot). Deterministic action queue (nuclei/ffuf sweeps, sqlmap on
  injection leads) with three hard caps (steps, tool calls, wall-clock) and a
  reflector; the planner only *reprioritises* and any AI failure leaves the order
  unchanged. Findings flow back through the journal, so grading stays the
  engine's. The runner runs it when `opts.agent` and reports the producing tools
  it could not run in `gaps.not_run`.
- **Slice 4 — episodic memory** (`app/agent/memory.py` pure; `app/models/agent_memory.py`
  + migration `0037`; `app/scans/agent_memory.py` persistence; ingest
  `GET /runner/runs/{id}/memory`). Offline token-hash embedding + cosine recall
  (no pgvector — see note). Written at `runner_complete` after fingerprints are
  stamped, recalled by the runner at agent start; the loop bumps the priority of
  tools a prior run found productive on the same target. Recall steers, never
  gates.

**The one real caveat — sandbox execution inside the runner.** The agent loop
runs *inside* the one-shot runner container, and the sandbox's default path
shells out to `docker run`, which needs a Docker endpoint. Mounting the Docker
socket into the runner is exactly the thing the safety posture forbids, so the
sandbox is **disabled by default**: with no `AGENT_SANDBOX_ENABLED` + docker, the
loop is a clean no-op (`agent_idle`), and slices 1/3/4 still work (source
annotation, memory, the loop's bookkeeping). To actually run sandboxed tools an
operator must deliberately provide a Docker endpoint to the runner (DinD or a
sibling-container broker); that wiring is the remaining production piece and was
left out on purpose rather than mounting the socket. `app/agent/sandbox.py` takes
an injected process runner precisely so a safer broker can replace the default.

**pgvector was deferred** (slice 4). The plan named it; the recall it describes
is fingerprint-keyed, and an in-process cosine over a bounded candidate set is
enough at one tenant's heavy-run volume, so memory ships without changing the
`postgres:16-alpine` image or adding the `pgvector` dependency. Swapping to
`pgvector/pgvector:pg16` + a `vector` column is a clean future optimisation.

### 3b (original plan, for reference) — the heavy runner's intelligence
Approved plan, `.claude/plans/giggly-squishing-wall.md` (outside the repo; summarised here):

- **Whitebox source analysis** (`app/agent/source.py`). The CLI mounts the project read-only
  into the runner. Index the repo (language-aware, size-capped, honours `.gitignore`); give
  relevant source to the AI to (a) confirm a finding against the code, (b) explain it with
  file:line, (c) steer which checks/params to probe. Source snippets are **evidence, never
  instructions** (reuse the prompt-injection guard in `ai_runtime/plan_agent.py`) and are
  redacted before upload. Needs a way for the runner to mount a directory (a `--source DIR`
  CLI flag → `-v DIR:/src:ro`) — currently the runner has **no** mounts.
- **Sandboxed tools.** Generalise `services/kali` into a per-tool Docker sandbox the runner
  drives (nuclei, sqlmap, nmap, ffuf…) on a **curated image allowlist** — the agent picks
  from the list, never an arbitrary image, never the Docker socket. Reuse the existing
  graceful-degrade + wall-clock-budget pattern (`app/engine/adjuncts.py`).
- **Bounded agent loop** (`app/agent/loop.py`, DeepSeek via the existing planner seam):
  plan → run engine checks → run a sandboxed tool → read source → reflect. Hard caps on steps,
  tool calls and wall-clock; a reflector ends a stalled loop. **Findings it produces still
  flow through the engine's grading**, so an unconfirmed lead stays `heuristic`.
- **Episodic memory** (`app/agent/memory.py`, pgvector — Postgres already runs): "what worked
  on this target/endpoint", keyed by fingerprint, recalled on the next heavy run. No Neo4j.
  Note the runner has no DB by design; memory must go through the ingest API, not a DB.

Open design questions Phase 3 must answer before coding (use the `architect` agent — it touches
the safety gates and the scan lifecycle):
- The v1 runner **refuses** `zap kali confirm plan adjudicate security_review genai_payloads
  adaptive resource_refine` at claim (`_LOCAL_REFUSED` in `app/api/routes/runner.py`) because
  they need server services or a DB session. Phase 3 decides which run locally (sandboxed
  tools replace ZAP/Kali/confirm?) and which move to server-side post-upload processing
  (adjudication after upload, before triage — keeps "a person outranks the model").
- Where whitebox source goes: it never leaves the machine unredacted; what is uploaded is
  findings + file:line citations, not source.
- How agent-proposed checks are bounded (budget, `mutate` opt-in still required, no new
  destructive verbs).

### 3c. Known gaps in what shipped
- Local runs upload **no request trace and no manifest** (`probe.mutations`, methodology),
  so the trace tab is empty and evidence `trace` links are absent. The bundle has no field
  for it; adding it needs size caps (a run's archive is bounded to ~1 MB for a reason) and
  server-side redaction of the trace.
- Runner image is **1.4 GB** (it is the API image). A slim `runner` stage in
  `services/api/Dockerfile` would help CI and cold starts.
- The runner reports `gaps` only as `budget_exhausted`; `not_run` is always `[]` locally.
- `run --local` needs `LOCAL_RUNNER_ENABLED=true` on the server (default **off**; the claim
  404s) and `make runner-image` on the client machine.
- `--api-key` auth was unit-tested but the live e2e ran with server auth **off**. Re-check
  with `API_KEYS` set: login prompt, 401 hint, key-from-env, and that the *runner* container
  never receives the key.
- No VPS/production setup exists (see the earlier analysis): no prod compose, no TLS proxy,
  CORS hardcoded to `http://localhost:3000` in `app/main.py`, no backups, no
  `.env.example` entries for `API_KEYS`/`TARGET_ALLOW_PRIVATE`/`VAULT_KEY`. Dev mode
  everywhere (`next dev`, `uvicorn --reload`, bind mounts). The user's box is 4 vCPU / 8 GB.
  If doing this: production compose override, same-origin proxy (Caddy) injecting
  `X-API-Key`, worker `-c 2`, drop the `target` service, healthchecks/limits, nightly
  `pg_dump`, keep `BIND_HOST=127.0.0.1`.
- Kali passes still run sequentially (~8 min per scan on the sample target, ~98% of a Kali
  run's wall-clock). Ideas: parallelise ffuf/katana/nuclei, restrict nuclei to
  `api,exposure,misconfig,cve` tags, make nikto opt-in. Superseded if Phase 3 replaces the
  Kali sidecar with per-tool sandboxes.

---

## 4. Safety invariants — do not regress (all enforced by tests; CLAUDE.md is authoritative)

- The **authorization gate**: `POST …/run`, schedules and `…/local-runs` all answer
  `_require_run_authorization`. The CLI answers it **before sending any request** and
  refuses a non-interactive run without `--authorized`. Never add a path that skips it.
- **Request budget** (500) and rate are **issued by the server**; the runner can't raise
  them; an upload over budget is refused.
- **`mutate` opt-in** gates every state-changing probe. No destructive attack verbs.
- **`target_guard`** always blocks cloud metadata incl. IPv6-embedded IPv4. The runner uses
  `allow_private=True` (internal hosts are the point) but never relaxes the metadata rule.
- **Secrets**: credential secrets reach the runner container on **stdin only** — never argv,
  env, or the server. The container holds the **per-run token, never the API key**; the token
  is stored hashed, scoped to one run, and dies on complete/fail/cancel/reap. No secret may
  appear in anything the CLI prints. Config and report files are `0600`.
- **Redaction** happens in the runner (it holds the secrets), then again pattern-only on the
  server. **Fingerprints and remediation are the server's** (`append_finding`), so identity
  does not depend on the runner's version. Changing what goes into a fingerprint is a
  compatibility change.
- Layering: `app.engine.execution` and `app.runner.main` are in `PURE_MODULES`
  (`tests/test_layering.py`) and must import with SQLAlchemy blocked. Anything Phase 3 adds to
  the runner path must keep that true.
- Precision gates stay green: `test_precision.py`, `test_detection_matrix.py`,
  `test_char_fingerprint.py`.
- **A tool/stage that did not run must never read as clean** (`check_skipped`,
  `check_failed`, `<tool>_skipped`, `gaps.not_run`, `gaps.failed_checks`). Any new local pass must report what it could not do.

---

## 5. How to run and verify everything

```bash
# Backend (the api container has Postgres; the DB-required form is the real gate)
docker compose up -d postgres redis api
docker compose exec -T api env TEST_REQUIRE_DB=1 pytest -q -p no:warnings
docker compose exec -T api ruff check .  &&  docker compose exec -T api mypy app
docker compose exec -T api alembic heads          # expect a single head: 0036

# Web
cd apps/web && npx tsc --noEmit && npm run lint
docker compose exec -T api python -m scripts.export_openapi /app/openapi.json \
  && cp services/api/openapi.json apps/web/contracts/openapi.json && (cd apps/web && npm run test:contracts)

# CLI (Go runs in a container; nothing to install)
make test-cli          # gofmt + vet + race tests
make cli               # cli/bin/aidetector for this machine
make cli-contract      # after ANY API contract change; then commit cli/testdata/openapi.json
make runner-image      # aidetector-runner:latest, for `run --local`
```

End-to-end local run (what was verified):
```bash
LOCAL_RUNNER_ENABLED=true docker compose up -d postgres redis api worker target
export AIDETECTOR_SERVER=http://127.0.0.1:8000 \
       AIDETECTOR_SECRET_USER=alice-token AIDETECTOR_SECRET_ADMIN=admin-token
curl -s localhost:9000/openapi.json > /tmp/spec.json
ID=$(cli/bin/aidetector scan create --target http://target:9000 --spec /tmp/spec.json)
echo alice-token | cli/bin/aidetector cred add $ID --name alice --role user  --auth-type header --header-name Authorization --secret-stdin
echo admin-token | cli/bin/aidetector cred add $ID --name admin --role admin --auth-type header --header-name Authorization --secret-stdin
cli/bin/aidetector run $ID --authorized --local --docker-network aidetector_default \
    --runner-server http://api:8000 --fail-on high --verified-only      # exit 1, 6 verified highs
```
The seed identities (`alice-token`, `admin-token`) are the repo's own test values for the
intentionally vulnerable `services/target`. Never point a scan at anything you do not own.

---

## 6. Gotchas that cost time

- **Do not override `HOME` when running the CLI with Docker features** — Docker Desktop's
  context lives under `~/.docker`; a fake `HOME` makes `docker` report "cannot connect to
  /var/run/docker.sock". Use `AIDETECTOR_SERVER` / `AIDETECTOR_API_KEY` env vars instead.
- **Changing the API contract fails `tests/test_cli_contract_snapshot.py` on purpose.** Run
  `make cli-contract` then `make test-cli` and commit the snapshot. Adding a run flag means:
  a `RunOptions` field, a checkbox in `RunPanel`, an entry in `RunFlags`
  (`cli/internal/commands/run.go`), and a refresh of the snapshot.
- `apps/web/contracts/` and `services/api/openapi.json` are **gitignored** generated files;
  `cli/testdata/openapi.json` is the one that is committed.
- The compose `api` service runs with `--reload` and bind-mounts source; the **worker does
  not reload** — `docker compose restart worker` after backend changes you want it to see.
  The `aidetector-api` image baked by compose is stale for `docker run`; use
  `make runner-image` for the runner.
- The local `services/api/.venv` is **broken** (points at a missing interpreter). Run tests,
  ruff and mypy through the `api` container.
- Tests that inject fake checks patch `ALL_CHECKS` on **`app.engine.execution`** (where the
  loop reads it), not on `runner`.
- Without Postgres, DB tests **skip silently**; always run with `TEST_REQUIRE_DB=1`.
- `master` is stale (see §2). Branch from and merge to `main`.
- Commit attribution: end commit messages with the `Co-Authored-By:` line the session's
  system reminder specifies (the model name changed during this work).

---

## 7. Suggested order for the next session

1. `cred add --shape-only` (small; closes the one secret leak) — or push/PR first if the user
   wants review before more work.
2. Re-verify local runs with server `API_KEYS` set (auth-on e2e).
3. Phase 3 design pass with the `architect` agent, decide the refused-passes question and
   the whitebox mount, **then** build in slices (source index → sandbox allowlist → agent loop
   → memory), each merged and verified on its own.
4. Production/VPS setup as a separate track if the user is deploying.
