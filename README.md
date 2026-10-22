# runpentests

An OpenAPI-driven API security scanner. Upload a Swagger/OpenAPI spec — or a HAR capture or Postman collection, which
are converted to one — plus credentials, run active security tests across the OWASP API Top 10
(BOLA/BFLA, broken auth, reflected injection, SSRF, excessive data exposure, misconfiguration), and get
a per-scan cost. The `/coverage` page in the UI lists every check, the literal
signal it uses, and what is **not** covered.

Free workspaces execute scans locally with the CLI and review their results in
the web. Starting scans from the web or enabling automatic server schedules
requires Premium. This is enforced by the API at every scan level, independently
of whether premium detection passes are selected.

Every finding carries its evidence tier (`heuristic` or `verified`) and the
change to make. The tier lets the exports, the report and a CI gate tell a lead
from a proof — SARIF grades only verified evidence as an `error`, and the
findings list has a *verified only* filter. The remediation is shaped by the
finding's own evidence ("Authorize the *object* … in the handler for
`GET /accounts/7`") and travels into the HTML report, the PDF and SARIF's rule
help, where a code-scanning UI renders it under the alert. Detection runs in tiers of increasing confidence: **reflection leads**
(reflected injection plus signature/error probes for XPath, LDAP, NoSQL, SSI and
JSON), **out-of-band confirmations** (an opt-in interactsh/OAST callback proves
blind SSRF, RFI, RCE, ESI and partial XXE), and **verified** transport checks
(a TLS/certificate audit built on stdlib `ssl` + `cryptography`). Optional
adjuncts layer on top: a per-run **OWASP ZAP** pass, and **Kali tools** —
sqlmap confirmation of SQLi leads, testssl.sh deep TLS audit, and a Kali
sidecar (built from the official Kali Docker image) running nuclei templates
plus ffuf endpoint discovery. Reflection and OOB probes reach GET query
parameters and JSON request-body fields.

AI is a two-model cascade: **Claude Opus 5** plans and adjudicates (via the
Agent SDK), **DeepSeek V4** executes the high-volume work as a delegated tool.

> Status: **v1 complete (Phases 0–5).** Upload a spec, attach dual credentials,
> and run active OWASP API Top 10 checks (BOLA, BFLA, broken auth, reflected
> injection with rotating payloads, signature/error probes for XPath/LDAP/
> NoSQL/SSI/JSON, SSRF, misconfig, and a TLS/certificate audit) as a background
> job with live progress — plus opt-in out-of-band confirmation of blind classes
> and an opt-in OWASP ZAP pass. Optionally have the **Opus + DeepSeek cascade**
> adjudicate the judgment-heavy findings, with a per-scan token/cost ledger.
> Triage once — verdicts are remembered against a finding's identity and
> re-applied on the next run — see what changed since the previous run, schedule
> recurring scans, and export JSON or PDF. A local vulnerable
> target (`services/target`, port 9000) ships for testing.
> See the [project roadmap — A–I](docs/roadmap-phase.md), including
> [Premium adaptive validation testing](docs/roadmap/premium-adaptive-testing-roadmap.md),
> [docs/execution-plan.md](docs/execution-plan.md),
> [docs/threat-model.md](docs/threat-model.md),
> [docs/runbook.md](docs/runbook.md),
> [scanner-hardening-roadmap.md](docs/roadmap/scanner-hardening-roadmap.md),
> [next-phase-roadmap.md](docs/roadmap/next-phase-roadmap.md),
> [tooling-expansion-roadmap.md](docs/roadmap/tooling-expansion-roadmap.md),
> [services/api/ai_runtime/README.md](services/api/ai_runtime/README.md), and
> [docs/ui-ux-review-2026-10-20.md](docs/ui-ux-review-2026-10-20.md), and the
> [production UX improvements and next priorities](docs/ui-ux-production-review-2026-10-22.md).

## Stack

| Layer            | Choice                                    |
| ---------------- | ----------------------------------------- |
| Frontend         | Next.js (light + dark) — `apps/web`       |
| API / engine     | FastAPI + Celery — `services/api`         |
| Queue / cache    | Redis                                     |
| Database         | Postgres                                  |
| AI planner       | Claude Agent SDK · `claude-opus-5`        |
| AI executor      | DeepSeek V4 (OpenAI-compatible)           |

## Quick start (Docker)

```bash
make env         # creates .env with a generated VAULT_KEY (api and worker share it)
make up          # builds, starts the stack, and applies all migrations
```

Host ports bind to `127.0.0.1`; set `BIND_HOST` in `.env` to expose them. The
intentionally vulnerable demo target stays on loopback either way.

`make up` waits for Postgres and runs `alembic upgrade head` for you; run
`make help` for the full target list (`make down`, `make fresh`, `make test`, …).
Prefer raw compose? `docker compose up --build` then
`docker compose exec api alembic upgrade head`.

- Web UI: http://localhost:3000
- API docs: http://localhost:8000/docs
- Health: http://localhost:8000/health

### Optional adjunct scanners (off by default)

All opt-in, and all degrade gracefully when unconfigured:

```bash
make up-oob      # + self-hosted interactsh (OAST) for out-of-band confirmation
make up-zap      # + OWASP ZAP daemon (per-run `zap` toggle in the UI)
make up-kali     # + Kali service: nuclei templates + ffuf discovery (per-run `kali` toggle)
make up-all      # everything
```

Set `OAST_SERVER` / `ZAP_BASE_URL` / `KALI_BASE_URL` in `.env` to activate
them — see `.env.example` and [docs/runbook.md](docs/runbook.md). ZAP and the
Kali service run **outside** the engine's request budget; the OOB check needs a
real callback domain. Two more tools run *inside* the worker once baked in at
build time (`WITH_KALI_TOOLS=1 make up` — compose passes the flag through) and
configured (`SQLMAP_BIN` / `TESTSSL_BIN`): sqlmap re-tests engine-flagged SQLi
leads with boolean/error/UNION/stacked/time techniques, and testssl.sh deepens
the TLS audit on HTTPS targets.

## Local dev (API only, no Docker)

```bash
cd services/api
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt -r requirements-dev.txt
# needs a local Postgres + Redis, or point DATABASE_URL/REDIS_URL elsewhere
alembic upgrade head
uvicorn app.main:app --reload
pytest -q
```

## Repo layout

```
apps/web/          Next.js UI (light + dark)
services/api/      FastAPI + Celery — scanner core
  app/core/        config, db, vault (Fernet)
  app/models/      SQLAlchemy tables
  app/engine/      deterministic checks (phase 2)
  app/ai/          Opus planner + DeepSeek executor (phase 4)
  migrations/      Alembic
infra/             deployment (compose lives at repo root)
docs/              execution plan, threat model, runbook, hardening roadmap
```

## Phase 0 acceptance gate

- `docker compose up` serves the UI shell and a green `/health`.
- `alembic upgrade head` applies the initial `scans` + `operations` schema.
- `pytest -q` passes.
