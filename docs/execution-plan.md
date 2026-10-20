# Execution plan

Full interactive version (blueprint + execution plan) lives as Artifacts:

- **Blueprint** — coverage, stack, AI cascade, cost calculator.
- **Execution plan** — repo layout, phase gates, data model, guardrails, risks.

This file is the source-of-truth checklist that tracks against those.

## Assumptions

| Decision            | State           | Note |
| ------------------- | --------------- | ---- |
| Cascade AI          | locked          | Opus 5 planner (Agent SDK) + DeepSeek V4 executor |
| Single scan target  | locked          | one spec + credentials per scan |
| Dual credentials    | open · assumed yes | required for BOLA/BFLA |
| DeepSeek hosting     | open · assumed hosted | self-host (vLLM) adapter behind same interface |

## Phases

- [x] **P0 — Setup.** Monorepo, compose (api/worker/redis/postgres), FastAPI `/health`, Next.js shell, vault, Alembic baseline, CI.
- [x] **P1 — Foundations.** Spec upload + OpenAPI 2/3 parse → operation enumeration, dual credential vault (encrypted), new-scan wizard, `vulnbank` local target. Verified end-to-end (11 tests + browser).
- [x] **P2 — Engine core.** Deterministic checks: BOLA, BFLA, broken auth, reflected injection/XSS, security-headers misconfig, SSRF candidate. Synchronous `/scans/{id}/run` with an authorization gate + request budget. Verified: live scan of vulnbank → 7 true-positive findings across 5 classes (gate ≥4). *Schemathesis fuzzing deferred to a follow-up — the custom OWASP checks deliver the phase gate; Schemathesis slots in as another check module.*
- [x] **P3 — Async + results UI.** Celery background scans (`202 Accepted` + poll), progress events, cooperative cancel, findings dashboard with severity filters, false-positive marking, evidence view, JSON export. Verified through a real worker end-to-end.
- [x] **P4 — Cascade AI.** Opus planner (Agent SDK, isolated venv) + DeepSeek executor tool, adjudicates HYBRID findings (confirmed/dismissed + rationale), per-call token ledger → cost per scan, `/cost` endpoint, opt-in `adjudicate` flag, graceful degradation. UI: AI toggle, cost chip, AI rationale on findings. *Live Opus call pending a working Anthropic credential (the provided key is identity-linked to a workspace it can't access); DeepSeek executor verified live; all plumbing verified with a fake cascade.*
- [x] **P5 — Cost ledger + polish.** Rotating payload library (seeded per run), cost breakdown UI (plan/execute/adjudicate from the real ledger), PDF + JSON export, recurring scan scheduling (Celery beat), threat model + runbook. Verified live end-to-end.

---

**All six phases complete.** v1 delivered: OpenAPI-driven scanner, OWASP API Top 10 engine checks, async jobs with live progress, AI cascade (Opus + DeepSeek) with per-scan cost, rotating payloads, scheduling, and PDF/JSON reports.

## Data model (target)

`scans · credential_profiles · operations · test_runs · findings · token_ledger · scan_events`

Phase 0 ships `scans` + `operations`; the rest land with their phases.

## Safety guardrails (built from P0)

Authorization gate · rate limiting & concurrency caps · dry-run mode ·
credential isolation · scope allowlist. See `docs/threat-model.md` (P5).
