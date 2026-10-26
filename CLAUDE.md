# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this is

An OpenAPI-driven API security scanner. You upload a Swagger/OpenAPI spec plus
two sets of credentials, the engine runs active OWASP API Top 10 checks against
the target, and an optional AI cascade adjudicates the judgment-heavy findings
with a per-scan token/cost ledger.

Three deployables: a Next.js UI (`apps/web`), a FastAPI + Celery service
(`services/api`), and an intentionally vulnerable local target
(`services/target`, port 9000) that exists so scans have real findings to catch.

## Commands

Everything below runs from the repo root unless noted.

```bash
make start                             # everything: make up-all + a ready banner; make stop tears it all down
make up                                # full stack (build) + wait for DB + migrate; web :3000, api :8000, target :9000
make up-all                            # ...plus the interactsh (OAST), ZAP, and Kali adjuncts
make down                              # stop the stack (keep the DB volume); make fresh wipes + re-migrates
make admin email=you@example.com       # create the workspace admin (password prompted) or reset theirs
make help                              # every target
```

`make up` runs the migrations for you (it waits for Postgres, then
`alembic upgrade head`). Prefer raw compose? `docker compose up --build` then
`docker compose exec api alembic upgrade head`.

API service (`cd services/api`, venv at `.venv`). From the repo root,
`make test` (pytest) and `make lint` (ruff + mypy) run these inside the api
container:

```bash
pytest -n auto -q                      # full suite, parallel (~30s; serial ~2min)
pytest tests/test_engine.py -q         # one file
pytest tests/test_engine.py::test_bola_is_flagged_on_shared_object -q   # one test
ruff check .                           # lint (CI gate)
mypy app                               # type-check (CI gate)
alembic upgrade head                   # migrations
alembic revision --autogenerate -m "..."
uvicorn app.main:app --reload          # needs local Postgres + Redis
celery -A app.workers.celery_app.celery worker --loglevel=info
```

Web app (`cd apps/web`):

```bash
npm run dev                            # :3000, talks to NEXT_PUBLIC_API_URL
npm run lint && npm run build          # both are CI gates
npx tsc --noEmit                       # type-check alone
```

CLI (`cli/`, Go; **Go is not needed on the host** — every target runs in `golang:1.23`):

```bash
make cli                               # build cli/bin/aidetector for this machine
make test-cli                          # gofmt + vet + race tests (also a CI job)
make cli-contract                      # refresh cli/testdata/openapi.json after an API contract change
```

DB-backed tests **skip locally** when Postgres is unreachable; **CI and
`TEST_REQUIRE_DB=1` fail** instead. Invalid database configuration and programming
errors always fail. Check the skip count. Tests run against a **dedicated
`<db>_test` database** (auto-created; override with `TEST_DATABASE_URL`). The
override must name a distinct disposable PostgreSQL database ending in `_test`;
the harness rejects the application's database name even through another host
alias and rejects routing query overrides before connecting. `conftest.py`
rebinds `app.core.db.SessionLocal` to it (under pytest-xdist each worker gets its own
`<db>_gwN_test`, derived before the same validation), so a run's schema reset and Alembic migrations
never touches the app/dev database — including the eager Celery worker's own
sessions. Celery runs eagerly in tests (`task_always_eager`), so an enqueued
scan executes inline within the request.

An autouse fixture resets application settings to declared defaults, preserving
only database routing. Configure services with `monkeypatch` inside the test;
ambient `.env`/environment settings must not activate AI, OAST or sidecars.
Real target sockets and tool subprocesses are blocked. Use ASGI/MockTransport
and injected tool doubles; only layering probes use `allow_subprocess`.
Database access through libpq remains available. Eager worker tests bind the
real async bridge to the in-process target rather than an assumed closed port.

The ordinary DB fixture builds through Alembic; `test_migrations.py` compares
head with ORM metadata and upgrades seeded old rows. `integration_tests/` is a
separate fixture tree with a real Redis broker and worker process. Run it with
explicit `TEST_DATABASE_URL` and `TEST_REDIS_URL` using `make test-integration`;
see `services/api/integration_tests/README.md`. It never flushes Redis or sends
scanner traffic to a live target. Browser workflows run with `make test-web`,
which fetches Playwright's pinned Chromium on first use; see `apps/web/e2e/README.md`.

Every test starts from an empty database *and* a freshly seeded target — two
autouse fixtures truncate all tables and call `vulnapp.reset_state()` before
each test, so a test is isolated from its predecessors however they exited.
`tests/vulnapp.py` keeps accounts, widgets and signups in module-level dicts and
the mutating checks change them, so without that reset a result would depend on
which tests ran first. Don't reintroduce tests that depend on rows another test left
behind; `pytest tests/test_x.py` alone must pass, and so must a reversed run.

Four support modules carry the shared setup, and **a test module must never
import another test module**:

| module | holds |
| --- | --- |
| `tests/conftest.py` | fixtures — `db_session`, `client`, `engine_client`, `make_scan`/`seeded_scan`, `new_scan`/`scan_with_spec`, `MINIMAL_SPEC` |
| `tests/harness.py` | database destination validation, required-DB behavior and deterministic settings defaults |
| `tests/factories.py` | builders — `operation`, `credential`, `scan_context`, `scan_row`, and the `run_one`/`run_registry` check runners |
| `tests/fakes.py` | doubles — `FakeCascade`, `FakePlanner`, their broken variants, `CollectorOob`, `adjunct_harness` |

`tests/vulnapp.py` is the in-process vulnerable app every engine test probes
through a Starlette `TestClient`, so the engine tier runs with no network. The
engine tests are split by concern (`test_engine_authz`, `_injection`, `_probe`,
`_headers`, `_oob`, `_smoke`) rather than living in one file.

**The detector harness is a pair, and both halves are gates.** Recall alone is
not enough: a report where most findings are noise gets ignored, and the real
finding goes with it.

| gate | asks | fails when |
| --- | --- | --- |
| `tests/test_detection_matrix.py` | does every registered check detect *anything*? | a check has no declared proof, or one claiming the shared run has gone quiet |
| `tests/test_precision.py` | does the registry stay quiet against a target that is *fine*? | any finding outside a scoped, justified `Waiver` |
| `tests/test_char_fingerprint.py` | does identity hold still? | a golden moves, or an `IDENTITY_KEYS` entry has no golden |

`tests/safeapp.py` is the precision half's target: the hardened twin of
`vulnapp`, same routes and shapes, everything done right. Two rules keep it
honest — a route here must exist in `vulnapp` with the same method and path
shape, and it must return a real populated response (404-everywhere would pass
trivially). When the precision gate fails, the question is which happened: a
check gained a signal that misfires on correct behaviour (fix the check — that
is the bug the gate exists to catch), or `safeapp` really is weak that way (fix
`safeapp`). Adding a `Waiver` is the third option and rarely the right one; each
one states why a *correct* API produces that finding and is scoped by check and
route so it cannot blind the gate elsewhere.

## Architecture

### Scan lifecycle

The whole system is one pipeline; understanding this order explains most of the
code:

1. `POST /scans` → `app/scans/service.py:create_scan`
2. `POST /scans/{id}/spec` → `app/specs/importers.py:load_source` sniffs the
   upload: an OpenAPI/Swagger doc passes straight through, while a **HAR capture
   or Postman collection** is converted to a synthesised OpenAPI dict (paths
   templated — id-looking segments become `{id}`; request/query kept as shape;
   HAR response bodies become response schemas, so `data_exposure` drift works;
   values always dropped) and *that* JSON is stored as `spec_text`. Then
   `app/specs/parser.py` flattens it into `Operation` rows (method, path,
   params, auth_scope). Replaces any prior ops. This is how the engine scans an
   API that never had a spec. A path is composed from the target too (a spec
   server prefix the target's path already ends with is not repeated), so
   `PATCH /scans/{id}` re-derives every route in place from `spec_text`
   (`operations.retarget_operations`, ids and opt-outs kept) — re-saving an
   unchanged target repairs routes a past change left stale. Internal `$ref`s are inlined with prance
   (`RESOLVE_INTERNAL` — never fetches). **Remote** `$ref`s are off by default
   (fetching one is spec-driven SSRF) and inlined only when `spec_ref_allowlist`
   lists their host: `app/specs/remote_refs.py` fetches each through the same
   `core/target_guard` the run endpoint uses (allowlist authoritative, metadata
   always blocked, redirects disabled), bounded by a fetch count, byte and depth
   cap, and degrades every failure to leaving the ref untouched.
3. `POST /scans/{id}/credentials` → secret encrypted via `app/core/vault.py`
   (Fernet) and stored as `secret_ref`; plaintext never persists. A credential
   is `static` by default (the secret *is* the token), or carries a token-minting
   `grant` (`client_credentials` / `password` / `cookie`, migration `0014`):
   `ResolvedCredential.mint` calls the target's own auth endpoint once at scan
   start so the scan never carries an expired token — the operational point of a
   scheduled scan. A grant that fails to mint leaves that identity
   unauthenticated (an `auth_grant_failed` event) rather than failing the scan.
   For a non-static grant the encrypted secret holds the grant's sensitive half
   (client_secret / password); the non-secret parameters live in `grant_params`.
   The web form and `aidetector.yml` (`grant:`) both expose it.
   A key can also ride in the query string or a cookie (`auth_type` `query` /
   `cookie`, `header_name` naming the parameter or cookie; migration `0057`).
   A query key travels inside the engine as a pseudo-header
   (`credentials.QUERY_KEY_HEADER_PREFIX`) so every check, identity matching and
   trace redaction treat it like any header; `credentials.wire_kwargs` moves it
   into the query string only at the transport call (probe send/burst, reauth).
   The redactor also masks a secret's percent-encoded spellings, because a query
   key comes back encoded in echoed URLs. The one request built outside the
   probe — sqlmap's raw request file — calls `wire_kwargs` itself.
   An identity's `privilege` is an explicit rank on the role-name scale (0 guest
   … 3 admin, `MAX_PRIVILEGE`) so explicit and inferred ranks compare; NULL
   infers it from the role name (`domain/privilege.py:ROLE_RANKS`). An identity's
   optional `tenant` (migration `0058`) names its workspace: once any identity sets one,
   `ScanContext.identity_pair` (BOLA, seeded BOLA, the write oracle) pairs identities of
   *different* tenants and `privilege_pair`/`lower_privileged` (BFLA) pair within one, so
   two keys of one workspace reading their own object is never BOLA. The write oracle runs
   both pairs (`write_oracle._writer_pairs`): across tenants it reports BOLA (write), and
   a lower role's write persisting inside one tenant is BFLA (write), API5. `GET /scans/{id}/auth-hints` and
   `POST /specs/auth-hints` read `securitySchemes` (`specs/auth_hints.py`, pure)
   to suggest public / one key / roles — advisory only, never fed to the engine;
   the web credentials panel and `aidetector init` lead with that choice.
4. `POST /scans/{id}/run` → requires `authorized: true` in the body (403
   otherwise — active scanning fires real payloads at a live host). Sets status
   `queued` and hands off to `run_scan_task.delay(...)`; returns 202.
5. Celery worker atomically claims a queued scan before target traffic; duplicate
   deliveries for running/finished scans are ignored. Then → `app/engine/runner.py:run_scan` does the real work.
   While it runs, a heartbeat thread stamps `Scan.heartbeat_at` (also stamped at
   queue time). The beat task `reap_stale_scans` (`app/scans/reaper.py`) fails a
   `running` scan silent past `scan_stale_seconds` and a `queued` one unclaimed
   past `scan_queued_stale_seconds`, so a dead worker or a lost queue message
   cannot lock a scan against every active-scan guard. The task carries a hard
   Celery time limit (`scan_time_limit_seconds`) and deliberately no soft one:
   `SoftTimeLimitExceeded` is an `Exception` the runner's check isolation swallows.
6. UI polls `GET /scans/{id}`, `/events`, `/findings`, `/cost` once per second
   while status is `queued` or `running`.

### The shared vocabulary (`app/domain/`)

`Severity`, `Confidence`, `Verdict`, `AuthType`, `GrantType` and the sort ranks
live in `app/domain/enums.py`; `is_privileged` lives in `app/domain/privilege.py`;
`app/domain/sensitive.py` says what a field *name* implies about its value.
That last one is shared for a reason: `engine/exposure_policy` **reports** a
`password_hash` and `core/redact` **hides** it, and when those were two
independent lists a family added to one was silently missed by the other. They
now select categories from one vocabulary — redaction takes them all, reporting
takes `REPORTABLE`, which is why a customer's own first name is masked but never
raised as a finding.
These are product concepts, not column types, and **nothing in `app/domain/` may
import SQLAlchemy, FastAPI, `app.engine` or `app.models`** — the arrow points
into this package and never back out. `app/models/` maps its columns onto these
enums; the engine and the report layer read them directly.

That rule is enforced, not just stated: `tests/test_layering.py` imports each
pure decision module in a subprocess with SQLAlchemy blocked at the import hook.
It exists because the vocabulary used to live inside `app/models/finding.py`, so
every pure policy module (`header_policy`, `exposure_policy`, `fingerprint`,
every check) dragged in the declarative `Base` registry to get the word
"critical" — and nothing failed, because the code worked either way.

### The engine

`app/engine/runner.py:run_scan` is the orchestrator, and *only* the orchestrator.
It resolves the scan into a `ScanContext` (base URL, operations, decrypted
credentials, an `HttpProbe`, and a fresh random `seed`), then walks `ALL_CHECKS`
in order. The work each stage does lives beside it:

| module | owns |
| --- | --- |
| `engine/checks/` | the engine tier, inside the request budget |
| `engine/adjuncts.py` | external tools, inside the wall-clock budget |
| `engine/ai_phases.py` | the two opt-in AI steps |
| `engine/run_record.py` | findings, the run archive, per-endpoint coverage |
| `engine/remediation.py` | per-check catalogue: CWE, summary, fix, references |

Which optional passes a run performs is one value object, `RunOptions`
(`app/scans/run_options.py`), carried end to end: `RunRequest.to_options()` →
the Celery message (as a **named dict**, never positional booleans) →
`run_scan(options=...)`. Every flag defaults to off, and that is a safety
property, not a convenience — `mutate` writes to the target, `zap`/`kali`/
`confirm` fire far more traffic than the budget allows, and `plan`/`adjudicate`
spend tokens. Adding a flag means adding one field there, deciding whether a scan level
(`app/scans/run_levels.py`, mirrored in `apps/web/app/components/scanLevels.ts`) or
an explicit switch turns it on, and one entry in the CLI's `RunFlags`
(`cli/internal/commands/run.go`);
`tests/test_coverage_mirror.py` fails if the web client can't send it and the CLI's
contract test fails if the CLI can't.
**Scan levels** (`app/scans/run_levels.py`) are what both clients lead with:
`RunRequest.level` (`quick` | `standard` | `deep`) and the `ai` switch expand
into the plain flags inside `_require_run_authorization`, *before* any gate
judges them, so the gates, the archive and the diff never see a level. A level
only turns flags on, leaves out what the tenant's plan or the lane (local runs:
`LOCAL_REFUSED`, currently empty) cannot do instead of refusing, and **never implies `mutate` or an
AI pass** — writes and AI are each their own explicit switch. An explicit `true`
still answers its own gate (an explicit `premium: true` on a free plan is 402); an
explicit `false` is not an opt-out, since a level turns that pass on anyway. A
schedule saves the expanded flags, so a tenant that later gains premium re-saves to
get it.
The web mirrors the table in `app/components/scanLevels.ts`, checked by
`tests/test_coverage_mirror.py`.
`RunOptions.checks` scopes the engine tier to a subset of check keys (empty =
all). It only narrows — a selected write check still needs `mutate` — and the
diff counts a check the newer run left out as `not_retested`, not fixed. The
panel's presets live in `app/components/checkScope.ts`, mirrored by the same test.

Key invariants, all deliberate:

- **A check that raises is isolated, and reported as not finished** — one
  broken check never aborts a scan, but it never reads as "completed" either.
  The runner emits `check_failed` (`"<key> did not finish: <ExceptionClass> on
  <METHOD route>"` — class and route template only, never the exception
  message) and records the key in `gaps.failed_checks`, so the diff calls its
  older findings `not_retested`, not resolved. A transport error that ends a
  check leaves a trace row with `error` set to its class (`ReadTimeout`).
  `HttpProbe` retries a timeout/network error once for a safe method outside
  a reserved test case, on its own budget slot; a write is never retried.
- **A check with nothing to work against says so.** A check may declare
  `inapplicable(ctx) -> str | None` (read through `base.inapplicable`, default
  "runs"); the runner skips it and emits a `check_skipped` event naming what is
  missing. This exists because an empty findings list is ambiguous in the worst
  possible way — "we looked and it was clean" and "we never looked" are the same
  output, and only one is good news. `tests/test_detection_matrix.py` fails if a
  check neither runs nor explains itself. Write the reason so the fix is obvious
  ("no url-shaped parameter in the spec"), not so it is merely true.
- **The same "we never looked" trap, per endpoint.** `build_coverage` records,
  beside each operation's request count, its response outcomes (`responses`,
  `ok`) and `exercised` — reached *and* answered ≥1 2xx. An enabled endpoint the
  engine hit but that only ever returned 401/404/422 was probed with the wrong
  auth, path or body, so its "0 findings" is inconclusive, not clean; the report
  and diff say so (`CoverageRow`, surfaced in `RunInsights`). Counted in
  `engine/coverage.py:CoverageRecorder.note_result`, which stays observational.
- **Reachability is checked before the budget is spent.** `_run_engine_checks`
  calls `engine/preflight.py` first: a few safe GETs, and if *nothing* answers
  (origin down/unreachable) it emits `target_unreached` and stops the run before
  it wastes ~750 requests. It aborts only on the unambiguous no-answer case — any
  answer (even errors everywhere) proceeds to the full run and the richer
  post-hoc `engine/target_health` diagnosis. Pure, so both lanes share it.
- **`HttpProbe` enforces a 750-request budget per scan.** Past the cap, `send()`
  returns `None` and checks stop silently. Any new check must handle a `None`
  probe result.
- **Cancellation is cooperative** — `cancel_requested` is re-read from the DB
  between checks, so a cancel only lands at a check boundary.
- **Re-running a scan clears prior findings and events**, it does not append.
  What survives is *identity*: `append_finding` stamps every finding with a
  `fingerprint` (`app/engine/fingerprint.py`) built from evidence keys naming
  what and where — never counts, statuses, harvested ids or rotating payloads.
  That is what carries human triage across runs (`Scan.triage`, re-applied by
  `run_record.apply_triage` *after* AI adjudication so a person outranks the
  model) and what `GET /scans/{id}/diff` (`app/scans/diff.py`) matches on.
  **Changing what goes into a fingerprint is a compatibility change** — every
  stored one is invalidated, triage stops matching and one diff reports the
  affected set as fixed-and-new. Prefer a per-check `IDENTITY_KEYS` override to
  widening `DEFAULT_KEYS`. Checks that probe a rendered URL (injection, authz)
  record `route` beside `path`; `route` supersedes `path` for both identity and
  remediation, because the probed URL carries the payload or a harvested id.
- **Every finding carries remediation.** `append_finding` fills it from the
  per-check catalogue in `app/engine/remediation.py`, shaped by the finding's
  (already redacted) evidence — one place, so no check carries advice around. A
  check may override it by setting `EngineFinding.remediation` when it has
  better text than a generic line (ZAP's per-alert `solution`, a nuclei
  template's own remediation). `scans/sarif.py` reads the same catalogue for CWE
  and rule metadata, so a SARIF rule and the finding it describes can never
  disagree. **Adding a check means adding a catalogue entry** —
  `tests/test_remediation.py` fails in both directions. Remediation interpolates
  target-controlled values, so any renderer that parses markup (the PDF's
  reportlab paragraphs, the HTML report) must escape it.
- Checks take an injectable `HttpClient`, so tests bind a Starlette `TestClient`
  to the in-process vulnerable app (`tests/vulnapp.py`) and exercise the engine
  with no network.

Adding a check: implement the `Check` protocol from `app/engine/base.py` (a
`key` attribute and `run(ctx) -> list[EngineFinding]`) and register it in
`app/engine/checks/__init__.py`. Registry order is run and display order.

### Detection signals are narrower than the check names

This matters when touching the engine or writing user-facing copy. The
authorization checks (`bola`, `bfla`, `broken_auth`), `security_headers`, and
`tls_config` collect evidence that demonstrates the weakness. `tls_config` is the
one check that inspects the transport rather than a response: it opens a direct
TLS socket (outside the `HttpProbe` budget) and analyses the presented
certificate + negotiated cipher/protocol via stdlib `ssl` + `cryptography`, so
its findings are verified. `security_headers`, `info_disclosure` and `data_exposure` share one
**per-endpoint header sweep** (`app/engine/checks/misconfig.py:sweep_headers`):
every safe endpoint (GET/HEAD, capped at `MAX_HEADER_ENDPOINTS`, round-robined
across path families) is probed once with a throwaway `Origin`, memoised on
`ScanContext.header_sweep` under `header_lock` because checks run concurrently.
The scoring rules are pure and unit-tested in `app/engine/header_policy.py`
(presence *and* value quality, plus CORS reflection and `Set-Cookie` flags);
endpoints sharing an issue profile collapse into one finding. Cookie values are
never surfaced — only the cookie name and its missing attributes.

`HeaderSnapshot` also carries a truncated **body sample**, which is what lets
`data_exposure` (API3, `app/engine/checks/data_exposure.py`) run at **zero extra
requests**: it reads the sweep rather than re-probing, and a test pins that.
It reads a **second** free corpus too — the run's request trace, which is every
call any check made. The sweep is structurally narrow (GET/HEAD, capped at
`MAX_HEADER_ENDPOINTS`, one identity, spec operations only), so alone it cannot
see a create that echoes a token back, a 5xx carrying internal state, the second
identity's view, or a shadow path discovery found. Trace rows carry sensitive
field *names* only — recorded during redaction (`Redactor.scan_body`), so
**detection is independent of retention**: a response past the run's body budget
keeps no text and still reports what it exposed. Drift needs the full field list
and stays with the sweep.
Its two signals are graded differently on purpose — sensitive field *names*
(five families in the pure `app/engine/exposure_policy.py`) are **verified**,
because the field is present in the response and no exploitation step is
missing, while fields absent from the declared 2xx schema
(`parser.declared_response_fields`) are **heuristic**, because from outside a
stale spec looks exactly like an over-exposing endpoint. **A `data_exposure`
finding records only field names — never a value** — the same rule as cookie
values, for the same reason: a findings table must not accumulate customer data.
Any future check that reads bodies inherits it. (The run's *request trace* does
keep a bounded, redacted body sample; it is a different store with its own
rules — see "The request trace" below.) The reflection family does
**not**: `app/engine/payloads.py` and `app/engine/signatures.py` send a payload
carrying a unique `aidx<hex>` marker and a finding fires when that marker comes
back **with a payload character the response's own context would have to encode
still intact beside it**. The marker is alphanumeric so it survives transport —
which means it also survives HTML escaping, so the marker alone cannot tell a
verbatim echo from a correctly escaped one, and *reflection of the marker is not
the signal*. `injection_probe.Attempt.reflected` splits the payload at the marker
and finds the decoded sides (`prefix + marker` / `marker + suffix`) that survived;
`Attempt.injected` then requires one of those surviving sides to carry a
character active in the response's context (`response_context`: `< > " '` in
HTML, a structural `" { } [ ]` in JSON — a `text/plain` body has none, so a
reflection there is never a lead). Escaping rewrites exactly those characters, so
a correctly-escaped page drops the signal; a percent-encoded payload must have
*decoded* (`%0d%0a` returned verbatim is proof the target never did). **Which
family a reflection can even be a lead for is an oracle, not a free-for-all**
(`payloads.FAMILY_ORACLE`): `xss`/`sqli` are `reflection` (a surviving
metacharacter is the evidence); `crlf` is `header` (a lead only when the injected
header name comes back in the response *headers* — a verified split, not a body
echo); `ssti` is `evaluate` (confirmed by the arithmetic oracle in
`independent_injection` under `confirm`, never by an echo) and `cmdi`/`traversal`
are `oob` (confirmed by `oob_injection`). So `reflected_injection` sends only the
`reflection` and `header` families and never turns a bare echo of `{{...}}`,
`;echo` or `../` into a finding. `signature_injection` (XPath/LDAP/NoSQL/SSI/JSON)
also matches FuzzDB-style backend error regexes: a match is a stronger lead (the
payload reached the interpreter) but still not exploitation; its reflection-only
tier obeys the same `injected` rule, so its curated payloads each carry a
context-active character to keep a class's *presence* stable across the per-scan
rotation. Both checks **drop a reflection seen only in a 4xx** — a validation
envelope echoing the value it rejected is the framework's error handler, not a
query layer — and **keep a 5xx**: the payload got through and broke something.

Three tiers of confidence now exist, and coverage copy must not blur them.
They are **data, not just prose**: every finding carries a `confidence`
(`Confidence.heuristic` | `Confidence.verified`, `app/domain/enums.py`), set
by the check that produced it on the `EngineFinding`. The dataclass default is
`heuristic` deliberately — a check that forgets to grade a finding understates
its evidence, which is the safe direction. Set `Confidence.verified` only where
the evidence demonstrates the weakness directly. It flows through
`append_finding`, the run snapshot, `FindingOut`, the adjudication payload, both
reports, and `sort_findings` (proof above leads within one severity); SARIF
derives `level` from severity **and** confidence, so only verified evidence can
reach `error` (`app/scans/sarif.py:result_level`). `tests/test_coverage_mirror.py`
fails if `FindingConfidence` in `apps/web/lib/api.ts` drifts from the enum.

- **Reflection leads** (`reflected_injection`, `signature_injection`, and the
  non-OOB part of `ssrf`) — marker reflected / error string matched. Injection is
  **spec-shaped** (`app/engine/spec_values.py`): the parser retains each param's
  schema facts (`type`/`format`/`enum`), payload values keep a valid prefix for
  typed/enum/formatted params, and the operation's other required params are
  filled with spec-valid baselines so the payload reaches the sink. Sinks: **GET
  query + path params** always, and **POST/PUT/PATCH JSON body fields only when
  `mutate: true`** (`ctx.allow_mutation`) — sending a body to a mutating verb
  changes target state, so it shares the write oracle's opt-in. Path/query on
  mutating verbs, headers and cookies are still never fuzzed. Body fields come
  from the parser's `requestBody` expansion, which resolves `$ref` into
  `components/schemas`. (`ssrf` remains query-only, url-named params.)
- **Out-of-band confirmations** (`oob_injection`: blind SSRF, RFI, RCE, ESI,
  partial XXE) — the target actually called back to our OAST server, so these
  are confirmations, not leads. **Opt-in and off by default**: they no-op unless
  `OAST_SERVER` is set and a `NullOobClient` is replaced by a live
  `InteractshClient` (see `app/engine/oob.py`). OOB reaches GET query params
  always and **JSON request-body fields only under `mutate: true`** (body writes
  change state); headers, cookies, path params and non-JSON bodies are still
  never fuzzed.
- **OWASP ZAP** (`app/engine/zap.py`) — an opt-in per-run (`zap: true`) parallel
  scanner. It runs **outside** the engine's 750-request budget and cooperative
  cancellation, so it is a side path in the runner (`_run_zap`), not a `Check` in
  `ALL_CHECKS`. Like the AI cascade and OOB, every failure degrades gracefully
  and never fails a scan.
- **Write oracle / authz-on-write** (`write_authz`,
  `app/engine/checks/write_oracle.py`) — the one check that **mutates** the
  target, so it is opt-in (`mutate: true` → `ctx.allow_mutation`) and no-ops
  otherwise. It pairs a write with a read-back (`app/engine/resource_map.py`),
  sends the write as the low-priv identity with a canary, and confirms via a
  read-back as the high-priv (owner) identity that the write **persisted across
  identities** — a *verified* BOLA-write (API1) or BFLA-write (API5), not a lead.
  Updates attempt restoration in `finally`; creates attempt a DELETE when one
  exists. Cleanup consumes the same request budget. Failed cleanup or lost create
  identifiers emit `cleanup_failed` events, so exhausted budgets or transport
  failures cannot silently imply that target state was restored.
  DELETE is never used as an attack verb. Reaches only string body fields on
  spec-paired create/update resources. Its **create** path seeds nested parents
  via `app/engine/sequence.py` (the write is sent under a seeded parent chain and
  the chain is torn down after); updates stay single-hop.
- **Seeded cross-tenant BOLA** (`seeded_bola`,
  `app/engine/checks/seeded_bola.py`) — the first producer→consumer *stateful
  sequence*, and the mirror of the write oracle: where `write_authz` proves a
  low-priv **write** persists across identities, this proves a cross-identity
  **read**. It creates an object as one identity (tagging a string body field
  with a canary), then reads that exact object back as a **different** identity;
  the canary returning is a *verified* cross-tenant BOLA (API1) — no longer the
  read-only `bola` check's inference from identical bodies. An anonymous read is
  the baseline (a public item read is not flagged). Also **mutates**, so it
  shares the `mutate: true` opt-in, uses **create** pairs only (a create is what
  guarantees the first identity owns the object), and DELETE-cleans what it
  creates. The shared write-building helpers (`mutable_body_field`,
  `created_id`, `build_body`, `path_values`) live in `resource_map.py` so all
  three write-side checks use one copy. It reaches **nested** resources
  (`POST /projects/{id}/items`) through `app/engine/sequence.py`, which seeds the
  parent chain first — a real *create-parent → create-child → read* sequence
  (`seed_ancestors` creates each ancestor collection's `POST` as the caller and
  chains the returned ids into deeper parent paths, `nested_create_pairs` finds
  the deep pairs `build_resource_pairs`'s single-id guard skips, `run_cleanups`
  tears the chain down child-first). A parent with no discoverable producer is
  skipped, and a half-built chain is cleaned up rather than left behind.

`apps/web/lib/coverage.ts` is the user-facing statement of all this, and the
`/coverage` page renders it. **Keep it in sync when engine checks change** — it
is a hand-maintained mirror of the engine, not generated from it. It is no
longer unguarded, though: each entry describing an engine-tier check carries a
`key` matching that check's `Check.key`, and `tests/test_coverage_mirror.py`
fails in both directions — a registered check with no entry, or an entry naming
a check that left the registry — as well as when a `source:` breadcrumb points
at a file that no longer exists. Its
`HEADER_POLICY` export is the tightest of those mirrors: one row per header, so
it tracks `_CORE` / `_HYGIENE` / `_HYGIENE_EXPECTED` in `header_policy.py`
row-for-row. `HEADERS_NOT_SWEPT` records the two headers from the usual
published checklists that are deliberately *not* scored (`Clear-Site-Data`,
`Upgrade-Insecure-Requests`) and why — don't "fix" that by adding them.

### The request trace

`HttpProbe` records one row per outbound call in `probe.mutations`, archived onto
`ScanRun.mutations` by `run_record.finish_run`. It exists because "the write was
rejected" is not an answer and `{"error":"tin required"}` is. Every row carries
the route, the check that was running, **which identity's credentials went out**
(the Authorization header is redacted, so without this an authorization row
cannot be read), the pass (`engine` or `discovery`), elapsed time, header names,
and redacted samples of both bodies.

Four rules keep it from becoming a copy of the target's data, all in
`app/engine/base.py`:

- **Everything is redacted before it is stored.** `Redactor.body`
  (`app/core/redact.py`) masks the scan's own credentials verbatim, then masks
  by *field name* through parsed JSON (`ssn`, `routing_number`, `first_name`, …
  — a name says what a value is far more reliably than its shape does), then by
  PII/secret pattern. `redact` defaults to a pattern-only redactor rather than
  to nothing, so a construction site that forgets one gets less masking, never
  raw data.
- **Only textual bodies are kept** (`_TEXTUAL_BODY`). A PDF or gzip stream
  decodes to mojibake; the row keeps its status and size and drops the text
  (`body_omitted`).
- **Two per-row limits and one per-run budget.** A write or an error gets 4000
  characters, an ordinary 2xx read gets 1000, and once `_BODY_BUDGET` of text is
  retained later rows keep their structure and drop the body. This is what bounds
  one run's archive at roughly a megabyte.
- **The request body is retained where the response is only sampled**, because it
  is data the scanner generated rather than the target's — and it is the half
  that answers "why was this rejected".

Two consequences worth knowing:

- A run's trace is **not** on `ScanRunOut`. `GET /scans/{id}/runs` returns every
  run a scan ever had, so it carries `trace_count` and the rows come a page at a
  time from `GET /scans/{id}/runs/{n}/trace`.
- A secondary pass that builds its own probe must merge back with
  `HttpProbe.absorb` (the discovery probe does) and be handed `ctx.redact`.
  Otherwise its calls leave no trace and go uncounted.

`append_finding` stamps each finding's evidence with `trace`: the sequence
numbers of the rows that produced it. That is computed **after** the fingerprint
and is deliberately not an identity key — sequence numbers move every run.

### Adjunct phase (external tools, outside the request budget)

After the engine tier, the runner runs external adjuncts as a bounded sequence
(`run_scan`): ZAP (`zap: true`), the lead-confirmation tools
sqlmap/dalfox/commix/tplmap (`confirm: true` — **opt-in and off by default**,
because they are slow), testssl (`testssl: true` — on at the Deep level only, so a
fast-lane run never waits minutes on it), then Kali (`kali: true`). The whole phase shares
one wall-clock budget (`settings.adjunct_budget_seconds`, default 600s) and a
cancellation check *between* passes: once the deadline is spent (or a cancel
lands), remaining passes are skipped (`adjuncts_skipped` event). The confirm
tools also honour the same deadline between their per-target runs. This is what
stops a scan hanging for tens of minutes in a slow tool. Each tool is still
additionally env-gated on its `*_BIN` and degrades gracefully. The AI cascade
runs after this phase with its own separate timeout.

**A tool that did not run must never read as a clean result.** The scanners
degrade to `[]` but set `.error`; `adjuncts._reported` turns that into
`AdjunctUnavailable`, so the pass emits `<tool>_skipped` ("did not run — …")
instead of "added 0 findings". `SqlRunJournal.event` records every such tool in
`ScanRun.gaps.not_run`, and a spent request budget in `gaps.budget_exhausted`
(announced once as a `budget_exhausted` event). An engine check that skipped itself
as inapplicable is recorded in `gaps.skipped_checks` (main pass only; the local
runner uploads it and the server keeps registered keys only). The diff reads `gaps` through
`run_options.unperformed`, so those findings land in `not_retested`, not
`resolved`. A failed run stores a redacted `Scan.failure_reason`
(`engine.journal.describe_failure`). `GET /capabilities` is the advisory
pre-run view of the same thing: the run panel switches unavailable passes off
and no preset ever ticks an AI (token-spending) pass.


After the adjuncts, **discovery is fed back into the engine** (`app/engine/discovery_probe.py`): the paths ffuf/katana found and the params arjun found — persisted as `kali_discovery`/`kali_crawl`/`kali_params` findings — are turned into synthetic `TargetOperation`s and the core checks run against them in a **second pass on its own budget** (`settings.discovery_probe_budget`, default 150, independent of the main 750). Gated on `kali`. It never mutates (a shadow path has no spec pairing to restore), so the write oracle, mass assignment and schema fuzz are excluded; a discovered finding carries no `operation_id` because its synthetic op is not a row in the operations table. This is the one place the engine tests endpoints the spec never declared — where API9 shadow-endpoint bugs live.

### AI (opt-in per run) — two touch points

The same subprocess planner backs two independent, opt-in AI steps:

- **`plan: true`** (before the engine) — the runner calls `_plan`, which sends the
  operations (method/path/params/auth_scope — no secrets) to the planner and gets
  back a per-op risk priority + rationale. It **reorders `ctx.operations`** high→low
  so the 750-request budget hits the riskiest endpoints first, persists the plan on
  `ScanRun.plan`, and meters cost under the `plan` phase. Purely advisory to
  ordering — it never changes what the checks do.
- **`adjudicate: true`** (after the engine) — passes findings whose `check` is in
  `HYBRID_CHECKS` (`bola`, `bfla`, `ssrf` — see `app/ai/types.py`) to the cascade,
  which sets `verdict` and `ai_rationale` and writes `TokenLedger` rows priced by
  `app/ai/pricing.py`. On a **confirmed** verdict it may also return a
  `remediation` — an evidence-specific fix that overrides the static catalogue
  line on that finding (never on a dismissal, and never blanks a real fix). It
  is cached on `AdjudicationCache.remediation` (migration `0015`) beside the
  verdict, so a re-scan reuses it without re-spending tokens. Pure enhancement:
  the static remediation always stands when the model returns none.

**`PLANNER_PROVIDER` picks who does the planner's job.** The default,
`deepseek`, runs every mode as one direct DeepSeek completion on
`EXECUTOR_MODEL` — no tool use, no Agent SDK, no `claude` CLI, and no
`.venv-ai` (the agent script then needs only `httpx`, so it falls back to the
service's own interpreter). `anthropic` restores the Opus planner below, with
DeepSeek as its triage tool. Q&A, payload design and the security review are
DeepSeek in both.

With `anthropic`, the Claude Agent SDK pulls `mcp`/`starlette` versions that conflict with
FastAPI's pins, so **the planner runs in its own venv as a subprocess**:
`app/ai/planner.py` shells out to `.venv-ai/bin/python ai_runtime/plan_agent.py`
with a `mode` (`plan` | `adjudicate`) and speaks one JSON object over
stdin/stdout. Setup is in `services/api/ai_runtime/README.md`.

Every AI failure path degrades gracefully: a missing venv, missing `claude`
CLI, or bad model output raises `PlannerUnavailable`; the runner emits an
`ai_skipped` (adjudicate) or `plan_skipped` (plan) event, and the scan completes
with engine findings intact, verdicts left `unreviewed`, and operations in spec
order. Preserve that property — never let an AI problem fail a scan.

### Scheduling

`schedule_minutes` on a scan plus a celery-beat task
(`dispatch_scheduled_scans`, every 60s) that enqueues scans whose `next_run_at`
is due and advances the timestamp. Logic lives in `app/scans/scheduler.py`; the
beat entry is in `app/workers/celery_app.py`.

A schedule is a standing run request, not metadata. Enabling one
(`PUT /scans/{id}/schedule` with `minutes`) answers the same gates as a manual
run — `authorized: true`, premium entitlement, the target guard — through the
shared `_require_run_authorization` in `app/api/routes/scans.py`, and saves the
run flags on `Scan.schedule_options`. Every scheduled run is enqueued with
exactly those options; the only thing re-decided at dispatch is entitlement (a
tenant that lost premium has its premium passes dropped). Clearing a schedule
needs no authorization and forgets the options.

Each `ScanRun` archives the `options` it ran with, so `GET /scans/{id}/diff` can
tell "fixed" from "never looked": an older-run finding whose check needs a pass
the newer run left off (`run_options.required_passes`, derived from the
registry's `mutates`/premium traits and the adjunct key names) lands in
`not_retested`, not `resolved`.

### Frontend

Next.js App Router: a static marketing landing page at `/` and a static
`/coverage`, plus three client pages (`/scans`, `/scans/new`, `/scans/[id]`).
There is no data-fetching framework and no server-side data fetching:
`apps/web/lib/api.ts` is a hand-written typed client whose interfaces mirror
`app/api/schemas.py`, and pages call it from `useEffect`. **When an API response
shape changes, update `lib/api.ts` by hand** — nothing generates it. The one
part that *is* verified is `RunOptions`: the mirror test fails if a run flag the
engine accepts cannot be sent from here.

**Every page outside `PUBLIC_PATHS` (`/`, `/cli`, `/coverage`, `/login`) is
behind a session** (`app/components/AuthGate.tsx`). The token lives in the tab's
sessionStorage, so the check is client-side: the gate renders nothing until the
probe settles and then shows `SignInPanel` in the page's place (no redirect, so
the URL and drafts survive). It is a UI gate, not a security boundary — the API's
own auth is — and an open dev server with no admin still shows sign-in, with the
`make admin` hint. Sign-in is the browser's only way in: there is no API-key
field or server switcher (the API address is `NEXT_PUBLIC_API_URL`, fixed at
build time); API tokens are for the CLI and CI. The e2e fixture seeds a
signed-in session by default.

`/scans/new` and `/scans/[id]` share their forms rather than each keeping a
copy — `app/components/RunPanel.tsx` (the opt-in passes plus the authorization
gate), `app/components/CredentialsPanel.tsx` (`startOpen` puts it in wizard
mode) and `app/components/scanShared.ts`. They were duplicated once and drifted:
the wizard silently forwarded four of the seven run flags. Add a pass in one
place.

The landing page explains the engine visually — the six-stage scan lifecycle and
the three evidence tiers — from `app/components/Flow.tsx`. Its hero is
`app/components/HeroStage.tsx`: one invented example scan (a confirmed BOLA)
drawn on the `--shell-*` palette, so it reads the same in both themes; its
selectors are scoped under `.stage` because short names like `.tier` and `.sp`
are already taken elsewhere. Like `lib/coverage.ts`
it is a hand-maintained mirror of the engine; keep both in sync when checks or
the runner change.

**Light is the default theme and the one the UI is designed in.** Dark is an
explicit opt-in: `ThemeToggle` writes `data-theme` on `<html>`, a boot script in
`layout.tsx` applies the stored choice before first paint, and
`prefers-color-scheme` is deliberately not consulted. Token overrides therefore
live under `:root[data-theme="dark"]`, not in a media query.

Styling is plain CSS in `app/globals.css`, organised as tokens → base →
primitives → feature blocks. Every colour is a CSS custom property with a
`:root[data-theme="dark"]` override, so use the tokens (`--ink`, `--accent`,
`--red`, `--surface-2`, …) rather than literal colours, or dark mode breaks.

### The CLI (`cli/`)

**The everyday form is `aidetector URL [DIR]`** (`cli/internal/commands/target.go`), or bare
`aidetector` inside a project with an `aidetector.yml` (`cli/internal/project`). It composes
the subcommands: consent first, then reuse the scan for that target (or create one), find a
spec, upsert identities by name, run, and print the findings. Like `run`, it is always a
local run (below); a DIR adds whitebox source (`--source` on `run`). `aidetector.yml` sets settings with precedence **flags > file > web >
defaults**, per setting. It never holds secrets (`secret_env` names an environment variable;
secret-looking keys are refused) or consent (no `authorized` key, unknown keys refused). The
CLI reports what the file owns via `PUT /scans/{id}/managed-config` → `Scan.managed_config`,
which the web uses to lock those controls. Each run records `ScanRun.config_source`
(path + digest + commit; migration `0038`), and the diff's `config_changed` compares path +
digest. `config_source` travels **inside the Celery options dict**, not as a task argument:
`RunOptions.from_dict` drops the unknown key in an older worker, while an unknown keyword
would fail the task during a rolling deploy.

A single static Go binary that drives the server over the same API the web UI uses, and is
the way to gate a pipeline (`run --fail-on high --verified-only --new-only`, or `wait` to
attach to a run already going and gate on it the same way; exit
codes 0 clean, 1 findings, 2 usage/auth, 3 failed, 4 timeout). It is hand-written, not
generated — FastAPI emits OpenAPI 3.1, which Go generators only partly support — and two
tests keep it honest: the Go contract tests read `cli/testdata/openapi.json` (every route
it calls exists; every `RunRequest` boolean is a flag), and
`tests/test_cli_contract_snapshot.py` fails when that snapshot stops matching the live
app. **Changing the API contract means `make cli-contract` then `make test-cli`, and
committing both.** The CLI keeps the product's safety posture: `run` answers the
authorization gate before sending any request and refuses a non-interactive run without
`--authorized`; secrets are never flags (prompt, `--key-stdin`, `--secret-stdin`, or
`AIDETECTOR_API_KEY`); its config and reports are written `0600`.

**`aidetector mcp`** (`internal/commands/mcp.go` over the hand-written stdio server in
`internal/mcp`) is a setup helper for coding agents: it serves the user guides in
`cli/docs/*.md` (embedded, and linked from `cli/README.md`) and tools that find the spec,
draft `aidetector.yml` through `init`'s own `draftInitFile`, validate it with
`project.Parse`, and list the commands for the person to run. It deliberately has **no tool
that runs a scan** (a tool call is not a person answering the authorization gate; a test
pins the exact tool set), never handles a secret value, and confines every path to the
directory it started in, because `suggest_config` sends the spec's text to the server.
`TestGuidesMirrorTheProjectFileAndTheFlags` fails when a project-file key or a `RunFlags`
pass is undocumented, or a guide is not served or not linked from the README.

The web UI is the **fast lane** (levels quick and standard, plus the writes and AI
switches; `deep` — ZAP, Kali, the confirm tools — is shown as CLI-only) and the CLI is
the heavy lane. The server still accepts every run
flag — the split is a UI gate, not an API change. The two lanes also differ in where the
traffic comes from: a web run is executed by the server's Celery worker, while **every CLI
run is local** — there is no `--local` flag and no CLI path that queues a server-side scan.

**A CLI run sends the scan traffic from the CLI machine** (`runLocal`,
`cli/internal/commands/local.go`, reached from both `run` and the target form). The CLI
claims the run (`POST /scans/{id}/local-runs`, `app/api/routes/runner.py`, off unless
`LOCAL_RUNNER_ENABLED` — a 404 there prints that hint) — the server answers the
authorization gate, the target guard and the premium check, issues the request budget and
a hashed per-run token — then starts `app/runner` in a hardened throwaway container
(`make runner-image`). A local run performs every pass (`run_levels.LOCAL_REFUSED` is
empty): the confirm tools, testssl and OAST ship in the runner image, ZAP and Kali run as
sibling containers the CLI starts, and the AI passes make their planner calls on the
service (`/runner/runs/{id}/plan` and `/ai` in the loop; adjudication and the security
review after the upload, `workers/tasks.py:review_local_run`), which holds the model keys,
the ledger and the per-run cap. Identities the CLI creates are `local_only`: the server
stores the shape, the secret stays on the CLI machine. The runner is the engine tier run without a database:
`app/engine/execution.py` is the DB-free core, `app/runner/main.py` supplies an HTTP-backed
`RunJournal`, and `tests/test_layering.py` imports both with SQLAlchemy blocked so neither
can grow a DB dependency. Invariants to keep: credential secrets reach the container on
stdin only (never argv, env or the server); the container holds the per-run token, never
the API key, and the token dies when the run ends (and when the reaper fails it);
redaction happens in the runner, then again, pattern-only, on the server; fingerprints
and remediation are the server's (`append_finding`), so identity does not depend on the
runner's version; `target_guard` runs in the runner with `allow_private=True` but always
blocks cloud metadata. `ScanRun.executor` records who ran a run, and the diff flags
`executor_changed` because a different vantage point can make a finding look fixed or new.

**Database schema context is local-only** (`docs/database-schema-context.md`). It is a
`schema:` block in `aidetector.yml` (password named by `password_env`), read only by the
local runner (`app/runner/schema.py` → the bounded `app/db_schema/postgres.py` adapter) on the
CLI machine; the password reaches the container on stdin like credential secrets. The runner
uploads a structure-only snapshot with its results, re-validated by
`db_schema.contracts.accept_upload` (a bad one is stored as `invalid_upload`, never a refused
run) onto `ScanRun.schema_context` (migration `0052`, which also dropped the old
`database_connections` table and its encrypted passwords). Every consumer — adaptive, AI
resource refinement and the security design review — reads `ctx.schema_context`,
set once per run: by the runner from its own read, or on a server run from the newest available
snapshot (`db_schema/snapshots.py:latest_snapshot`). The schema-reading AI passes of a local
run run on the server, since none sends target traffic: `security_review` after the upload
(`workers/tasks.py:review_local_run`), and `plan` when the runner asks before its first check
(`POST /runner/runs/{id}/plan`, which only reorders the claim's operations and returns the
stored plan if asked twice). The runner starts its heartbeat first, so a slow plan never trips
the reaper.

### Sign-in and sign-up

Password accounts sit on the existing users/memberships/API-token tables
(`app/scans/accounts.py`, routes in `app/api/routes/auth.py`, migration `0053`).
`POST /auth/signup` creates a `pending` user with a password and **no
membership**, so it authenticates to nothing until an admin approves it
(`/workspace/signups`) with a role. `POST /auth/login` mints a `session` row in
`api_tokens` that always expires (`SESSION_HOURS`, default 12) and is hidden from
the workspace token list; the web sends it as `X-API-Key` like any token.
The first admin is created from a shell (`make admin`, `python -m app.manage
create-admin`), never over HTTP. Rules worth keeping: a sign-up for an email that
already exists changes nothing and gets the same 202 (otherwise it could plant a
password on a member); an unknown email still costs one scrypt verification; a
422 on `/auth/*` never echoes the input; and once an active admin has a password,
the keyless dev "open" posture closes (`auth_required(db)`).

Both routes are rate-limited by `app/scans/throttle.py` (fixed-window counters in
`auth_throttle`, migration `0054`, pruned hourly by the `prune_auth_throttle`
beat task): failed sign-ins per email and per client address, sign-ups per
client address (counted before scrypt runs). Buckets never name a user — the
email is a digest and an unknown email locks exactly like a real one — and a
locked bucket answers 429 before the password is checked, so a lockout reveals
neither which accounts exist nor whether a guess was right. The client address
is the direct peer; forwarded headers are deliberately not trusted. `make admin`
lifts a lockout on that email, so locking the admin out cannot lock them out.

## Safety constraints

This is an active scanner; the guardrails are product requirements, not
suggestions:

- The run endpoint's `authorized` gate and the UI's confirmation must stay. Do
  not add a path that runs a scan without explicit authorization — enabling a
  schedule is such a path and answers the same gate. For a target whose domain
  this workspace has verified, `RunPanel` folds the confirmation into the Run
  button ("I'm authorized — run scan on <host>") instead of a checkbox: still one
  explicit act per run, never a pre-ticked or remembered consent.
- `core/target_guard` always blocks cloud metadata, including IPv6 addresses
  that embed an IPv4 one (`::ffff:169.254.169.254`, 6to4, NAT64, Teredo). A new
  address rule must be judged against the embedded address too.
- **A public target is scanned only after its workspace proves ownership**
  (`app/scans/domains.clear_target`, `app/core/ownership.py`; migration `0055`,
  `/workspace/domains`). Proof is two-part on purpose: a DNS TXT record at
  `_aidetector-challenge.<host>` (queried over DoH, never the local resolver)
  proves the *name*, and an HTTP token at `/.well-known/aidetector-verify/<token>`
  fetched from the *pinned* address proves the machine — owning `attacker.com`
  lets anyone point `victim.attacker.com` at someone else's IP. The run, schedule
  and local-claim routes answer it, and the worker repeats it at scan start.
  Exempt: hosts that resolve only to private addresses, the operator's
  `target_allowlist`, and `TARGET_REQUIRE_VERIFICATION=false`. Exemption is
  decided by **resolved address, never by name**, and scan traffic connects to
  the address that was judged (`app/core/pinning.py`): a target cleared as
  private stays private-only, so a rebinding resolver or an edited `/etc/hosts`
  cannot turn `localhost` into a public machine. The local runner repeats both
  rules from its own resolver (`LocalRunConfig.target_policy`, `_target_pins`).
  Hosts are compared in one spelling (`pinning.canonical_host`: IDNA, lower-case,
  no trailing dot) — a pin keyed on `bücher.example` must hold for a request to
  `xn--bcher-kva.example`. A check that opens its own socket (`tls_config`,
  `request_smuggling`) connects to `ctx.connect_address(host)`, never a lookup of
  its own. The adjunct tools (ZAP, Kali, the confirm tools, testssl) do their own
  DNS and cannot be pinned, so `AdjunctPhase` re-resolves before each pass and
  skips the rest (`<tool>_skipped`) once the answer drifts from the pin.
  Credential grant/refresh URLs reach other hosts with only the egress check —
  authentication calls, not attack traffic.
- `docker-compose.yml` publishes host ports on loopback (`BIND_HOST`, default
  `127.0.0.1`). The broker is unauthenticated and the worker trusts a queued
  `run_scan` message, so a reachable Redis bypasses every API gate.
- Keep the per-scan request budget. Removing it turns the tool into a DoS.
- The write oracle (`write_authz`) mutates the target, so it must stay behind the
  explicit `mutate: true` opt-in (`ctx.allow_mutation`, off by default) and keep
  its restore/cleanup behaviour. Do not enable it by default, and do not add
  destructive attack verbs (DELETE as an attack) to it.
- `race_condition` is the **one check that bypasses the per-host rate limiter**:
  a race can only be caught by requests that land together, so `HttpProbe.burst`
  fires a small concurrent burst (`settings.race_burst`, default 6) straight at
  the transport, skipping the `aiolimiter` bucket. It stays safe by being
  `mutate:true`-only, bounded, budget-counted (each burst request still reserves
  a slot from the 750 cap), no-opping unless the transport can actually burst
  (`probe.can_burst()` — the sync test client cannot), firing only where a
  *sequential* duplicate was refused first (so it never load-tests an endpoint
  with no constraint), and DELETE-cleaning everything it creates. Do not widen
  the burst or reuse the limiter bypass for any other check.
- `mass_assignment` writes too, under the same opt-in, and adds one rule of its
  own: **it writes a canary, never a real privileged value.** Sending
  `{"role": "admin"}` would escalate privileges on someone's system; a canary
  proves the field is client-writable, which is the finding. That is also why it
  only probes string-valued fields already present on the object — the original
  is known and restorable, and there is no non-escalating value for a boolean
  `is_admin`. A test asserts on the recorded request bodies that only a canary
  or the original value is ever written. It probes **create** pairs too (POST
  collection ↔ GET item): with no object to read first it injects an undeclared
  server-owned name from a curated shortlist at creation and confirms by reading
  the created object back, DELETE-cleaning what it makes — update pairs restore,
  create pairs delete. The create path also seeds nested parents via
  `app/engine/sequence.py` (once per pair, reused across the field probes, torn
  down after).
- `ctx.allow_mutation` gates *all* state-changing probes, not just the write
  oracle: `mass_assignment`, `race_condition`, `seeded_bola`, body-sink injection
  (reflection/signature/OOB into POST/PUT/PATCH bodies) and DELETE probing in
  `broken_auth`/`bfla` only fire under `mutate: true`. A default scan reads and fuzzes GET query/path only — it never writes.
- Credential secrets are encrypted at rest and decrypted only inside the worker.
  Never log, export, or return them — the API deliberately never echoes a secret
  after upload. The api and worker must share one `VAULT_KEY` (`make env`
  generates it; comma-separated keys rotate, first encrypts). An unset key is
  refused outside `ENV=dev`, and a secret no key opens drops that identity with
  a `credential_unreadable` event rather than failing the run.
- The server never connects to a target database and never stores a database password.
  Schema context is read by the local runner only; do not add a server-side connection path,
  and keep the adapter's fixed read-only catalog queries, deadlines and output bounds — it is
  still our code holding the user's password.
- `services/target` is intentionally vulnerable and must never be deployed
  anywhere reachable.
