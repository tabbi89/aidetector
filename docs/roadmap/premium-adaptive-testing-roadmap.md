# Change set I — Premium adaptive validation testing

Status: **Implemented (Premium, read-only first release)**.
All new items I1–I6 are **Premium**.
This extends the [canonical roadmap](../roadmap-phase.md) with a new premium
phase following change set H — test effectiveness and contracts.

## Intended workflow

**API spec → endpoint → highest-risk applicable test → request (payload) →
response → AI analysis (optionally fetch read-only DB schema) → improve payload
→ rerun the same test.**

Prioritize critical validation and authorization risks rather than treating
every endpoint/test combination equally. Use the existing spec parser, request
builder and test catalogue. The AI proposes a focused revision based on the
previous result; the engine decides whether that revision can execute.

Configure **2 or 3 total payload attempts per endpoint/test pair**, default 3,
including the initial attempt: at most two refinements. This is not 3 retries
after an initial request. Controls, setup, read-back and cleanup are additional
requests, all counted within the existing per-scan request budget. No recursive
subtests or model-selected retries may reset either limit.

Schema context is optional. Without a configured, available connection, the
loop uses the API spec and sanitized response observations and explicitly marks
DB-assisted analysis unavailable. It must not infer that validation passed.

## I1. Read-only database connection and schema tool — Premium, implemented

> **Superseded by local-only schema context (migration `0052`).** The server no
> longer stores a connection or connects to a target database: the connection is a
> `schema:` block in `aidetector.yml`, read by `aidetector --local` on the CLI
> machine, and the scan's AI passes reuse the uploaded structure-only snapshot. See
> [database schema context](../database-schema-context.md). The original plan follows.

Let the user define a target database connection in scan setup and attach it to
that scan. Initial scope: **PostgreSQL schema metadata**, with other database
adapters deferred. The API, worker connection test and bounded catalog adapter
are implemented; see [setup and current limits](../database-schema-context.md).
API-field mapping, richer normalized constraints and the AI tool bridge remain
before I1 can be marked complete. The UI setup form belongs to I5.

- Configure a connection label, host, port, database, username, password, TLS
  settings and an explicit schema/table allowlist. Optionally map API request
  fields to columns; inferred mappings carry uncertainty and cannot establish
  a finding on their own. Keep target DB connections separate from the
  scanner's own application database and test harness.
- Require a dedicated database identity restricted to necessary metadata
  access, with no application-row reads, writes, DDL or executable application
  routines. Verify supported privilege restrictions before enabling the tool;
  fail closed if they cannot be established. Use read-only transactions as an
  additional restriction, not as a substitute for least-privilege grants.
- Encrypt the secret with the existing vault. Tenant-scope creation, attachment,
  connection testing, rotation and removal. Return masked configuration/status
  only; do not expose secrets or DSNs to the model, API responses or logs.
  Queued jobs carry an identifier, not connection secrets. Revalidate ownership
  and connection availability in the worker, including scheduled runs.
- Provide a user-triggered connection test and a bounded tool such as
  `get_db_schema(connection_id, tables)`. The server resolves the scan's bound
  connection and rejects any other connection or table selection. Tool queries
  are fixed, parameterized metadata queries; the model cannot submit SQL.
- Return only approved structural facts: tables/columns, types, nullability,
  lengths, unique keys, foreign keys and normalized constraint facts. Exclude
  rows, sample values, comments, raw defaults and routine definitions. Do not
  pass raw constraint expressions containing literals to AI; omit anything
  that cannot be represented safely as an approved structural fact.
- Apply DB-specific destination controls to actual connections: explicitly
  approved hosts/ports, metadata-address blocking, DNS/address validation and
  constrained TLS configuration. Reject alternate DSN routing options. Permit
  approved private target DBs without treating all private destinations as safe.
- Bound connection/query duration, calls, tables and output bytes. Cache approved
  metadata within one run; refresh it on subsequent runs. Keep full schema
  snapshots out of findings and exports, and record sanitized access audit events.

Acceptance: controlled DB fixtures prove scoped metadata access succeeds;
overprivileged identities, cross-tenant references, forbidden destinations,
arbitrary SQL, application-row access and secret-bearing metadata are rejected
or excluded before reaching the model. Unreachable, revoked or unsupported
connections produce a visible unavailable state while core scanning completes.

## I2. Select critical endpoints and tests — Premium, implemented

Rank operations using authentication scope, sensitive field names, write
semantics, declared constraints and existing findings. Reuse existing planning
where useful, but select the **highest-risk applicable test per selected
endpoint** for the first release and retain the reason for that selection.
Keep a bounded endpoint allowance; unselected operations are recorded as
untested by this phase, never as passed. Risk priority is not finding severity.

Build a spec-valid baseline with the proper identity and required parameters,
then vary one validation rule or field at a time. Retain all unrelated valid
fields so malformed setup does not hide the behavior under test. Candidate
rules include required fields, type/format/length/range boundaries, enum
handling and server-owned fields where a safe existing oracle applies.

DB constraints help compare the API contract with storage expectations; they
do not establish that an endpoint maps to a particular table or that a rule
belongs in the application layer. Skip unsupported mappings and unsafe tests
with a reason. Use deterministic selection if AI ranking is unavailable.

Acceptance: fixtures show risky operations selected first, valid baselines,
one-rule changes, ambiguous mappings handled explicitly and no execution of
mutation-only tests when mutation is disabled.

## I3. Bounded AI refinement loop — Premium, implemented

Add a proposed default-off `adaptive:true` run option, requiring server-side
premium entitlement, `premium:true` and the existing `authorized:true` gate.
Neither existing `plan` nor `adjudicate` flags implicitly activates this loop.
Place it after core checks and before adjuncts/final adjudication, sharing the
core `HttpProbe` budget rather than opening a separate HTTP allowance. Give
the phase a configurable sub-cap within the remaining budget.

For each selected test, execute the baseline/control and first candidate,
extract bounded sanitized response observations, and ask AI for a structured
assessment plus an optional revised payload proposal. The schema tool is
available only when I1 is configured. Validate proposals against an allowed
payload grammar, selected operation, identity, field and test family before
execution. The model cannot change target origin, method, credentials, gates,
tool permissions or resource limits, and cannot execute arbitrary code or SQL.

All attempts, controls and read-backs use `HttpProbe`, respecting target guards,
rate limiting and the remaining request budget. State-changing requests require
`mutate:true`, safe canaries and existing restoration/cleanup strategies. Do not
introduce DELETE as an attack verb. Reserve cleanup capacity before writes;
stop further writes after cleanup failure and report uncertain target state.

Stop on a verified result, decisive controlled rejection, no useful/new safe
payload, attempt limit, request/token/cost budget, deadline, cancellation or
unavailable AI. Enforce limits outside the model and check cancellation before
each request/tool/model call. Bound in-flight calls with timeouts. Meter every
model attempt under an adaptive phase; reuse the per-scan ledger. Model failure
preserves core findings and completed attempts with an explicit stop reason.

Acceptance: deterministic model/tool doubles prove no fourth payload attempt,
no duplicated-payload retries, no budget reset, cancellation between attempts,
bounded timeouts, cleanup on partial failure and rejection of out-of-scope
proposals. Disabled/non-premium runs make no adaptive calls or token spend.

## I4. Validation-bypass evidence and confidence — Premium, implemented

Evaluate whether the input was rejected, accepted as designed, or accepted in
violation of an expected rule. A 2xx status alone does not prove that a field
was used or persisted. An AI interpretation or schema discrepancy is likewise
insufficient to set `Confidence.verified`.

| Outcome | Required evidence and presentation |
| --- | --- |
| Validation enforced for the tested case | Valid baseline succeeds and the controlled invalid input is rejected for the intended rule. Report the tested rule; do not claim endpoint-wide safety. |
| Suspected validation gap | An invalid shape appears accepted or API/DB expectations differ, but there is no behavioral proof. Keep it heuristic and explain normalization, stale specs and uncertain mappings as possible alternatives. |
| Verified validation bypass | Controlled API behavior demonstrates the rule is bypassed and the security effect; persisted-write claims additionally require authorized API read-back with a canary and cleanup. Schema-only DB access never reads rows to verify persistence. |
| Inconclusive or skipped | Missing baselines, unavailable schema, ambiguous mapping, insufficient oracle, timeout or exhausted limits prevent a conclusion. Preserve the limitation rather than reporting a pass. |

Distinguish application rejection from a database constraint error where
observable; otherwise report that the rejecting layer is unknown. Neither a
database constraint nor its absence proves which application validation ran.
Keep contract drift separate from a demonstrated security impact and reuse
existing findings where the same weakness is already recorded.

Acceptance: paired secure/vulnerable fixtures cover ignored fields, normalized
inputs, misleading 2xx responses, DB-only rejection, stale contracts and actual
canary read-back. AI cannot promote any ambiguous case to verified confidence.

## I5. Scan setup, attempt history and reporting — Premium, implemented

Show **Premium** on the adaptive-run control and DB-schema connection setup in
both new-scan and existing-scan flows. Show the 2/3-attempt choice, bounded
endpoint/request/time/token allowances, DB connection status and mutation opt-in
before execution. Persist settings for repeat/scheduled runs while preserving
the existing authorization policy and rechecking entitlement and connection
access at execution time.

Record a sanitized per-test timeline: operation, selected rule and rationale,
attempt number, synthetic payload change, response status/structural facts,
schema facts used, AI assessment, cost and stop reason. Keep raw request and
response bodies, tokens, connection secrets and customer values out of stored
history, AI inputs, findings and exports. Treat specs, responses and metadata
as untrusted data; validate and redact model outputs before persistence too.

Show tested, skipped and inconclusive coverage separately. Attach relevant
attempts to findings and remediation, preserving human triage. Finding identity
uses method, route, rule and field, never iteration, payload, canary or status;
multiple attempts must not create duplicates or invalidate existing hashes.

Carry the new options/settings through API validation, the named Celery message,
runner, typed web client and shared `RunPanel`. Add tenant-scoped connection and
attempt storage with migrations. Update confidence/report contracts, remediation
and coverage mirrors as applicable; update `Flow.tsx` for the added lifecycle
stage only when implemented. Do not advertise planned features as live coverage.

Acceptance: browser and API contract tests cover configuration, premium gating,
attempt progress, failure/stop explanations and sanitized exports. Sentinel
values cannot reach AI input, logs, history or reports; findings remain stable
across payload changes and reruns.

## I6. Effectiveness gate and rollout — Premium, implemented

Implement in order: **I1 → I2 → I3 → I4 → I5 → I6**. I2 selection work can be
built independently of the DB adapter. Keep the feature off by default through
rollout and enable it only after its evidence and resource limits are verified.

Compare the same controlled targets with adaptive testing off/on: measure
additional verified validation flaws, false positives, unresolved leads, request
count, elapsed time, tokens and cost. Include cases where refinement reaches a
validation gap the first payload misses and secure counterparts it must not flag.
Run model/tool doubles in CI with no external target traffic or paid model calls;
any live-model evaluation uses explicitly authorized isolated fixtures.

The release gate requires all I1–I5 acceptance criteria, DB-backed migration and
tenant-isolation checks, real worker option propagation, browser/contract checks,
lint/type checks and appropriate builds. Report database skips explicitly.
Demonstrate the loop's added value and publish measured limits before marking
these items done. Missing DB/AI services must leave ordinary scans functional
and show the lost adaptive coverage clearly.

## Change set J — AI resource seeding and the resource-lifecycle loop

Status: **Implemented (Premium; default-off, mutate-gated)**.
Four additions on top of I1–I6 are now shipped. The first gives the planner a new bounded
capability — instead of only choosing the next validation variant, it crafts a
**valid resource** from the spec, which the engine creates once and then
reuses. The second makes that loop visible: the coverage page graphs how a
resource is created and how its response and the read-only DB records are
analysed to decide whether the payload can be improved. The third adds a
testing-flow graph that draws the whole loop — selection, payload, request,
response, DB analysis, refinement, reuse — on one page. The fourth records
resource provenance and a value-safe mutation trace for post-run diagnosis.

### Why this phase — gaps a live premium run exposed

A completed premium run against a real multi-tenant API surfaced the gaps below;
each directly motivated the shipped resource-seeding, lifecycle, and
observability work.

1. **One identity, no authorization coverage.** With a single credential the
   cross-identity checks (`seeded_bola`, BOLA/BFLA-on-write) no-op, so object-
   and function-level authorization — API1/API5, the highest risk on an API full
   of `{id}` segments — was never tested. J1 does not mint identities (that stays
   a scan-setup requirement), but it is what gives those checks a real, owned
   object to read back once both identities exist.
2. **The adaptive loop did nothing.** 20 selected tests → 19 skipped
   `unsupported_or_unsafe`, 1 candidate starved at `request_budget`; zero
   payload attempts. The DB schema was fetched (`available`) but never
   consulted, so "analyse the DB records to improve the payload" never happened.
3. **Budget starvation.** The loop runs after the core checks on the shared
   500-request budget, which the core already consumed. It needs a reserved slice
   (like discovery's independent budget) or an earlier slot; J2's graph makes the
   starvation legible instead of a silent `request_budget`.
4. **Path parameters and authorization are a blind spot.** The selector fuzzes
   only query/body scalar constraints; path IDs are baseline-filled, never
   varied, and there is no "create → read back as another identity" concept, so
   read-heavy object-ID specs select nothing. J1's created resource is the object
   whose id then populates those path parameters for the read-back checks.
5. **No valid seed resource.** With `mutate:true` on, `mass_assignment` and
   `race_condition` still produced nothing: the deterministic
   `resource_map`/`sequence` seed failed validation against a complex create
   DTO, so there was no object to probe. This is the core of J1.
6. **Silent endpoint exclusion.** Four endpoints (an entire onboarding/write
   flow) were opted out and never exercised — a coverage-reporting gap the
   resource-lifecycle graph should surface rather than bury.
7. **Poor signal-to-noise.** 85 of 88 findings were dismissed, dominated by
   static `design_review` / `schema_fuzz` heuristic noise, because the
   high-value behavioural checks were the ones that could not run. J1 raises the
   ceiling on those high-value checks; J2 shows the loop that produces them.
8. **The one confirmed design finding** was a credential in a URL query
   parameter (`token` on a payment-keys endpoint, API2) — static review worked;
   the behavioural layer that should have found the rest could not.

Root cause: the run had **no valid seed resource and no second identity**, so
the stateful/authz checks — the ones that matter most on a multi-tenant API —
were starved of both data and budget. J1 closes the data half by making the AI
craft an accepted resource; J2 and J3 make the lifecycle and testing flow
visible; J4 makes the resulting requests and resource provenance diagnosable
without retaining values.

### Intended workflow

**Spec (schemas) → AI-crafted valid resource → POST (create) → response →
response + read-only DB record analysis → refined payload → resource reused for
further tests.**

Where I1–I6 refine a *validation* probe, this loop refines a *fixture*. The AI
reads the full OpenAPI component schemas — nested required fields, formats,
enums, defaults and cross-field rules — and proposes one create payload the
target should accept. The engine validates the proposal against the spec
grammar, sends it once behind the existing `mutate:true` gate, extracts the
created resource id from the documented 2xx response, and registers the object
in the resource map so the stateful checks (`seeded_bola`, the write oracle,
`mass_assignment`, and the `GET /{id}` read-back paths) run against a real,
owned object instead of a heuristic body the server rejects.

The read-only DB schema tool (I1) supplies the second observation: where
configured, the loop compares the response shape and the created object's
declared columns/constraints to decide whether the payload can be improved —
for example a field the schema requires but the response omits, or a value the
API accepts beyond the DB column length. Schema metadata cannot read rows to
verify persistence (I4's rule), so a DB observation is advisory context for the
next payload, never a finding on its own.

### J1. AI-created valid resources — Premium, implemented

- Added the bounded `propose_resource` planner capability as a fallback after
  deterministic `resource_map` / `sequence` creation fails with a clear 400,
  409, or 422 payload rejection.
- Validated every proposal against the declared operation body schema and
  field allowlist before sending it. The model cannot change method, origin,
  credentials, gates, budgets, tool permissions, or execute code/SQL.
- Kept execution `mutate:true`-only and limited the full create flow to 2–3
  total attempts. Accepted IDs are registered for dependent checks and queued
  for declared DELETE cleanup where available.
- Added predefined resource IDs for callers that already have valid fixtures;
  these are reused without a create and are marked separately in the report.
- Failed creates remain stop reasons/events, never findings. IDs, canaries and
  payload values stay out of evidence and exports.

Acceptance: deterministic model doubles and resource tests cover (a) a
heuristic seed that fails being retried through AI; (b) out-of-schema or
out-of-scope proposals rejected before any request; (c) created resources
reused by `seeded_bola` / the write oracle / `mass_assignment` and cleaned up;
(d) predefined IDs bypassing creation; (e) no proposal under `mutate:false`;
and (f) failed creates remaining non-findings without value leakage.

### J2. Resource-lifecycle coverage graph — implemented

- Added a hand-maintained graph to the `/coverage` page beside the existing
  adaptive-validation graph, showing the loop **spec → AI-crafted resource →
  create (response) → response + read-only DB record analysis → refined payload
  → resource reused for further tests**. It mirrors the engine, not the other
  way round: it lives in `apps/web/app/components/Flow.tsx` (rendered from
  `apps/web/app/coverage/page.tsx`), and any check-registry text contracts
  move with `apps/web/lib/coverage.ts`, guarded by
  `tests/test_coverage_mirror.py`.
- The graph separates the two observations (response vs DB metadata) and the two
  gates (`mutate:true` for the create, `premium:true` for the AI), and must
  not imply the DB tool reads rows — schema metadata only, per I1/I4.
- Updated the premium/how-it-works copy to show the explicit `authorized`,
  `premium`, `mutate`, and refinement gates, plus the schema-metadata-only DB
  limitation.

Acceptance: the coverage page renders the graph, the mirror test passes, and
copy does not claim DB row access or an un-mutated create.

### J3. Testing-flow coverage graph — implemented

- Added a hand-maintained graph to the `/coverage` page showing the **flow of
  testing** as one closed loop: **spec → AI analysis → endpoint/test selection →
  payload (baseline or AI-crafted resource) → request → response analysis →
  read-only DB record analysis → refined payload → resource reused for further
  tests → finding**. It sits beside the resource-lifecycle graph (J2) and the
  existing adaptive-validation graph, so the three pictures tell one story: what
  the loop selects, what it creates and analyses, and how the whole test flows
  end to end.
- Draw the gates on the edges — `authorized:true` at the start, `premium:true`
  for the AI steps, `mutate:true` on the create/refine edges — and separate the
  two observations (response vs DB metadata) with the same "schema metadata only,
  no rows" rule as J2.
- Separate the *decision* (which test, which payload) from the *evidence*
  (status, structural facts, schema facts), so the picture reads as "a test is
  run and its result feeds the next step", not "the model drove the scan".
- Mirror the engine, not the other way round: lives in
  `apps/web/app/components/Flow.tsx`, rendered from
  `apps/web/app/coverage/page.tsx`, with any check-registry text contracts in
  `apps/web/lib/coverage.ts` guarded by `tests/test_coverage_mirror.py`.

Acceptance: the coverage page renders the flow graph, the mirror test passes,
and the graph does not claim DB row access, an un-mutated create, or that the
AI owns the budget or gates.

### J4. Resource provenance and mutation observability — implemented

- Persist a sanitized resource row for each supplied or created fixture,
  including source (`predefined`, deterministic, or AI), create/read routes,
  verification status, bounded attempt history, and cleanup outcome. The
  results UI highlights resources created during the scan and summarizes them
  separately from supplied IDs.
- Persist a mutation trace for every core-engine POST, PUT, PATCH, and DELETE:
  sequence, route, check, status, safe request/response headers, query-field
  names, content sizes, and structural JSON metadata. Sensitive headers are
  redacted, and rendered IDs, scalar body values, response text, and secrets
  are never retained.
- Present traces with progressive disclosure in the run results: expandable
  request/response panes, header counts, status badges, and a raw preformatted
  payload preview made from typed placeholders. This is intentionally not a
  raw-value dump; an unsafe payload-capture mode is not part of the shipped
  default.

Acceptance: API and UI contract tests cover nested resource/mutation schemas,
header redaction, created-versus-supplied marking, cleanup status, and the
value-free payload preview. Historical runs remain unchanged; new runs record
the fields when the worker is running the updated code.
