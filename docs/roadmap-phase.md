# Project roadmap — change sets A–J

This is the canonical, top-level roadmap for aidetector. It consolidates the
main outcomes from change sets A through J; the linked documents retain the
implementation detail, acceptance criteria and historical reasoning.

Scoped product work in A–G is **complete and verified**. Change sets I and J add
**Premium** features behind explicit entitlement and run opt-ins. Historical
H0/H0.1/H1 IDs remain unchanged in tooling. Deliberately deferred breadth is
called out rather than counted as unfinished work. In G4, SSLyze was evaluated
and deliberately not adopted.

## At a glance

| Phase | Focus | Main outcome | Status |
| --- | --- | --- | --- |
| **A** | Detection accuracy | Authorization findings use controlled behavioral evidence instead of weak response comparisons. | **done** |
| **B** | Scanner security | Target egress, tenant access, stored secrets and AI execution are guarded. | **done** |
| **C** | Depth and reliability | Scanning is bounded, concurrent, rate-aware, stateful and resilient to optional-tool failures. | **done** |
| **D** | Actionable findings | Confidence and remediation are first-class data throughout the product. | **done** |
| **E** | Detection expansion | Data exposure, mass assignment, races, shadow endpoints and bounded JWT behavior are covered. | **done (scoped)** |
| **F** | Repeatable workflow | Findings keep identity across runs, triage persists, diffs work and more input/auth flows are supported. | **done** |
| **G** | Focused tooling expansion | Fuzz validation, offline secret detection, design rules, JWT and GraphQL depth were added after measured evaluation. | **done (scoped)** |
| **H** | Test effectiveness and contracts | Repair the harness, measure effectiveness and verify backend/frontend contracts. | **implemented; hosted CI verification pending** |
| **I — Premium** | Adaptive validation testing | Prioritize critical endpoint tests, analyze responses with optional read-only DB schema context, and refine payloads within 2–3 total attempts. | **implemented (read-only first release)** |
| **J — Premium** | Resource seeding & lifecycle observability | Deterministic and optional AI-refined resources, predefined IDs, provenance/cleanup status, redacted mutation traces, and coverage graphs for the create → analyze → refine → reuse flow. | **implemented (default-off; mutate/premium gated)** |

## A — detection accuracy

- Rebuilt BOLA around anonymous rejection, static-content controls and
  cross-identity behavior.
- Rebuilt broken-auth testing around controlled JWT forgeries and explicit
  acceptance of a named bypass class.
- Rebuilt BFLA around declared security scope and privileged behavior rather
  than URL naming alone.
- Added mutation-gated seeded BOLA sequences that create as one identity, read
  as another and clean up created state.

## B — the scanner's security posture

- Added guarded target egress, cloud-metadata protection and an explicit remote
  `$ref` allowlist.
- Added API-key authentication, tenant scoping and constant-time key matching.
- Kept credential secrets encrypted at rest and added central secret/PII
  redaction before findings are stored or exported.
- Hardened AI inputs and constrained the planner's tool permissions.
- Applied the same target guard to credential grant and refresh URLs.

## C — depth and reliability

- Added an async transport, per-host rate limiting, bounded concurrency, fair
  request allocation, 429 backoff and cooperative cancellation.
- Added spec validation, safe internal and bounded remote reference resolution,
  SARIF export and cached AI adjudication.
- Added schema-driven fuzzing and persistent OAST correlation while keeping
  optional integrations failure-isolated.
- Added authenticated token refresh and stateful producer→consumer sequences,
  including nested-resource setup and cleanup.
- Kept core traffic within the per-scan request budget and external adjuncts
  within a shared wall-clock budget.

## D — findings that lead to fixes

- Added `heuristic` and `verified` confidence as stored finding data, propagated
  through sorting, API responses, UI, reports, SARIF and AI adjudication.
- Added centralized CWE-aware remediation and references for every engine check.
- Added evidence-specific AI remediation for confirmed findings, with cached
  results and deterministic remediation as the fallback.

## E — new detection

- Added zero-extra-request excessive-data-exposure checks over the shared
  response sweep; only field names, never values, reach evidence.
- Added mutation-gated mass-assignment checks using harmless canaries, read-back
  confirmation, restoration and create cleanup.
- Added a small, budget-counted race-condition burst only after a sequential
  control proves the target normally enforces the constraint.
- Added a separate, non-mutating discovery pass over paths and parameters found
  by Kali tooling, with its own request budget.
- Added the first bounded JWT-depth probes, including case-variant `alg=none`
  and empty-key `kid` traversal behavior.

## F — repeatable scanning workflow

- Added stable finding fingerprints based on what and where, excluding rotating
  payloads, values, statuses and counts.
- Persisted human triage across reruns and made it override later AI verdicts.
- Added run-to-run added/resolved/unchanged diffs over archived snapshots.
- Added static, OAuth client-credentials/password and cookie-login credential
  flows with graceful minting failure.
- Added value-dropping HAR and Postman import, producing normalized OpenAPI for
  the existing engine.

## G — focused detection and tooling expansion

1. **Schema fuzz response validation:** Schemathesis cases now validate declared
   status, content type, headers and response schema, with fair positive/negative
   case allocation and one request per case.
2. **Offline potential-secret detection:** bounded `detect-secrets` analysis
   scans reused response samples and uploaded specifications without network
   verification or retention of candidate values.
3. **Design governance:** deterministic rules flag missing error contracts,
   undocumented rate-limit contracts and unbounded collection schemas.
4. **TLS tool evaluation:** a controlled benchmark found no unique confirmed
   SSLyze coverage worth its substantially higher connection volume. SSLyze was
   not adopted; the existing testssl adapter's JSON and critical-severity
   handling were corrected.
5. **Targeted JWT depth:** bounded weak-HMAC-key testing and correctly signed
   expiry/`nbf` controls were added, with recovered keys kept in memory and out
   of evidence and logs.
6. **Bounded GraphQL behavior:** added shallow field-suggestion checks and
   controlled alias/batch authorization comparisons. Support alone is not a
   finding; mutation replay and overload testing remain out of scope.

## H — test effectiveness and contracts

H0 and H0.1 cover the completed harness and behavioral/integration work. H1
implements effectiveness measurement and API/frontend contract checks; hosted
CI verification remains pending. See the existing
[tooling roadmap](roadmap/tooling-expansion-roadmap.md#change-set-h--test-effectiveness-and-contracts)
for scope and acceptance criteria.

## I — adaptive validation testing (Premium, implemented)

The loop: **API spec → endpoint → highest-risk applicable test → request
(payload) → response → AI analysis + read-only DB schema tool → improved
payload → rerun the same test**. Each selected test gets at most **2–3 total
payload attempts**, including the first; it can stop earlier.

The aim is to detect inputs that bypass expected validation, using controlled
API behavior as evidence and database constraints as supporting context.
Schema access alone cannot prove which application validation ran or whether
a write persisted.

| Item | Scope | Tier | Status |
| --- | --- | --- | --- |
| **I1** | Scan-scoped, encrypted read-only database connection and a schema-only AI tool. | **Premium** | **implemented** |
| **I2** | Rank endpoints and select the highest-risk applicable validation test with a spec-valid baseline. | **Premium** | **implemented** |
| **I3** | Execute a bounded response-analysis/payload-refinement loop through the existing guarded probe. | **Premium** | **implemented** |
| **I4** | Distinguish enforced validation, suspected gaps, verified bypasses and inconclusive results using controls. | **Premium** | **implemented (heuristic leads; no false verified promotion)** |
| **I5** | Add scan setup, attempt history, stop reasons, evidence and per-attempt AI costs to the UI and reports. | **Premium** | **implemented** |
| **I6** | Verify effectiveness, isolation, limits and graceful failure before enabling the feature for premium tenants. | **Premium** | **implemented; default-off rollout** |

See the
[Premium adaptive-testing roadmap](roadmap/premium-adaptive-testing-roadmap.md)
for contracts, limits and acceptance criteria for I1–I6.

## J — AI resource seeding and the resource-lifecycle loop (implemented)

The Premium resource pass turns the adaptive loop from "refine a validation
variant" into "exercise the API the way a real client would". It is available
only when the run is explicitly authorized, mutation-enabled, and premium-gated.

1. **AI-created valid resources.** The planner can read the full OpenAPI component
   schemas — nested required fields, formats, enums and cross-field rules — and
   produces a spec-valid, *accepted* create payload. The engine sends it once
   behind `mutate:true`, extracts the created id from the response, and
   registers the object in the resource map so `seeded_bola`, the write oracle
   and `mass_assignment` run against a real, owned object instead of a
   heuristic body the target's validation rejects. A create that fails is a stop
   reason, never a finding, and the object is cleaned up like every other
   mutation.

2. **Resource-lifecycle coverage graph.** The coverage page now includes a graph of the
   loop this creates: *spec → AI-crafted resource → create (response) →
   response + read-only DB record analysis → refined payload → resource reused
   for further tests*. It is a hand-maintained picture beside the existing
   adaptive graph in `apps/web/lib/coverage.ts` / `Flow.tsx`, not generated
   from the engine, and the mirror test keeps it honest.

3. **Testing-flow coverage graph.** A second graph on the coverage page draws the
   flow of testing as one closed loop — *spec → AI analysis → endpoint/test
   selection → payload → request → response + DB record analysis → refined
   payload → resource reused → finding* — beside the resource-lifecycle graph,
   with the `authorized` / `premium` / `mutate` gates drawn on the edges. Like
   the other two, it is a hand-maintained mirror in `coverage.ts` / `Flow.tsx`.

4. **Resource and mutation observability.** The run archive records whether a
   resource was caller-supplied or created during the scan, how it was created,
   read-back verification, bounded create attempts, and cleanup outcome. The
   write log records POST/PUT/PATCH/DELETE method, route, check, status, safe
   request/response headers, and structural payload/response metadata. Scalar
   body values, rendered IDs, credentials, and response text remain excluded;
   the UI renders a raw preformatted preview using typed placeholders.

See [Premium adaptive-testing roadmap — J1–J4](roadmap/premium-adaptive-testing-roadmap.md)
for contracts, acceptance criteria and the field evidence that motivated the
implementation — including missing valid seed resources, predefined fixture
support, and insufficient mutation/resource observability.

## Invariants across every phase

- Active scanning still requires explicit authorization.
- All target requests remain bounded; race probing is the only tightly limited
  exception to per-host rate limiting.
- State-changing probes remain behind `mutate:true` and restore or clean up
  target state where possible.
- Secrets and response values are never stored as finding evidence.
- Mutation traces retain only redacted headers and structural payload/response
  metadata; scalar body values and rendered resource IDs are not persisted.
- Optional tools and AI degrade gracefully and cannot fail the core scan.
- Heuristic leads remain distinct from behavior that directly verifies a flaw.

## Detailed documents

- [Scanner hardening roadmap — A–C](roadmap/scanner-hardening-roadmap.md)
- [Next-phase roadmap — D–F](roadmap/next-phase-roadmap.md)
- [Tooling-expansion roadmap — G and test-effectiveness work](roadmap/tooling-expansion-roadmap.md)
- [Premium adaptive-testing roadmap — I1–I6, J1–J4](roadmap/premium-adaptive-testing-roadmap.md)
- [Roadmap implementation review](roadmap-implementation-review.md)
- [Execution plan](execution-plan.md)
- [Test-effectiveness baseline](test-effectiveness-baseline.md)
- [TLS scanner benchmark](tls-scanner-benchmark.md)
