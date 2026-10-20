# Tooling-expansion roadmap

Expand the scanner's evidence and measure the strength of its tests, building
on [next-phase-roadmap.md](next-phase-roadmap.md). Prefer improvements to
existing integrations; add a dependency or execution path when it provides
measurable additional coverage within explicit operating limits.

Status legend: **implemented baseline** describes current code; **planned**
describes work still to do; **evaluation** requires evidence before adoption;
**deferred** is outside the initial implementation sequence; **done** means
implemented and verified. H0 and H0.1 are done. H1 is implemented and locally
validated, with hosted CI verification pending. G1 through G6 are complete;
SSLyze was evaluated in G4 and deliberately not adopted.

## Implemented baseline

- **Schema fuzzing uses Schemathesis and Hypothesis.**
  [`schema_fuzz.py`](../../services/api/app/engine/checks/schema_fuzz.py) generates
  cases and sends them through `HttpProbe`, inside the shared 500-request
  budget. It is gated by `fuzz:true`, with GET probes by default and
  POST/PUT/PATCH body probes under `mutate:true`. Schemathesis is already pinned
  in production requirements; the configured case allowance defaults to 20 per
  scan. Positive and negative generation are explicit and fairly share the exact
  allowance across eligible operations. Each collected response is reused for
  status, content-type, required/typed-header and body-schema validation. A 5xx
  is a verified input-handling failure; contract drift is a heuristic finding.
- **Design review is deterministic and uses no AI tokens.**
  [`design_review.py`](../../services/api/app/engine/checks/design_review.py) checks
  sensitive operations without declared authentication, credentials in URL
  parameters, server-owned request fields, missing error/rate-limit contracts
  and unbounded collection schemas. It is gated by `premium:true` and produces
  heuristic design findings.
- **TLS has two existing paths.** The built-in transport check and testssl
  already cover this area. `testssl_timeout_seconds` defaults to 300 seconds;
  the shared adjunct-phase budget defaults to 600 seconds. The phase checks its
  deadline between passes, so that deadline alone does not interrupt a pass
  already running.
- **JWT forgery includes `kid` traversal and bounded HMAC depth.**
  [`jwt_forge.py`](../../services/api/app/engine/jwt_forge.py) retains the empty-key
  traversal probe; [`jwt_hmac.py`](../../services/api/app/engine/jwt_hmac.py) adds
  bounded weak-key and valid-signature time-claim probes.
- **Fingerprint golden tests already exist.**
  [`test_char_fingerprint.py`](../../services/api/tests/test_char_fingerprint.py)
  pins hashes and selected invariants. Generated stability properties would
  extend that protection.

The planned G-series is complete. Deferred breadth, overload testing and future
measurement refinements remain intentionally outside it. More generated cases
do not exhaust an API's input space or automatically prove more vulnerabilities.

## Change set G — detection expansion

### G1. Improve the existing Schemathesis check — done

Keep `fuzz:true` and the `HttpProbe` execution path. Add response status,
content-type, header and schema validation where the spec declares a contract;
configure positive and negative generation explicitly. Improve case allocation
across eligible operations while retaining the global request cap. Validation
should reuse each collected response rather than issue a second request.

Implemented with exact round-robin case allocation in parsed/planned operation
order. Positive and negative modes alternate across rounds, one outbound request
is made per generated case, and findings retain only method, route, rule,
structural response location and (for status findings) the numeric status. The
5xx signal remains verified; conformance drift is low-severity and heuristic.

Report an observed contract mismatch separately from its possible security
impact: schema drift can mean a stale specification. Do not promote every
conformance failure to a verified security weakness. Keep finding identity
based on the route, method, rule and structural location, never generated values.

Acceptance: fixtures demonstrate new violations the current `5xx`-only check
misses, including valid responses that must not be flagged. Tests cover budget
exhaustion, generation failures, mutation gating, and absence of response values
in findings or diagnostic output.

A separate deep-fuzzing adjunct is **deferred**. Adopt one only after a comparison
shows useful findings beyond the improved check. Before adoption, define a total
request cap, rate and concurrency limits, an enforceable timeout, cancellation,
and explicit method/phase filtering. Schemathesis's example count is not a total
request limit across all phases; stateful or unexpected-method probes must not
bypass mutation policy. Do not introduce a duplicate `schemathesis:true` flag
as part of G1. See the [Schemathesis CLI reference](https://schemathesis.readthedocs.io/en/latest/reference/cli/).

### G2. Offline potential-secret detection — done

Use `detect-secrets` through an in-memory wrapper over the body samples already
collected by the header sweep. Scan the uploaded `spec_text` separately for
potential embedded credentials, retaining whether the source is a response or
the uploaded artifact. HAR/Postman conversion drops values, so this cannot
recover secrets from discarded capture content.

- Explicitly disable network verification and test that the wrapper makes no
  outbound requests. The tool supports credential verification by network call;
  its behavior must not be assumed offline. See
  [detect-secrets usage](https://github.com/Yelp/detect-secrets#usage).
- Treat regex/entropy matches as **heuristic potential secrets**, not proof
  that a credential is live or improperly disclosed. Account for placeholders,
  UUIDs, example values and legitimate token-returning authentication endpoints.
  Preserve existing sensitive-field-name findings when adding this separate signal.
- Record only the detector and sanitized structural location with route/source
  metadata. Never record a matched value, surrounding text, secret-derived hash,
  or raw detector object, including in exceptions and logs. Locations must not
  copy credential-bearing URLs or arbitrary secret-bearing map keys.
- Bound input bytes, traversal depth, matches and processing time. Truncated
  samples limit coverage; absence of a match is not proof that no secret leaked.

Acceptance: zero extra network requests, positive and false-positive fixtures,
stable identity when a candidate secret rotates, and sentinel tests proving
candidate values cannot reach persisted findings, reports, AI inputs or logs.

Implemented as a bounded, short-lived subprocess around pinned `detect-secrets`.
Credential verification is explicitly disabled and socket connection primitives
are blocked in the worker as defense in depth. Response analysis reuses header
sweep samples; uploaded `spec_text` is scanned separately. Findings retain only
the source, detector name and sanitized structural location (plus route/method
for responses), and always remain heuristic. Unit and persistence/report tests
cover no-egress behavior, placeholders, UUIDs, examples, token routes, resource
bounds, hard timeout, stable identity and candidate non-retention.

### G3. Extend deterministic design governance — done

Extend `DesignReviewCheck` with Python rules for missing error contracts,
undocumented rate-limit behavior and unbounded collection schemas. These are
review leads, not proof that runtime controls are absent. Retain the existing
`premium:true` gate; no new AI phase or sidecar is needed for this scope.

Use the full safely parsed specification (`ctx.spec`) for rules requiring
responses, schema constraints or security requirements. Flattened `Operation`
rows do not preserve the whole contract. Evaluate inherited global security,
operation overrides, explicit anonymous alternatives and intentional public
operations; absence of an operation-level `security` key is not enough to flag
missing authentication. See the
[OpenAPI Operation Object](https://spec.openapis.org/oas/v3.0.3.html#operation-object).

Acceptance: each rule has a stable identifier, positive/negative fixtures,
reference-resolution and security-inheritance cases, and no new egress.
Spectral is **deferred** unless reusable organizational rulesets or measured
maintenance savings justify a Node runtime. Any later integration must use
trusted rules and preserve the existing restrictions on remote references.

Implemented in the existing premium `DesignReviewCheck` against `ctx.spec`.
The three added heuristic rule identifiers are `missing_error_contract`,
`missing_rate_limit_contract` and `unbounded_collection`. Local response and
schema references are resolved with bounded traversal; effective security honors
global inheritance, operation overrides and anonymous alternatives. Fixtures
cover clean and flagged contracts, composed/reference-backed schemas and zero
target requests. No Spectral runtime was added.

### G4. Evaluate SSLyze against testssl — done; not adopted

Benchmark SSLyze as an opt-in adjunct against the current testssl integration on
controlled TLS fixtures. Measure unique actionable findings, duplicate findings,
wall time, connection count, worker CPU/memory and deployment compatibility.
Being a Python library does not establish a speed or operating-cost advantage.

SSLyze supports cipher enumeration, certificate analysis, ROBOT and
downgrade-prevention checks. Map results individually: a demonstrated vulnerable
behavior can be verified; a missing optional feature or inconclusive scan is
not automatically a proven exploit. For example, lack of fallback protection
does not alone demonstrate an exploitable downgrade. See
[SSLyze scan commands](https://github.com/nabla-c0d3/sslyze/blob/release/docs/available-scan-commands.rst).

Acceptance before adoption: choose replacement or coexistence based on the
benchmark; document coverage losses and deduplication; define a default-off
opt-in and limits on total connections, concurrency, retries and elapsed time.
Honor target restrictions and control any auxiliary certificate/OCSP network
access. The pass must stop within its allocated share of the remaining adjunct
deadline, with timeout/cancellation tests. Do not expand the built-in TLS socket
exception into an unbounded premium check. If identities change when replacing
testssl, document triage/diff compatibility explicitly.

The controlled benchmark is recorded in
[tls-scanner-benchmark.md](../tls-scanner-benchmark.md). SSLyze 6.3.1 completed in
under one second but opened 568–579 connections per target even with reduced
concurrency, versus 117–148 connections and roughly two minutes for testssl.sh
3.2.4. It produced no unique confirmed actionable weakness after accounting for
the built-in check and testssl, and the tools disagreed on ROBOT for the legacy
fixture. SSLyze is therefore **not adopted**: no dependency, flag or execution
path was added. The benchmark did reveal and fix two existing testssl adapter
defects (`--jsonfile` usage and dropped `CRITICAL` entries) without changing
stored identities for existing findings.

### G5. Targeted JWT depth — done

Use existing PyJWT and signing helpers for bounded **offline** HMAC dictionary
testing of supplied tokens. Limit wordlist size and CPU time; deduplicate tokens
and never persist or log recovered keys. Any target confirmation uses
`HttpProbe` and consumes the normal request budget.

Expiry and `nbf` acceptance tests require a valid signature: use a recovered
signing key or a suitable validly signed test credential. Changing claims while
breaking the signature cannot isolate time-claim validation. Compare against
valid-token and rejected-token controls, preserving other claims so the test
does not conflate distinct failures.

Add `kid` variants only where they test a distinct missing behavior; the empty
key-file traversal probe already exists. SQL errors are leads, not proof of
authentication bypass. Preserve the existing premium/OOB separation for JWKS
key confusion and `jku`/`x5u` callbacks. Do not describe this bounded extension
as completing JWT security coverage.

Implemented for supplied HS256/384/512 credentials with a fixed 15-entry list,
a hard maximum of 64 candidates, an 8 KiB token bound and a 50 ms CPU-time
search window. Tokens are deduplicated. A recovered key never leaves the helper;
it signs a privilege probe plus expired and future-`nbf` variants. Behavioral
findings require anonymous rejection, a successful unchanged valid-token control
and a rejected unchanged-claims/bad-signature control, and all requests use
`HttpProbe`. No additional `kid`, JWKS or OAST behavior was added.

### G6. Bounded GraphQL behavior — done; overload testing deferred

Start beside `graphql_introspection` with field-suggestion checks and small
alias/batch comparisons through `HttpProbe`, retaining `premium:true`.
Field suggestions demonstrate schema information exposure, whose significance
depends on context. Alias or batching support alone is not a vulnerability.
An authorization-bypass finding requires showing that an identity gains access
through the alternative form to data denied through an equivalent normal query,
with owner and anonymous controls where applicable.

The [GraphQL Cop detections](https://github.com/dolevf/graphql-cop#detections)
include overload probes; its logic must not be ported wholesale. A single HTTP
request can expand into substantial server work. Bound query bytes, depth,
aliases, batch size and requests, and stop on errors or a latency threshold.
Use known valid query shapes or skip when the schema/fixtures are insufficient.
GraphQL mutations require `mutate:true` and cleanup regardless of HTTP method.

Deep-query and overload testing is **deferred** until a separately reviewed
design defines workload limits and an explicit default-off disruptive-testing
opt-in. `premium:true` and `mutate:true` do not authorize load testing. Prefer
bounded evidence of rejection limits over attempts to cause an outage.

Implemented as the premium `graphql_behavior` check. Anonymous field-suggestion
probing is capped at three shallow queries and remains a low heuristic. Alias and
two-item batch findings require a safe read-only query example plus owner success,
anonymous denial, low-privilege normal denial and equivalent-data success only
through the alternative form. Targets, bytes, depth, aliases, batch size,
requests and per-endpoint time are bounded; server errors stop the endpoint.
Mutation/subscription examples, variables, fragments and unsafe shapes are
skipped. No deep-query or overload behavior was added.

### Other breadth options — deferred

Consider Wapiti only if it demonstrates unique findings beyond ZAP; RESTler
only for concrete stateful scenarios the current sequence engine cannot cover;
and mitmproxy only for an identified live-capture workflow beyond HAR/Postman
import. Each needs its own operational-cost and data-handling assessment before
entering the implementation sequence.

## Change set H — test effectiveness and contracts

### H0. Repair the current harness — done

The five harness gaps are repaired on `codex/test-harness-hardening`. These
changes establish the prerequisite for H1 measurement and detection expansion.

1. **Database protection:**
   [`tests/harness.py`](../../services/api/tests/harness.py) validates the destination
   before creating an engine. Explicit and derived names must identify a
   disposable PostgreSQL database ending in `_test`, with a bounded ASCII
   identifier. The application database must be explicitly named and cannot be
   reused, even through different credentials, ports or host aliases. Routing
   query overrides are rejected on both application and test URLs. The fixture
   restores the original session binding and disposes its engine on teardown.
   Regression tests assert rejection before any connection or destructive call.

2. **Production cancellation tests:**
   [`test_run_stages.py`](../../services/api/tests/test_run_stages.py) injects setup
   and stage work into the real `run_scan` function. The copied execution loop is
   removed; production behavior is unchanged. Tests cover cancellation before
   work and at every enabled stage boundary, completion and exception handling
   without requiring Postgres. In-memory mutation probes demonstrated failures
   when cancellation was removed, delayed until after stage work, or followed by
   completion.

3. **Required database in CI:** `CI=true` or `TEST_REQUIRE_DB=1` makes database
   unavailability fail; CI sets the latter explicitly. Only operational database
   errors may skip when the database is optional locally. Invalid configuration
   and programming errors propagate. An isolated pytest probe verified a failing
   exit for a simulated CI outage and an explicit skip for the same local outage.

4. **Integration isolation:** an autouse fixture restores declared settings
   defaults while preserving database routing. Target socket connections, UDP
   sends and tool subprocesses are blocked; external DNS is disabled outside
   the configured DB endpoint. ASGI/MockTransport tests and libpq database access
   remain available; layering probes explicitly opt into Python subprocesses.
   Eager Celery endpoint tests use the real async bridge with an ASGI target and
   require a completed scan with findings, instead of assuming port 9 is closed.
   This is a test isolation guard, not a sandbox for untrusted code.

5. **Complete target reset:**
   [`vulnapp.reset_state()`](../../services/api/tests/vulnapp.py) now clears `OUTBOUND`
   in place, preserving references held by `CollectorOob`. Manual callback clears
   were removed from OOB tests. A regression test checks callback clearing and
   restoration of the mutable target stores.

Validation includes the complete DB-backed suite on a disposable database,
reversed suite order with sentinel OAST/sidecar/tool settings, targeted harness
regressions, cancellation mutation probes, `ruff` and `mypy`. The tests live in
[`test_harness.py`](../../services/api/tests/test_harness.py) and the existing
runner/OOB suites. No detection tool or production scan behavior was added.

### H0.1. Extend behavioral and integration coverage — done

Implemented on the same `codex/test-harness-hardening` branch:

| Area | Implementation and acceptance |
| --- | --- |
| Realistic targets | `tests/realistic_targets.py` exercises Expat and pickle opcodes with inert external-effect handlers, secure counterparts and benign URL lookalikes. Only the supported Python pickle payload confirms on the pickle target; Java/.NET markers do not. XML payloads must parse successfully. These tests also exposed a missing XML root and an overstated exfiltration label: both are corrected, retaining the historical family identity. No real commands, network callbacks or files are accessed. |
| Concurrency | `test_concurrency.py` uses barriers to exercise simultaneous budget reservations, per-operation ceilings, thread-local attribution, a shared header sweep, and production runner ordering of concurrent readers followed by serial writers. |
| Cleanup faults | `test_cleanup_failures.py` injects lost write/create responses, read-back errors, exhausted budgets, failed DELETEs and partial parent-chain failures. Updates restore in `finally`, child cleanup survives read-back errors, and failed cleanup cannot erase a finding. Cleanup attempts remain budget-counted; `cleanup_failed` events report failures or unknown target state using route templates, with no response/credential data. Cleanup cannot be guaranteed if the budget is spent or a create response loses its resource identifier. |
| Migration schema | The ordinary database fixture now builds through `alembic upgrade head`. `test_migrations.py` runs `alembic check` against that schema and upgrades seeded revision-0001 rows inside a rolled-back transaction, checking retained data and new defaults. |
| Real worker | `integration_tests/` runs a separate Celery process, real Redis and a separate migration-built test database. It asserts flag serialization, persisted findings/history, cancellation from another session, and duplicate deliveries. An atomic queued-row claim prevents overlapping runs and completed duplicate deliveries. Target transport and AI remain controlled test doubles. Crash recovery and stale deliveries after a later requeue are not covered by this claim. |
| Browser workflows | Pinned Playwright + Chromium tests cover the wizard, credentials, all flags, authorization reset, progress, cancel, JSON export and API-error recovery. A production UI build uses a dedicated port/output directory; API responses are mocked and external traffic blocked. |

CI runs the ordinary API suite, separate worker suite and browser suite. Local
commands and fixture boundaries are documented in
[`integration_tests/README.md`](../../services/api/integration_tests/README.md) and
[`e2e/README.md`](../../apps/web/e2e/README.md). These additions do not replace H1's
coverage measurements, mutation scoring, or API-contract work.

Local validation: 778 ordinary API tests passed with zero skips, 3 real-worker
tests passed, and 4 Chromium workflow tests passed. API lint/type checks,
frontend lint/type checks, and the production UI build also passed. CI is wired
for these checks; a hosted CI run has not been performed from this workspace.

### H1. Measure effectiveness and verify contracts — implemented, hosted CI pending

All six workstreams are implemented. The [baseline report](../test-effectiveness-baseline.md)
records 850 passing tests with zero skips, 90.19% line / 77.82% branch coverage,
and 665 killed / 217 surviving mutants (zero timeouts/errors). CI runs the
coverage/property/contract gates on normal changes and mutation reporting weekly
or manually. The first hosted run remains pending. No mutation-score threshold
is imposed before the surviving mutants are classified.
The 3 real-worker tests, 4 Chromium workflows, lint/type checks and production
web build also pass locally.

| Item | Implementation | Status |
| --- | --- | --- |
| **Coverage baseline** | Complete DB-backed line/branch reports; 89% line / 76% branch floors; JUnit skip/error/failure gate with broken-report regressions. | **implemented** |
| **Targeted mutation testing** | Pinned mutmut over `header_policy`, `exposure_policy`, `fingerprint` and `spec_values`; separate outcome counts, raw results and initial survivor triage. Weekly/manual CI report; no score threshold yet. | **implemented** |
| **Generated policy properties** | `test_policy_properties.py`: bounded deterministic Hypothesis examples for normalization, nested/malformed data, field limits, value independence and mutation permissions. | **implemented** |
| **Fingerprint stability** | `test_char_fingerprint.py`: generated rotating payload/status/count/id properties for every existing sample, identity distinctions, empty inputs and malformed Unicode. All existing hash goldens unchanged. | **implemented** |
| **API response conformance** | `test_api_contract.py`: authenticated seeded lifecycle plus generated valid/invalid requests; Schemathesis validates real FastAPI responses through TestClient. Dispatch/AI stubbed and target traffic blocked. Broken responses prove the gate fails. | **implemented** |
| **Frontend contract compatibility** | Generated current OpenAPI types compared exactly with 17 handwritten response types, 19 response-to-route bindings and 10 request shapes bound to routes, including optionality, nullability and enums. Six deliberately mismatched compile fixtures prove drift detection. | **implemented** |

Self-contract fuzzing runs only against the in-process app or an isolated local
test stack with the dedicated test database. Stub Celery dispatch, scheduler,
AI and external tools; prevent outbound target traffic even if a generated
request includes `authorized:true`. Test the real scan lifecycle separately
against the existing controlled vulnerable app. No generated request may start
a real target scan or spend tokens.

Mutation testing measures sensitivity to the selected mutations, not correctness
of the entire engine. Begin with a CI report on a measured cadence; introduce a
blocking mutation-score threshold only after classifying exclusions and costs.
Coverage and fast property/contract checks belong in normal pull-request CI.

## Suggested sequence

1. **Repair the harness — done:** H0 database protection, real cancellation-path
   tests, required-DB CI behavior, integration isolation and complete target resets.
2. **Establish measurement — implemented, CI verification pending:** H1 coverage
   floors, targeted mutation report, policy/fingerprint properties and contracts.
3. **Improve existing fuzzing — done:** G1 response validation and case allocation.
   Backend-conformance and frontend-contract gates are already in H1.
4. **Add offline secret detection — done:** G2, with false-positive and no-egress tests.
5. **Extend deterministic governance — done:** G3 over the full safe spec.
6. **Benchmark deeper TLS — done:** G4 did not justify SSLyze adoption.
7. **Expand targeted JWT and GraphQL behavior — done:** G5/G6 stay within defined
   evidence and workload limits. Overload testing and extra general scanners remain deferred.

## Shared integration requirements

- **Authorization and mutation:** preserve the API `authorized:true` gate and
  UI confirmation. State-changing probes remain behind `mutate:true`, with
  existing restoration/cleanup guarantees and no new destructive attack verbs.
- **Budgets and cancellation:** new HTTP checks use `HttpProbe`, handle `None`
  and share its request/rate limits. Evidence-only rules make no requests.
  Adjuncts need explicit workload limits and an enforceable execution deadline,
  capped by the remaining shared phase budget. Checking time only between passes
  cannot enforce this; running work must cooperate or run in a terminable process.
- **Target boundaries:** preserve `target_guard` policy for new transports,
  redirects and auxiliary fetches. Do not let library handling of spec `servers`,
  external `$ref`s or generated links select unapproved destinations or forward
  credentials to another origin. Use the existing safe spec-loading path.
- **Evidence and graceful failure:** retain engine findings if an optional tool
  is missing, times out or fails. Emit bounded, secret-safe skip/error diagnostics
  for enabled work that cannot run, distinguishing unavailable coverage from a
  clean result. Persist only sanitized, structured evidence; no raw body samples,
  matched secrets, credential-bearing reproduction commands or library dumps.
- **Flags and mirrors:** reuse `fuzz`, `premium` and other existing gates where
  their semantics fit. Add a new default-off `RunOptions` field only for a
  distinct user-controlled pass. Carry new flags through API, named Celery dict,
  runner, typed client and `RunPanel`. Update `coverage.ts` for changed signals
  and new registered checks; update `Flow.tsx` if the lifecycle/evidence story
  changes. CI-only tools do not need product flags or check catalogue entries.
- **Layering:** `app/domain` remains independent of engine/framework/persistence
  modules. Pure engine policy may use domain vocabulary and suitable pure engine
  types, but must not pull in the ORM. Add new pure modules to `test_layering.py`;
  its current subprocess test blocks SQLAlchemy, not all engine or FastAPI imports.

## Definition of done

For each detection item, demonstrate additional useful signals with positive
and negative fixtures, state the evidence tier and limits, and measure its request
and runtime cost. Pin any new direct dependencies in the appropriate production
or development manifest and verify compatibility with the deployed runtime.

Each new finding needs catalogue-backed remediation, appropriate confidence and
stable identity. Extend per-check identity keys where necessary without changing
unrelated hashes. Verify deduplication with overlapping existing checks, safe
report rendering, and exclusion of sensitive values from persistence and logs.
Exercise the applicable budget, cancellation, mutation, target restriction and
failure paths. Add flags and UI controls only when required by the integration
decision above, and update coverage descriptions to match demonstrated behavior.

H0 is complete only when all five regression criteria pass, including tests of
production cancellation behavior and rejection before destructive database work.
For H1, completion means the check/report runs in CI with documented
scope, runtime, exclusions and any justified threshold. A deliberately broken
fixture or mutation must demonstrate that each new gate can detect its intended
regression. A locally runnable command alone is insufficient.

Run the checks appropriate to implementation changes: API `pytest`, `ruff` and
`mypy`; web lint, `tsc --noEmit` and build when web code or contracts change.
Report DB skips explicitly. Documentation-only updates require link/content and
diff checks, not a production build or active scan.
