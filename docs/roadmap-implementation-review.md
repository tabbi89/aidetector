# Roadmap implementation review

Current-state review of the scoped work in roadmap change sets A through G.
This document describes what is implemented, how it is verified and which
boundaries remain intentional. It is not a history of issues found and fixed.

## Overall verdict

The scoped A–G roadmap is **implemented and verified**. The scanner now combines
controlled authorization oracles, guarded execution, bounded active testing,
stable finding identity and expanded API-specific detection. Confidence is
carried as data, so heuristic leads remain distinguishable from behavior that
directly verifies a weakness.

G4 reached a measured non-adoption decision: SSLyze did not add unique confirmed
coverage sufficient to justify its much higher connection volume. G6 excludes
GraphQL mutation replay and overload testing because they cannot meet the same
safe cleanup and traffic bounds as the implemented checks.

## Implementation by change set

| Change set | Implemented result | Verification focus | Status |
| --- | --- | --- | --- |
| **A — detection accuracy** | BOLA, BFLA and broken-auth checks use anonymous, privileged, invalid-token and static-content controls. Seeded BOLA verifies a cross-identity read of an object created during the scan. | Positive and clean authorization fixtures, mutation gating, nested-resource sequencing and cleanup. | **done** |
| **B — scanner security** | Target and credential-auth egress are guarded; API keys map to tenants; secrets are encrypted and centrally redacted; remote references and AI permissions are constrained. | Metadata/private-target rejection, tenant isolation, credential non-disclosure, safe reference resolution and planner permission tests. | **done** |
| **C — depth and reliability** | Async rate-aware transport, shared budgets, 429 backoff, cancellation, OAST correlation, schema fuzzing, stateful sequences, token refresh, SARIF and adjudication caching are in place. | Budget exhaustion, rate behavior, cancellation boundaries, optional-tool degradation, state cleanup and output conformance. | **done** |
| **D — actionable findings** | Confidence, remediation and references flow through persistence, APIs, UI, reports, SARIF and AI adjudication. | Enum/client mirror checks, catalogue completeness, rendering safety, confidence-sensitive sorting and SARIF severity. | **done** |
| **E — detection expansion** | Data exposure, mass assignment, race conditions and discovery-fed shadow-endpoint checks are implemented with evidence-specific confidence. | Zero-request response reuse, canary-only writes, restoration/cleanup, bounded race bursts and isolated discovery budgets. | **done (scoped)** |
| **F — repeatable workflow** | Stable fingerprints support persistent human triage and run diffs; grant-based credentials and HAR/Postman imports feed the normal scan pipeline. | Fingerprint properties and goldens, diff lifecycle, runner mint success/failure, import value dropping and response-schema synthesis. | **done** |
| **G — focused tooling expansion** | Contract-aware fuzz validation, offline secret detection, design-contract rules, measured TLS selection, bounded JWT behavior and GraphQL behavior checks are implemented. | Dedicated boundary, no-egress, non-retention, control-response, fingerprint and clean-fixture tests for every G item. | **done (scoped)** |

## G1–G6 review

### G1 — schema fuzz response validation

- Validates declared response status, content type, required/typed headers and
  body schema in addition to 5xx behavior.
- Reuses one response per generated case and fairly allocates positive and
  negative cases across operations.
- Keeps response-contract drift heuristic while treating an observed 5xx as a
  verified input-handling failure.

### G2 — offline potential-secret detection

- Scans bounded response samples already collected by the header sweep and
  scans uploaded specifications as a separate source.
- Runs the pinned detector in a short-lived, no-egress worker with byte, unit,
  match and time limits.
- Persists only detector type and sanitized structural location; candidate
  values, surrounding text and secret-derived hashes cannot reach findings,
  reports, AI inputs or logs.

### G3 — deterministic design governance

- Flags missing error contracts, undocumented rate-limit contracts and
  unbounded response collections without target traffic or AI tokens.
- Uses bounded local-reference resolution and respects global security,
  operation overrides and explicit anonymous alternatives.
- Reports design-review leads as heuristic findings rather than claiming that a
  runtime control is absent.

### G4 — TLS scanner evaluation

- Benchmarked SSLyze 6.3.1 against testssl.sh 3.2.4 on controlled modern and
  legacy TLS fixtures.
- SSLyze was faster but opened roughly four to five times as many connections,
  added no unique confirmed actionable weakness and disagreed with testssl on
  the legacy ROBOT result.
- SSLyze was not adopted. The retained testssl adapter now uses its documented
  JSON output option and preserves critical-severity entries.

### G5 — bounded JWT behavior

- Tests supplied HS256/384/512 tokens against a fixed, bounded weak-key set and
  a CPU-time limit.
- Uses an in-memory recovered key only to build controlled privilege, expiry and
  future-`nbf` probes with valid signatures.
- Requires successful valid-token and rejected bad-signature controls before a
  time-claim acceptance finding can be verified. Keys and generated tokens are
  never evidence.

### G6 — bounded GraphQL behavior

- Detects shallow anonymous field suggestions as heuristic schema-exposure
  leads.
- Tests one safe read-only query through normal, alias and batch forms, and only
  reports an authorization bypass when owner, anonymous and attacker controls
  demonstrate differential access to equivalent data.
- Caps targets, query size, depth, suggestion requests, aliases, batch size and
  elapsed time. Mutation examples are never replayed.

## Verification baseline

The implementation was last validated as one combined tree with:

- **905 backend tests passing with zero skips** against a dedicated PostgreSQL
  test database (`TEST_REQUIRE_DB=1`).
- **Ruff passing** for application code, tests and benchmark code.
- **mypy passing** across 110 application source files.
- **Frontend lint and production build passing**.
- Contract mirrors covering run options, finding confidence, registered checks,
  remediation entries and frontend API response shapes.
- Characterization and generated-property tests protecting finding identity,
  policy bounds, value independence and mutation permissions.

## Current safety properties

- A scan cannot run without the explicit authorization gate.
- Core requests remain under the shared per-scan budget; discovery uses a
  separate smaller budget and adjuncts share a wall-clock deadline.
- State-changing probes are off by default behind `mutate:true`; supported
  writes restore or delete created state and report cleanup failure.
- The race check alone may bypass rate limiting, only for a small budget-counted
  burst after a sequential constraint control succeeds.
- Credential secrets, detected secret candidates, cookie values and response
  values are excluded from stored evidence.
- Optional AI, OAST and external-tool failures degrade gracefully and do not
  fail the core scan.
- Human triage is reapplied after AI adjudication and therefore remains
  authoritative.

## Intentional boundaries

- Heuristic contract and design findings do not prove exploitable behavior.
- Bounded fuzzing and sampled secret scanning improve coverage but cannot prove
  that an API's full input or response space is clean.
- JWT weak-key testing is intentionally small and does not claim exhaustive key
  recovery or complete JWT security coverage.
- GraphQL mutation replay, broad field traversal and overload testing remain
  deferred until they can be bounded and cleaned up safely.
- SSLyze remains outside the runtime; testssl and the built-in TLS check are the
  retained paths.

## Related documents

- [Canonical A–G roadmap](roadmap-phase.md)
- [Scanner hardening detail — A–C](roadmap/scanner-hardening-roadmap.md)
- [Product and workflow detail — D–F](roadmap/next-phase-roadmap.md)
- [Tooling expansion detail — G](roadmap/tooling-expansion-roadmap.md)
- [TLS scanner benchmark](tls-scanner-benchmark.md)
- [Test-effectiveness baseline](test-effectiveness-baseline.md)
