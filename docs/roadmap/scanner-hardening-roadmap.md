# Scanner hardening roadmap

A senior offensive-security review of aidetector and the sequenced plan that came
out of it. The tiered-confidence framing (reflection leads → OOB confirmations →
verified authz-on-write) is the product's best asset; this document records where
the marquee checks and the tool's own posture fell short of that bar, and tracks
the work to close the gap.

A visual version of this roadmap — with before/after oracle diffs — lives at
[scanner-hardening-roadmap.html](scanner-hardening-roadmap.html).

Status legend: **done** (implemented + tested) · **partial** · **planned**.

## The three findings that drove the plan

1. **Oracles didn't prove what they claimed.** BOLA compared two *authorized*
   identities on a fixed `id=1` and flagged byte-identical bodies; broken-auth
   flagged any `< 400` for a garbage token without checking that auth was
   required. Both fired on healthy endpoints → false positives, and neither
   tested a *foreign* object/real forgery → false negatives.
2. **The tool had no security of its own.** No API authentication and an
   unvalidated `target_base_url` made a hosted deployment an SSRF/attack pivot.
   The `authorized: true` flag is user consent, not access control.
3. **The engine runs shallow.** Sequential sync requests and one flat 500-request
   cap spread across ops × checks × payloads give a large spec only a few
   requests per endpoint.

## Change set A — detection accuracy

Each flagship oracle was rebuilt around an explicit **authorization baseline**,
modelled on the one check that was already sound (`write_oracle.py`, which proves
a write persisted across identities with a read-back).

| Check | Before | After | Status |
| --- | --- | --- | --- |
| **BOLA** (API1, `authz.py`) | Fixed `id=1`, two authorized identities, byte-equality. | Baseline-gated (anon must be rejected) + static-content guard (a different id must return a different body) before flagging identical cross-identity bodies. | **done** |
| **Broken auth** (API2, `auth.py` + `jwt_forge.py`) | Garbage non-Bearer token, flag any `< 400`. | Confirm anon is rejected, then a JWT forgery suite (`alg=none`, stripped/tampered signature, elevated claims) via **PyJWT**; the accepted forgery names the bypass class. | **done** |
| **BFLA** (API5, `authz.py`) | `"/admin"` substring, flag any `< 400`. | "Privileged" derived from path *or* security scope; confirms the low-priv identity reaches the same function a privileged identity does. | **done** |
| Cross-tenant object seeding for BOLA | — | Seed an object as identity A, read it as B, to prove a true cross-tenant read rather than inferring from a shared response. `seeded_bola` (`engine/checks/seeded_bola.py`) does exactly this: create as A with a unique canary, read that object back as B; the canary returning is a *verified* cross-tenant read. Mutation-gated (`mutate:true`), cleans up the object it creates. | **done** |

## Change set B — the tool's own posture

| Control | Detail | Status |
| --- | --- | --- |
| **SSRF egress guard** (`core/target_guard.py`) | Enforced at `POST /run`. Non-http(s) schemes are always blocked. Without an allowlist, cloud-metadata (`169.254.0.0/16`, `metadata.*`) is blocked and private ranges are blocked when `target_allow_private=false`. A configured host allowlist is authoritative and explicitly permits matching hosts regardless of address class. | **done** |
| **API authentication** (`core/auth.py`) | Router-level `X-API-Key` / `Authorization: Bearer` gate on every scan route. Disabled when no keys are configured (the local/dev posture). | **done** |
| **Secret/PII redaction** (`core/redact.py`) | Applied centrally in the runner to every finding's description + evidence before it is stored. Masks known credential secrets verbatim, plus JWTs / bearer tokens / emails / opaque blobs by pattern. | **done** |
| **Adjudicator hardening** (`ai_runtime/plan_agent.py`) | System prompt frames all finding evidence as untrusted target-controlled data, never instructions; tool surface stays minimal. | **done** |
| **Multi-tenant scoping + spec-`$ref` allowlist** | API keys map to tenants (`config.api_key_tenants`, constant-time compare); scans carry a `tenant_id` (migration `0010`); a spec-`$ref` allowlist bounds remote references. | **done** |
| Drop `bypassPermissions` fully | Done, and without the non-root prerequisite. `plan_agent.py` now passes a `can_use_tool` callback that approves exactly one tool — the DeepSeek `triage` MCP tool — and denies everything else, replacing the blanket `permission_mode="bypassPermissions"`. The SDK routes the decision over the control protocol (stdio), so it is deterministic and never prompts a headless subprocess. That also removed `--dangerously-skip-permissions` and its root-only `IS_SANDBOX=1` workaround in `planner.py`, so the agent's permission posture no longer depends on the worker's uid. | **done** |

### Deployment note

`target_allow_private` defaults to **true** so the intended local lab
(`../../services/target`, `localhost`) keeps working. A **hosted or multi-tenant**
deployment MUST set `target_allow_private=false` and configure
`target_allowlist`, and MUST set `api_keys`. Never put cloud-metadata names or
addresses in the allowlist; an allowlist entry is an explicit override of address
classification. Non-http(s) schemes remain blocked regardless of these flags.

## Change set C — depth & reliability

| Item | Detail | Status |
| --- | --- | --- |
| **429 backoff** | `HttpProbe.send` honours `Retry-After` and backs off on 429 so a throttling target doesn't poison results. | **done** |
| **SARIF 2.1.0 export** | `GET /scans/{id}/sarif` (`scans/sarif.py`) with CWE + OWASP metadata, for CI security dashboards. | **done** |
| **Spec validation** | `openapi-spec-validator` surfaces non-fatal structural warnings on upload (`parser.spec_warnings`). | **done** |
| **Bounded remote `$ref` resolution** | `app/specs/remote_refs.py`: off unless `spec_ref_allowlist` lists a host, then each remote `$ref` is fetched through the run endpoint's `core/target_guard` (allowlist authoritative, cloud-metadata always refused, private refused unless allowlisted, redirects disabled) with fetch-count/byte/depth caps. A fetched doc's own internal refs self-resolve against that doc (cycle-safe); every failure leaves the ref untouched. Covered by `test_remote_refs.py`. | **done** |
| **Async engine + per-host rate limit** | Production requests now go through `engine/transport.py` (`AsyncHttpClientBridge`): one `httpx.AsyncClient` on a dedicated loop, a per-host `aiolimiter` leaky bucket, concurrent checks (`engine_concurrency`), and per-operation fairness budgets in `HttpProbe`. | **done** |
| **Auth-token refresh** | `ResolvedCredential.refresh` re-mints an expired bearer on a 401 (coalescing concurrent refreshes); refresh URL/secret/fields persisted on the credential (migration `0010`). Covered by `test_probe_collaborators.py`. | **done** |
| **Adjudication verdict cache** | `_adjudicate` fingerprints each HYBRID finding (check + OWASP id + title) and short-circuits any already in `adjudication_cache`, so a re-scan reuses verdicts without re-spending tokens. Covered by `test_cascade.py`. | **done** |
| **Schema-driven fuzzing** | `SchemaFuzzCheck` (opt-in `fuzz:true`): Schemathesis generates boundary/negative inputs; cases run through the engine probe (budget-bounded) and a 5xx is flagged as unhandled input (API8/CWE-20). Covered by `test_schema_fuzz.py`. | **done** |
| **OOB transport (persistent session)** | `InteractshClient` now runs one long-lived `interactsh-client`: a background thread captures the session domain and streams interaction JSON into a buffer `poll()` drains, so callbacks actually correlate. The subprocess is injectable for testing; the runner tears the session down after each scan. Covered by `test_oob.py`. | **done** |
| **RESTler-style stateful sequences** | Producer→consumer ordering so authz is tested as a real create-as-A → read-as-B sequence. Landed as `seeded_bola` (single-hop) and `engine/sequence.py` (multi-hop): a nested create seeds its parent chain first — create-parent → create-child → read — chaining each producer's returned id into the next parent path, and tearing the chain down child-first. Consumed by all three write-side create probes — `seeded_bola`, the write oracle and mass-assignment — through one shared `open_create_chain` / `run_cleanups` helper, so each reaches nested resources. | **done** |

## Libraries adopted

| Library | Used for | Status |
| --- | --- | --- |
| **PyJWT** | Reading presented tokens to build the JWT forgery suite. | **done** |
| **openapi-spec-validator** | Non-fatal structural validation of uploaded specs. | **done** |
| **aiolimiter** | Per-host leaky-bucket rate limiting in `engine/transport.py`. | **done** |
| **Schemathesis** | Boundary/negative input generation, driven through the engine probe by `SchemaFuzzCheck`. | **done** |
| **prance** | Internal `$ref` inlining (`RESOLVE_INTERNAL`, SSRF-safe) plus an `allOf`/`oneOf`/`anyOf` property merge in the parser. | **done** |
| interactsh (persistent client) | Correlating blind-vuln callbacks. | **planned** |

## Verification

The combined working tree lands green: `pytest` (182 passing, including
`tests/test_hardening.py`, `test_tenant_scoping.py`, and `test_oob.py`),
`ruff check`, and `mypy app` (67 files) all pass, and the web app type-checks. The
two hand-maintained mirrors — `../../apps/web/lib/coverage.ts` (engine) and
`apps/web/lib/api.ts` (schemas) — were updated for the strengthened checks and the
new `fuzz` run flag.

**Newly covered by tests:** the adjudication verdict cache (re-scan reuses
verdicts), token refresh (401 → re-mint → retry), the async transport bridge
(in-process ASGI), the `allOf` body-field merge, `SchemaFuzzCheck` (5xx on a
generated boundary input), **tenant isolation** (cross-tenant reads/writes 404),
the **per-operation budget** fairness cap, and the **persistent OOB session**
(streamed callback correlation + graceful degradation).

**All closed.** Remote `$ref` resolution now exists, bounded: off unless
`spec_ref_allowlist` lists a host, and every fetch goes through the run
endpoint's own `core/target_guard` (allowlist authoritative, metadata blocked,
redirects disabled) with fetch-count/byte/depth caps and failure-safe degradation
(`app/specs/remote_refs.py`). `bypassPermissions` on the AI worker is done (a
`can_use_tool` allowlist gate replaced it, which also dropped the root-only
`IS_SANDBOX` workaround). RESTler-style stateful sequences have fully landed
(`engine/sequence.py`, consumed by `seeded_bola`, the write oracle and
mass-assignment create paths for nested resources).
