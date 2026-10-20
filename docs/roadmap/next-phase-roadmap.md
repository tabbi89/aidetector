# Next-phase roadmap

Where aidetector goes after the hardening pass in
[scanner-hardening-roadmap.md](scanner-hardening-roadmap.md). That document was
about making the scanner's claims true — oracles that prove what they assert, a
tool with its own security posture, an engine that runs deep enough to matter.
This one is about making those true claims **change the application under test**.

A finding that nobody fixes is a finding that did no work, and a scan you have
to re-triage every run is one nobody keeps running.

All four items of the arc are in. The confidence tier that was the product's
best idea and lived only in prose — in `..`, in `apps/web/lib/coverage.ts`, in
the check docstrings — is now a column every check sets and every consumer reads.
Findings no longer stop at the problem: each one carries the change to make,
named against the endpoint it was found on. `data_exposure` is the first new
check built on both: it grades its two signals into different tiers and costs no
requests, by reading a sweep the engine had already paid for. And the fourth
gives a finding an identity that outlives its row, which is what turns a report
into a regression tool — triage carries forward, and a run answers "what
changed" rather than "what is wrong".

What remains is in the change sets below: more detection, deeper authentication,
and the inputs that let the scanner point at an API with no OpenAPI spec. The
library-driven expansion that comes after this arc — property-based fuzzing,
richer TLS, secret-value detection, and a self-testing pass that proves the
engine's own tests have teeth — lives in
[tooling-expansion-roadmap.md](tooling-expansion-roadmap.md).

Status legend: **done** (implemented + tested) · **partial** · **planned**.

## The arc

Four items in sequence, each one making the next possible — all landed:

```
confidence tier → remediation → data exposure → run diffing
 (a column)       (a fix)       (a new check)    (regression)
```

1. **Confidence becomes data.** *(done)* Every downstream consumer — the report,
   the exports, the findings list — needs to distinguish a reflection lead from
   a verified cross-identity write. Nothing else on this list is honest without
   it.
2. **Findings carry remediation.** *(done, including the AI upgrade)* The
   output stops being "here is what is broken" and becomes "here is what to
   change".
3. **Excessive data exposure (API3).** *(done)* The check only a spec-driven
   scanner can do well, built on responses the engine already collects.
4. **Run-to-run diffing.** *(done)* New / fixed / persisting, with human triage
   that survives a re-run.

## Change set D — findings that lead to fixes

| Item | Detail | Status |
| --- | --- | --- |
| **Confidence tier as a column** | `Finding.confidence` (`heuristic` \| `verified`, migration `0011`), set by each check at construction and defaulting to `heuristic` so an ungraded finding never reads as proof. SARIF `level` is derived from severity **and** confidence (only verified evidence reaches `error`); `sort_findings` puts proof above leads within a severity; the findings list gains a badge and a *verified only* filter; the adjudication payload carries it. The vocabulary matches `coverage.ts`, and `test_coverage_mirror.py` fails if `api.ts` and the enum drift. | **done** |
| **Remediation + references** | `Finding.remediation` and `Finding.references` (migration `0012`), filled centrally in `append_finding` from one per-check catalogue (`app/engine/remediation.py`) whose templates are shaped by the finding's own evidence — "Authorize the *object* … in the handler for `GET /accounts/7`", not "implement object-level authorization". A check may override (ZAP and nuclei ship alert-specific text). Rendered in the findings list, `report.html`, the PDF, and SARIF — `help.markdown` per rule, `Fix:` plus a `remediation` property per result. The catalogue also feeds SARIF's CWE and rule summaries, so rule and finding can never disagree. | **done** |
| **AI remediation upgrade** | Done. On a `confirmed` verdict the adjudicator may return a `remediation` shaped to that finding's evidence, which overrides the static catalogue line (never on a dismissal, never blanks a real fix). Cached on `AdjudicationCache.remediation` (migration `0015`) so a re-scan reuses it token-free; the static text stands whenever the model returns none. The adjudication payload now carries the existing remediation so the model improves on it rather than restating it. | **done** |

## Change set E — new detection

| Check | Signal | Tier | Status |
| --- | --- | --- | --- |
| **Excessive data exposure** (API3, `data_exposure`) | Two signals over each 2xx JSON response. Sensitive field *names* — five families (credential material, session/bearer tokens, payment data, government identifiers, internal state), matched on a normalised name so `password_hash` and `passwordHash` are one rule, with an allow-list for benign lookalikes (`has_password`, `card_last4`). And fields the declared 2xx schema does not mention, via `parser.declared_response_fields` ($ref/allOf/oneOf/anyOf resolved, array responses unwrapped). Scoring is pure in `engine/exposure_policy.py`. Costs **zero extra requests**: `HeaderSnapshot` now carries a truncated body, so the check reads the sweep the header checks already fired. **Only field names are ever recorded — never a value.** | verified (sensitive names) · heuristic (drift) | **done** |
| **Mass assignment** (API6, `mass_assignment`) | The write oracle's read-back asking a different question: not "did the wrong *identity's* write persist" but "did the wrong *field's*". Reads the object, picks a field already on it whose name means server-owned state — privilege (critical), ownership or state (high) — that the write operation's request schema does **not** declare, writes a canary, and confirms the read-back equals it. **A canary, never a real privileged value**: `role=admin` would escalate on a live system, and proving the field is client-writable is the finding. Hence string-valued fields only, already present on the object, so the original is known and restored. Same `mutate: true` gate. Now probes **create** pairs too: with no object to read first it injects an undeclared server-owned name from a curated shortlist at creation and confirms by reading the created object back, DELETE-cleaning what it makes — building on the same seeding sequence as `seeded_bola`. | verified | **done** |
| **Race conditions / limit overrun** (`race_condition`) | Done. The one check that fires a concurrent burst bypassing the per-host limiter (`HttpProbe.burst` → the async bridge's un-rate-limited `gather`) — a serialized burst could never catch a race. Proves a uniqueness constraint holds sequentially, then fires `settings.race_burst` (default 6) identical creates at once; >1 success is a verified TOCTOU. `mutate:true`-only, budget-counted, no-ops unless the transport can burst, only fires where a sequential duplicate was refused first, and DELETE-cleans what it creates. | verified | **done** |
| **Scan what discovery found** (API9) | Done. `app/engine/discovery_probe.py` rebuilds `TargetOperation`s from the `kali_discovery`/`kali_crawl`/`kali_params` findings and runs a reduced core check set against them in a **second pass on its own budget** (`discovery_probe_budget`, default 150, independent of the main 500), gated on `kali`. Never mutates — shadow paths have no restore pairing — so the write/fuzz checks are excluded; findings carry no `operation_id`. A discovered URL is reduced to its path first, so a finding can never redirect the probe to another host. | verified/heuristic (per check) | **done** |
| **JWT depth** | The blind, no-new-infra half is **done**: `jwt_forge.py` adds `alg_none_case` (the capitalised `None` that slips a literal-`"none"` string block) and `kid_empty_key` (only when the token carries a `kid` — point it at an empty-key file via traversal and sign HS256 with `b""`, a genuinely valid signature the server reproduces if it loads the key from a kid-named path). **The rest is out of scope for a blind tier, not merely unbuilt**, and the plan was over-optimistic here: RS256→HS256 key confusion needs the server's public key (a JWKS fetch — new egress, subject to the SSRF guard) and `jku`/`x5u` injection is only confirmable via an OAST callback, so both belong with the OOB tier; audience/issuer confusion and expiry acceptance are not forgeable blind at all, because changing those claims breaks the signature and a server ignoring the broken signature is already caught by `sig_tampered`. | verified | **partial** |

## Change set F — workflow

| Item | Detail | Status |
| --- | --- | --- |
| **Stable finding fingerprint** | `Finding.fingerprint` (migration `0013`), stamped in `append_finding` from `app/engine/fingerprint.py`: an ordered set of evidence keys naming *what and where*, never counts, statuses, harvested ids or rotating payloads. Per-check overrides where "endpoint + parameter" is the wrong identity — the header sweep is identified by *which headers* (it already emits one finding per issue profile, so the endpoint list would only churn when scope changes), and a reflection lead drops the payload family (which payload carried the marker is a property of the run). The injection and authz checks now record `route` beside the probed `path`, since the probed URL carries the payload or a harvested id. | **done** |
| **Human triage survives a re-run** | `Scan.triage` maps fingerprint → verdict, written by the triage endpoint and re-applied by `run_record.apply_triage` after the run records its findings — *after* AI adjudication, so a human's judgement outranks the model's. The runner re-reads it from the DB like `cancel_requested`, since it is written by the API session while a run may be queued. A verdict remembered for a fingerprint this run did not produce is kept, not dropped. | **done** |
| **Run diffing** | `GET /scans/{id}/diff` (optional `from_run`/`to_run`, defaulting to the two most recent) over the archived snapshots, matched by fingerprint: added / resolved / unchanged, ordered like every other list. Rows predating fingerprints are counted as `unmatchable` rather than reported as new. 409 when a scan has fewer than two runs. Rendered as a *Since run N* panel on the scan page. | **done** |
| **Auth flows, not static tokens** | Done. A credential carries a `grant_type` (migration `0014`): `static` (today's behaviour), OAuth `client_credentials` / `password`, or a `cookie` login. `ResolvedCredential.mint` calls the target's auth endpoint once at scan start and rewrites the credential's token/auth in place, so a scheduled scan never carries an expired token. Minting never raises — a failed grant scans that identity unauthenticated with an `auth_grant_failed` event. The grant's sensitive half stays in the encrypted secret; non-secret params in `grant_params`. API-level like refresh (no web form). | **done** |
| **HAR / Postman import** | Done. `app/specs/importers.py` converts a HAR capture or a Postman collection into a synthesised OpenAPI dict — id-looking path segments templated to `{id}`, query/body kept as shape (values dropped), and HAR response bodies inferred into response schemas so `data_exposure` drift works on imported APIs. `load_source` sniffs the upload, so the existing `/spec` endpoint accepts all three formats and the stored `spec_text` is always OpenAPI. | **done** |

## Carried over from the hardening roadmap

Both items carried over here have now landed (and the hardening roadmap's own
last item, bounded remote `$ref` resolution, with them):

- **RESTler-style stateful sequences** — producer→consumer ordering, so authz is
  tested as a real create-as-A → read-as-B sequence. *(done)* Single-hop landed
  as `seeded_bola`; multi-hop landed as `engine/sequence.py`, which seeds a nested
  resource's parent chain before the create — create-parent → create-child →
  read — chaining each producer's returned id into the next parent path and
  tearing the chain down child-first. All three write-side create probes —
  `seeded_bola`, the write oracle and mass-assignment — consume it through one
  shared `open_create_chain` / `run_cleanups` helper, so each reaches nested
  cross-tenant objects (`POST /projects/{id}/items`). Mutation-gated, and the
  whole chain is cleaned up.
- **Drop `bypassPermissions`** on the AI worker. *(done)* `plan_agent.py` now
  passes a `can_use_tool` callback that approves only the DeepSeek `triage` MCP
  tool and denies everything else, so the blanket `permission_mode=
  "bypassPermissions"` is gone. The SDK routes the decision over its control
  protocol, so it stays headless and deterministic — and it turned out not to
  need the non-root prerequisite: dropping the bypass also let `planner.py` drop
  `--dangerously-skip-permissions` and its root-only `IS_SANDBOX=1` workaround,
  so the agent's permission posture no longer depends on the worker's uid.

## Premium tier (Lever 4)

Net-new detection depth and AI features reserved for a paid tier. These are the
capabilities the free engine deliberately does not claim — each needs
infrastructure, heavy payloads, or a new protocol surface the blind,
single-process engine avoids. All are **done** behind `premium: true`; the two
protocol surfaces (GraphQL, gRPC) ship their detection slices (introspection /
reflection) with the deeper schema/RPC scanning as future work. The detection
features are labelled **Premium** in `../../apps/web/lib/coverage.ts`.

### New protocol surfaces

| Feature | Detail | Needs | Status |
| --- | --- | --- | --- |
| **GraphQL scanning** | Introspection detection is done (`graphql_introspection`); running the engine's authorization and injection checks against resolved queries/mutations/fields remains (needs a schema source + query-shaping layer). | `engine/checks/graphql_introspection.py` for the introspection slice | **premium, partial** |
| **gRPC / protobuf scanning** | Reflection detection is done (`grpc_reflection`, over gRPC-Web); exercising the resolved protobuf RPCs with schema-valid payloads remains (needs an HTTP/2 + protobuf transport). | `engine/checks/grpc_reflection.py` for the reflection slice | **premium, partial** |

### Deeper attack-technique scanners (confirmation tier)

| Feature | Detail | Needs | Status |
| --- | --- | --- | --- |
| **JWT key confusion & header injection** | RS256→HS256 (fetch the server's public key over JWKS, re-sign as HS256 with it) and `jku` header injection (point the token at an attacker-controlled key set, confirmed by OAST callback). The blind forgery suite in `engine/jwt_forge.py` stays free. | `engine/checks/jwt_confusion.py`; a JWT-bearing credential + (`premium:true`; `jku` also needs OAST) | **premium, done** |
| **Insecure deserialization** | Injects gadget payloads (Python pickle, PHP unserialize, plus Java/.NET markers) into body fields, confirmed by an OAST callback that proves the chain fired. | `engine/checks/deserialization.py`; a live OAST server + `mutate:true` + `premium:true`. The Java/.NET entries are markers to be replaced with a curated corpus | **premium, done** |
| **XXE confirmation (out-of-band)** | Injects three out-of-band XXE variants (external entity, parameter entity, blind file exfiltration) into XML-facing body fields, confirmed by callback — completing the free check's single basic external-entity variant. | `engine/checks/xxe_confirmation.py`; a live OAST server + `mutate:true` + `premium:true` | **premium, done** |
| **HTTP request smuggling / desync** | CL.TE / TE.CL probes over a raw socket; a confirmed desync (two responses on one connection) is the foundation for request queue poisoning and web-cache deception. | `engine/checks/request_smuggling.py`, gated on the `premium: true` run flag | **premium, done** |
| **Host header / vhost injection** | Sends a spoofed-host canary in the forwarded-host headers and flags when it is reflected in the body or `Location` — the prerequisite for password-reset poisoning and web-cache poisoning. | `engine/checks/host_header.py`, gated on the `premium: true` run flag | **premium, done** |
| **Advanced rate-limit (sustained load)** | Sends a sustained 24-request sequence to authentication-shaped endpoints and flags when all of it is served without a throttle — catching limits that only engage past the free 6-request burst. | `engine/checks/advanced_rate_limit.py`, gated on the `premium: true` run flag | **premium, done** |

### AI-powered premium features

| Feature | Detail | Needs | Status |
| --- | --- | --- | --- |
| **Pentest-grade report** | A fifth export beside PDF/HTML/SARIF/JSON: an executive summary, rules-based attacker-path narrative, and evidence-per-finding. Deterministic (no AI), so it cannot invent findings. | `app/scans/pentest.py` + `GET /scans/{id}/report.pentest` | **premium, done** |
| **AI triage of all findings** | Widen adjudication from `HYBRID_CHECKS` (`bola`/`bfla`/`ssrf`/`reflected_injection`) to every check, so each finding gets a verdict + rationale. | `adjudicate_findings(..., premium=ctx.premium)` reviews all findings when the run opts in; more tokens (metered) | **premium, done** |
| **"Ask your scan" assistant** | Natural-language Q&A over a scan's findings, evidence and remediation. | `POST /scans/{id}/ask` + a `qa` mode in `ai_runtime/plan_agent.py` | **premium, done** |
| **Spec design review (A06 Insecure Design)** | A static premium check that reads the OpenAPI spec's operations, schemas and auth scope (no secrets, no values) and emits *design-level* risks a black-box scan cannot see — sensitive endpoints with no declared auth, secrets in query/path params, and server-owned fields in request schemas. It is a static review of the design artifact, not behavioral detection, so its findings are heuristic and it cannot see design flaws invisible in the spec. | `engine/checks/design_review.py`, gated on the `premium: true` run flag | **premium, done** |

The coverage page carries the same premium label for the *detection* features
in the "Premium — advanced detection" group; the AI features (pentest report,
wider triage, the assistant) are not checks, so their labels live here.
`premium: true` is enforced server-side: the run endpoint and the ask endpoint
refuse (402) a non-premium tenant (config `premium_tenants`).

## Invariants this phase must not break

Everything here lands inside the existing constraints, which are product
requirements and not implementation details:

- The `authorized: true` gate and the UI confirmation stay. No new path runs a
  scan without explicit authorization.
- The 500-request budget stays. `data_exposure` reuses the header sweep
  precisely because a new check must not buy its signal with new traffic; the
  test that pins its request count at zero is the guard.
- A response body is customer data. `data_exposure` reports field *names* and
  never values, the same rule that keeps cookie values out of
  `security_headers`. Any future check that reads bodies inherits it.
- Every state-changing probe stays behind `mutate: true`. Mass assignment and
  the race check write to the target, so they are opt-in and off by default,
  and they restore what they change.
- Every optional tier degrades to a skip event. AI remediation is an
  enhancement to a static template, never a dependency of it.
- The two hand-maintained mirrors — `../../apps/web/lib/coverage.ts` and
  `apps/web/lib/api.ts` — move with the engine. `tests/test_coverage_mirror.py`
  fails in both directions and is the guard.

## Verification

`0011`, `0012` and `0013` apply and reverse cleanly against Postgres. `pytest`
lands 322 passing with no skips, `ruff check .` and `mypy app` (81 files) are
clean, and the web app passes `next lint`, `tsc --noEmit` and `next build`.

The diffing work was also verified **against the running stack** rather than
only the in-process target: eleven scans of `../../services/target` through the real
API and worker. Two identical runs produce `0 new, 0 fixed, 27 still there`; a
finding dismissed through the API comes back dismissed on a new row after a
re-run; and narrowing scope reports exactly the six findings of the excluded
endpoint. That last run is what caught the header-identity bug — the endpoint
list was in the fingerprint, so re-scoping reported the same missing CSP as
fixed *and* new. Nothing in the unit tests would have shown it.

**Newly covered by tests** (`tests/test_confidence.py`): the checks grading
themselves (two-identity BOLA verified, its single-identity sibling probe only a
lead, reflection always a lead), the cautious default on an ungraded
`EngineFinding`, a full registry run producing both tiers, the tier surviving
`append_finding` and the run snapshot, the report ordering (proof above leads
within a severity, severity still outranking confidence), and the SARIF
derivation — only verified evidence reaches `error`, with `note` as the floor.
`tests/test_coverage_mirror.py` gains a guard that `FindingConfidence` in
`api.ts` and the `Confidence` enum name the same tiers.

**Newly covered by tests** (`tests/test_remediation.py`): the catalogue as a
mirror of the check registry — a registered check with no entry, or an entry
naming a check nothing emits, fails in both directions — every entry being
populated, evidence interpolation (including missing keys degrading to prose and
non-scalar evidence being ignored), an unknown check getting no advice rather
than the wrong advice, a check overriding the catalogue with tool-supplied text,
an end-to-end registry run leaving no finding without a fix, the SARIF rule help
and per-result remediation, and escaping — remediation carries target-controlled
paths into a reportlab paragraph and an HTML report, so both are escaped and a
`<` in a URL can no longer abort an export.

**Newly covered by tests** (`tests/test_engine_exposure.py`): the pure policy —
the bounded field walk (depth, array width, path recording), naming style not
changing a verdict, the five families and their ranking, benign lookalikes
staying silent, and **values never reaching an issue**; and the check — the
leaky endpoint graded verified, no response *value* appearing anywhere in a
finding, nested fields being reached, a clean endpoint producing nothing, spec
drift graded heuristic, no-spec meaning no drift finding, non-JSON responses
skipped, grouping collapsing endpoints that share an issue, evidence naming both
the route and the probed URL, and the request count staying at zero beyond the
shared sweep. `tests/vulnapp.py` gains `GET /users/{user_id}`, a handler that
serialises the whole record — the shape "return the ORM object" produces.

**Newly covered by tests** (`tests/test_run_diff.py`): identity stability under
drifting status codes, samples, counts and rotating payloads; different
endpoints and parameters separating; the reflection family collapsing while the
OOB and signature families stay distinct; the attacked URL being ignored once a
route is known; header findings identified by headers alone; the title fallback
for checks with no identity-bearing evidence; two engine runs at different seeds
producing identical fingerprints; triage remembered, re-applied, cleared, and
kept when a run does not reproduce the finding; the diff's three buckets, its
ordering, and unfingerprinted rows counted rather than called new; and the
endpoint's defaults, its 409 with fewer than two runs, its 404 on an unknown run
number, and a dismissal surviving a re-run end to end.

**A note for the next change to identity.** The inputs to a fingerprint are a
compatibility surface: changing them invalidates every stored one, so carried
triage stops matching and the next diff reports the affected set as
fixed-and-new, once. It is recoverable and the run after settles, but prefer a
per-check override in `IDENTITY_KEYS` to widening `DEFAULT_KEYS`.

## Change set K — closing the OWASP labelling gaps

Three OWASP API families currently wear a label that a check does not truly
earn. This change set builds the missing detection so the label is honest.

| Gap today | What the label actually covers now | New check | Tier |
| --- | --- | --- | --- |
| **API6 — Unrestricted Access to Sensitive Business Flows** | `seeded_bola`, `mass_assignment`, `race_condition` carry `API6:2023` but are really BOLA / BOPLA / TOCTOU. Business-flow *abuse* — driving a checkout/purchase/redeem/invite flow at machine speed with no anti-automation — is untested. | **`business_flow`** | heuristic |
| **API10 — Unsafe Consumption of APIs** | `deserialization` carries `API10:2023` but is an injection class. Trusting/relaying an unvalidated downstream response is untested (overlaps `ssrf`, which asks the *reachability* question, not the *trust* question). | **`unsafe_consumption`** | verified (OOB) |
| **API4 — Unrestricted Resource Consumption** | `enumeration` (6-request burst) and premium `advanced_rate_limit` (24-request burst) only test *request-rate* limits. A single client-controlled request that forces an unbounded response — `?limit=100000` on a collection — is untested (`NOT_COVERED` says so). | **`resource_consumption`** | heuristic |

### `resource_consumption` (API4) — unbounded page size

A collection endpoint that honours a client-controlled page-size parameter
without an effective cap lets one request extract the whole table and force
unbounded serialisation cost — the amplification half of API4, orthogonal to
rate limiting. Spec-driven: only endpoints that *declare* a size/limit-shaped
query parameter are probed, so the signal is grounded in the API's own
contract, not guessed. Two probes at two above-normal sizes (1000, 5000): if the
returned record count **tracks** the requested size (grows across the two) and
is large in absolute terms, there is no effective cap. A server capped at 100
returns 100 for both and stays quiet — that comparison is what separates a
capped list from an unbounded one with no false positive on correct behaviour.
Read-only (GET), so no `mutate` gate; heuristic, because response volume infers
consumption rather than measuring server cost. Bounded to a few endpoints, two
requests each, inside the 500 budget.

### `business_flow` (API6) — anti-automation on sensitive flows

Sensitive-flow endpoints (checkout, purchase, order, redeem, coupon, invite,
subscribe, booking, transfer, …) that can be driven repeatedly at machine speed
with no throttle and no anti-automation control (CAPTCHA / challenge /
idempotency requirement) are exposed to the abuse API6 names — inventory
hoarding, coupon farming, referral fraud. Distinct from `enumeration`'s
rate probe by endpoint class (business flows, not auth endpoints), by requiring
`mutate: true` (it drives a real write flow), and by also inspecting responses
for anti-automation signals, not only a 429. Identical-body burst so a
correctly de-duplicating flow is not mistaken for an unprotected one. Heuristic.

### `unsafe_consumption` (API10) — trusting a downstream response

The honest black-box slice needs a controllable upstream, so this is the
OAST-confirmed, premium tier — the same shape as `xxe_confirmation` and
`deserialization`. A URL-shaped parameter is pointed at the OAST collector (GET
query always; JSON body fields under `mutate: true`); a callback proves the
target fetched the downstream (that much is SSRF, already `oob_injection`'s
job), and the API10-specific signal is the collector's **marker content being
reflected back** in the target's own response — the target *consumed and relayed*
downstream data it did not validate. Verified when the reflected marker returns;
no-ops without a live collector, so it never touches the free tier or the
precision gate.

### Invariants (unchanged)

All three land inside the existing constraints: the 500-request budget (each is
bounded to a few endpoints), the `mutate: true` gate for the two that write, the
premium gate and OOB no-op-without-collector pattern for `unsafe_consumption`,
graceful-skip for every optional path, and the two hand-maintained mirrors
(`apps/web/lib/coverage.ts`, `apps/web/lib/api.ts`) moving with the engine under
`tests/test_coverage_mirror.py`. Each new check adds a `remediation` catalogue
entry, a `PROOF` row, a coverage entry, a `vulnapp` route it fires on and a
hardened `safeapp` route it stays quiet against.
