# Phase K — Passive evidence and security observability

## Status

In progress. This phase extends an active OpenAPI security scan with read-only
evidence from WAF/SIEM logs, application access logs, source code and database
schema metadata.

This is an additional product feature named **Infrastructure Monitoring Scan**.
It is not another active attack scan and it must not be implemented as a
`Check` inside the existing `HttpProbe` pipeline. Its primary input is a daily
snapshot of operational traffic, compared with a rolling baseline of at least
seven completed days.

The active OpenAPI scan remains available for point-in-time behavioral proof.
Infrastructure Monitoring Scan observes what happened in the running system and
raises anomalies when current behavior departs from its established baseline.

### Implemented first slice

The first vertical slice is now present in the API service:

- `app/monitoring/waf.py` normalizes vendor-shaped WAF/access records and drops
  query values, raw identifiers, credentials and raw IPs at the boundary;
- `app/monitoring/detectors.py` aggregates route metrics and emits a heuristic
  enumeration observation only after at least seven non-empty baseline days;
- `InfrastructureMonitor` and `MonitoringRun` persist daily lifecycle state and
  value-free aggregates in migration `0028`;
- `POST /monitoring/{monitor_id}/runs/ingest` is the initial adapter handoff for
  AWS WAF/SIEM/MCP connectors, while `POST /monitoring/{monitor_id}/run` and
  Celery beat create an idempotent daily collection slot;
- `app/ai/provider.py` adds a provider-neutral monitoring explanation seam;
  Cursor is optional, isolated, MCP-only, and cannot create or promote findings.

### Implemented source connector increment

Migration `0029` adds tenant-scoped `EvidenceSource` bindings and the first
`json_snapshot` connector. This is an API-only, offline upload connector; live
AWS retrieval, GitHub/MCP retrieval and the monitoring UI remain pending.

- Create/list sources with `POST/GET /monitoring/sources`. Source names, target
  bindings and connector type are validated; this connector needs no credentials.
- Create a monitor with that source UUID in `source_ids` and the exact same
  `target_binding`. The first connector supports one source per monitor because
  each upload replaces a complete day, not one part of a multi-source aggregate.
- Upload a JSON array to
  `POST /monitoring/{monitor_id}/sources/{source_id}/snapshot?observation_date=YYYY-MM-DD&revision=1`
  with `Content-Type: application/json`. The date must be a completed UTC day.
  The request stream is capped at 2 MiB and 10,000 records; every record must
  normalize successfully and fall within the selected day. Partial batches are
  rejected before persistence. Callers must supply the full day's snapshot.
- Generic access records use ISO timestamps and `uri`/`path`. AWS WAF records
  accept the documented nested `httpRequest`, separate `args`, and millisecond
  timestamps ([AWS field reference](https://docs.aws.amazon.com/waf/latest/developerguide/logging-fields.html)).
  WAF `ALLOW` is not treated as proof of an origin HTTP 200.
- Duplicate request IDs within one snapshot count once. Records without request
  IDs remain separate. Exact replay returns the same daily run; changed content
  rebuilds that day's aggregates. Only a content digest, normalized aggregate
  metrics and observations persist, never the uploaded JSON.
- Empty snapshots report `data_quality: missing` and do not become baseline days.
  Manual and scheduled collection now select the previous complete UTC day.
- `POST /monitoring/sources/{source_id}/revoke` increments the binding revision
  and stops future ingestion. Authorization is checked again after upload and
  locked through persistence, so revocation and ingestion are serialized.
- `DELETE /monitoring/sources/{source_id}` removes that source and its monitors'
  retained daily summaries, then pauses those monitors. Other tenants cannot
  list, bind, ingest, revoke or delete the source. Revocation alone retains prior
  summaries; deletion removes them.
- Source-bound monitors cannot use the legacy unbound `/runs/ingest` handoff.
  Existing monitors without sources retain that initial API for compatibility.

### Implemented setup, AWS credential chain and AI traffic analysis

- `POST /monitoring/setup` creates the contract scan, an `aws_cloudwatch` source
  from a WAF log-group ARN, an optional GitHub source (branch mode) and the
  monitor in one call. A refused setup leaves nothing behind.
- AWS reads sign with the worker's standard credential chain when a source
  stores no keys (a profile mounted by `make up-aws`, or a task, pod or instance
  role). Those credentials belong to the deployment, not to a tenant, so
  `MONITORING_AWS_LOG_GROUPS` (log-group ARNs) is mandatory and authoritative.
- Collection normalizes each `FilterLogEvents` page as it arrives, so a raw
  message never outlives its page. It is bounded by `MONITORING_AWS_MAX_EVENTS`,
  `MONITORING_AWS_MAX_CALLS` and `MONITORING_COLLECT_SECONDS`. Throttling is
  retried, and AWS errors map to fixed codes (`access_denied`,
  `log_group_not_found`, `credential_unavailable`).
- `app/monitoring/bots.py` aggregates AWS WAF Bot Control labels (name,
  organization, category, verification) into `metrics["bots"]`, served by
  `GET /monitoring/{id}/bots`. It raises three heuristic leads:
  `unverified_ai_surge`, `bot_identity_spoof` (a name verified on earlier days
  that is now unverified) and `bot_on_protected_route`.
- `app/monitoring/clients.py` groups each day by the JA4 TLS client fingerprint
  AWS WAF logs (`ja4Fingerprint`) into `metrics["clients"]`, served by
  `GET /monitoring/{id}/clients`. A JA4 follows one tool across the addresses it
  rotates through, which per-IP buckets cannot; it is also shared by every user
  of one browser build, so breadth is judged per request and per address. Three
  heuristic leads, on absolute thresholds that need no baseline:
  `ja4_endpoint_probing` (≥100 distinct path shapes, ≥30% of its requests new,
  ≥25 per address), `ja4_identifier_enumeration` (≥50 identifiers on one route,
  ≥50% consecutive, ≥25 per address) and `ja4_request_manipulation` (≥3 requests
  matching AWS managed payload rules such as SQLi, LFI or PHP; medium when a
  count-mode rule let one reach the origin, low when all were blocked). Traffic
  the operator's own allow rules let through and Bot Control verified bots never
  count toward breadth. The raw JA4 is kept because a WAF rule can match it; it
  names client software, not a user. Path shapes and identifiers are HMACs held
  in memory for counting and never stored.
- One carve-out from that: a `ja4_request_manipulation` observation keeps the
  **paths of the requests that matched**, as sent. A payload-matched path is the
  sender's own string, not a client's data -- the same reasoning that lets a scan's
  request trace retain the body the scanner generated -- and it is the one thing an
  operator needs, because normalization templates exactly the segments a payload
  occupies (`GET /{value}`). Percent-encoding is preserved (it is half of a
  traversal attempt), the query string is dropped because that is where a real
  client's values live, the sample is truncated at `waf.MAX_ATTACK_PATH`, and
  breadth leads (`ja4_endpoint_probing`) collect no paths at all.
- Identifiers now also come from id-shaped query values whose parameter is named
  like a reference (`jid`, `tech_id`, `acct`, …). The parameter name is part of
  the HMAC input and only names are kept, so `/ajax.php?jid=…` style APIs are
  covered by both the bucket and the JA4 enumeration leads.
- AWS WAF logs carry no origin status code, so status-based signals (404 counts)
  stay at zero for this source.
- A day's `degraded` alerts are acknowledged automatically once the day collects.
- Repository context goes through Cursor with GitHub's hosted MCP server in
  read-only mode, not Cursor cloud agents. The SDK's tool allowlist applies only
  to local agents, so a cloud agent with the repository attached could run a
  shell or push. Each monitor supplies its own repository and fine-grained
  token, stored encrypted on its GitHub source and never placed in the prompt;
  that token's read-only repository scope is the boundary, so there is no
  deployment repository allowlist. The read-only header only narrows the tool
  list. (AWS keeps its allowlist: the worker's AWS identity is shared.)
- `POST /monitoring/{id}/runs/{run_id}/observations/{fingerprint}/explain` runs
  the provider in a worker and stores `ai_explanation` beside the observation.
  It never changes type, confidence, disposition or fingerprint, and it survives
  a recomputed day.
- Dev-only examples: `POST /scans/example` and `POST /monitoring/example`, the
  latter with seven ordinary synthetic days and one attack day from
  `app/monitoring/demo.py`.

Known limit: the enumeration detector compares a bucket (method, route, client,
hour) only with that same bucket's history, so a client with no seven-day
history is never flagged. The demo's enumerator is an existing client for that
reason.

Remaining work includes live read-only provider adapters and their credential
vault integration, explicit feed completeness/health signals, route/cohort-aware
baselines, recomputing downstream comparisons after historical revisions, pinned
repository context, and the UI. The snapshot connector does not establish that
an externally supplied day's data is complete; the uploader asserts completeness.


## Goal

Detect security leaks, suspicious behavior and design/runtime mismatches that
cannot be established from an active request/response scan alone.

The first target is actionable detection of enumeration, especially object
enumeration across tenant boundaries. The same evidence plane should later
support account enumeration, sensitive data leakage, shadow endpoints and
authorization design review.

The phase must preserve the product's existing safety properties:

- active checks remain bounded by the existing request budget;
- this phase is read-only and must not mutate the target or production data;
- credentials remain encrypted and are never returned to an AI model;
- raw WAF, source and database values are not copied into findings by default;
- heuristic observations are not presented as verified vulnerabilities;
- every persisted finding has a stable fingerprint and remediation;
- source failures degrade gracefully and never fail an otherwise valid scan.

## Feature boundary: Infrastructure Monitoring Scan

The feature has its own lifecycle and status. A daily run should analyze the
previous complete log day after ingestion is expected to have settled, then
compare it with at least seven prior comparable days.

```text
daily scheduler
      |
      v
fetch previous complete day -> normalize -> aggregate -> compare baseline
      |                                                    |
      +--> warming_up (< 7 days)                           +--> anomaly state
                                                            |
                                                            v
                                           observation -> finding / alert
```

Suggested monitoring states:

- `no_data`: the source is missing, empty or unavailable;
- `warming_up`: fewer than seven complete comparable days are available;
- `baseline_ready`: the minimum baseline exists and comparison is valid;
- `degraded`: data quality, source delay or coverage is insufficient;
- `anomaly`: one or more detector thresholds were crossed.

`warming_up`, `no_data` and `degraded` are coverage states, not clean results.
The UI and API must show them explicitly.

### Daily scheduling

Use a dedicated monitoring schedule rather than the existing active scan
schedule:

```text
frequency: once per day
input window: previous complete UTC day, or tenant-configured timezone day
minimum baseline: 7 complete prior comparable days
comparison: route + method + identity cohort + time bucket
alerting: state changes and sustained anomalies only
```

The first seven daily runs build the baseline. They may emit observations for
data quality, but must not emit anomaly alerts unless the user explicitly asks
for a provisional early-warning mode. A source with gaps must not silently use
partial history as a normal baseline.

Daily runs must be idempotent for `(monitor_id, observation_date,
source_revision)`. Late-arriving log records should trigger a bounded rebuild
of the affected day and a new comparison revision, rather than duplicate
counts.

### Baseline model

Baselines should be route-specific and cohort-aware. A global traffic average
will make normal administrative jobs and batch clients look malicious.

Store bounded aggregates such as:

- request count and distinct pseudonymous principals;
- status-code distribution;
- WAF action distribution;
- distinct identifier count and sequentiality score;
- response-size and latency buckets;
- route-not-found and route-newness rates;
- sensitive query-key counts;
- cross-tenant access indicators when the source provides them.

Start with robust comparisons such as median, percentile and median absolute
deviation over the seven-day window. Add longer-term weighted baselines only
after false positives are measured. Deployments, maintenance windows, known
admin cohorts and scheduled batch jobs should be represented as explicit
annotations or exclusions, not hidden in detector code.

### Monitoring-specific data model

Add a persistent monitoring object above `EvidenceRun`:

```text
InfrastructureMonitor
- id
- tenant_id
- scan_id (nullable)
- target_binding
- schedule: daily
- timezone
- minimum_baseline_days: 7
- source_ids
- status: active | paused | unavailable
- last_observation_date
- created_at / updated_at
```

Extend `EvidenceRun` with:

```text
observation_date
baseline_start / baseline_end
baseline_days_available
baseline_revision
data_quality
monitor_state
```

Keep `SecurityObservation` as the daily, explainable detector result. A
promoted `Finding` should represent the stable issue across days, while its
evidence records the current window, comparison window, count and deviation.
Do not create a new finding every day for the same continuing anomaly.

### AI role in monitoring

The repository already has a partial AI abstraction:

- `Cascade` is an application-level protocol in
  `services/api/app/ai/cascade.py`;
- `AICascade` delegates to `OpusPlanner`;
- `OpusPlanner` invokes the isolated Claude Agent SDK runtime through
  `services/api/ai_runtime/plan_agent.py`;
- DeepSeek is currently called directly through the isolated runtime for
  executor-style phases;
- `Usage` and the token ledger already provide a common accounting seam.

This is not yet a provider-neutral `AIProvider` interface. Cursor should be
added behind a new provider/runtime abstraction, not wired directly into the
monitoring worker.

Suggested interface:

```text
AIProvider
- id: deepseek | claude | cursor
- explain_observation(input) -> structured explanation
- prioritize_observations(input) -> ordered ids
- answer_investigation(input) -> structured answer
- usage / cost metadata
```

The provider interface should receive sanitized observation payloads from the
monitoring service. It should not receive source credentials, raw WAF records,
customer identifiers, request bodies or unrestricted repository access.

### Cursor SDK placement

Cursor SDK is a viable Phase K provider/runtime. The current
[Cursor Python SDK](https://prod.cursor.com/docs/sdk/python) can run an agent
locally or in a Cursor-hosted cloud runtime and can be configured with MCP
servers. Its local-agent `tools` allowlist, `disallowed_tools` deny list and
`setting_sources` controls are the basis for the empty-workspace, MCP-only
runtime used here. For this product, use it only in the isolated AI runtime and
pass it a narrow MCP configuration for the specific monitoring task.

Recommended deployment shape:

```text
Celery monitoring worker
        |
        +--> deterministic baseline + anomaly engine
        |
        +--> provider adapter (optional)
                    |
                    +--> Cursor SDK runtime
                    |       |
                    |       +--> read-only MCP policy gateway
                    |                    |
                    |                    +--> AWS WAF context adapter
                    |                    +--> GitHub pinned-repo adapter
                    |                    +--> DB schema adapter
                    |
                    +--> Claude / DeepSeek adapter
```

Cursor is best used to explain or investigate an already-produced observation,
for example: “Why did `GET /orders/{id}` diverge from its seven-day baseline?”
It should not calculate the baseline, decide whether a threshold was crossed,
or promote a heuristic observation to a verified vulnerability.

The first Cursor provider should expose only these capabilities:

- summarize a sanitized anomaly;
- compare current and baseline aggregate metrics;
- explain route, code and schema context;
- suggest bounded investigation questions;
- produce structured remediation suggestions for human review.

Do not expose Cursor's general coding-agent capabilities to the monitoring
worker. In particular, do not grant shell, arbitrary filesystem, repository
write, WAF-rule write or database-query tools. If the Cursor runtime cannot be
configured to enforce this exact surface, keep Cursor as a human-operated
analyst integration rather than an unattended provider.

GitHub's hosted MCP server is additionally configured with its documented
[`X-MCP-Readonly` and `X-MCP-Toolsets` headers](https://github.com/github/github-mcp-server/blob/main/docs/server-configuration.md).
The monitor-owned fine-grained token remains the repository and permission
boundary; the headers reduce the exposed tool surface.

### Allowed AI actions

AI SDK plus MCP is allowed only as an optional assist lane:

- explain why a deterministic anomaly crossed its threshold;
- prioritize multiple anomalies for an analyst;
- retrieve bounded AWS WAF, GitHub and schema context;
- suggest investigation questions or remediation wording.

AI must not:

- calculate the authoritative baseline;
- decide that an anomaly exists without detector evidence;
- promote heuristic confidence to verified;
- execute arbitrary SQL, shell commands or repository actions;
- change AWS WAF rules, GitHub content, target state or database state.

The monitoring worker should still complete successfully when the AI provider
or an MCP source is unavailable.

## Why this is a separate pipeline

`ScanRun.mutations` describes traffic generated by the scanner. WAF and access
logs describe traffic generated by real clients. They have different lifecycles,
retention requirements, privacy risks and confidence semantics, so WAF events
must not be appended to the active request trace.

The existing active pipeline remains:

```text
OpenAPI -> engine checks -> active findings -> run archive
```

Phase K adds:

```text
WAF / access logs ─┐
source at commit ──┼─> normalized evidence -> passive detectors ─┐
DB schema metadata ─┘                                           ├─> findings
active scan trace ──────────────────────────────────────────────┘
```

The correlation layer may combine evidence, but it must retain the provenance
and confidence of every contributing source.

## Scope and non-goals

### In scope

- WAF/SIEM log snapshots over an explicit time window;
- normalized request metadata and bounded behavioral aggregates;
- enumeration and request-side sensitive-data-leak detectors;
- read-only source-code context at a pinned repository revision;
- read-only database schema metadata;
- OpenAPI-to-code and OpenAPI-to-database consistency checks;
- correlation with active-scan findings and request IDs;
- point-in-time evidence runs and a later watermark-based monitoring mode;
- tenant isolation, redaction, retention and auditability.

### Out of scope for the first release

- arbitrary SQL, shell commands or source-code execution;
- writing to the target, repository, database or WAF;
- storing complete raw WAF logs in the application database;
- claiming a vulnerability from source inspection alone;
- response-body inspection through a WAF that only exposes request metadata;
- replacing a SIEM, WAF or incident-response platform;
- automatic blocking, rule changes or remediation deployment;
- unrestricted AI access to production systems.

## Architecture

### Evidence source configuration

Add a scan- or tenant-scoped `EvidenceSource` configuration. The configuration
contains connector metadata only; secrets are stored through the existing vault.

```text
EvidenceSource
- id
- tenant_id
- scan_id (nullable when shared at tenant level)
- type: waf | access_log | repository | database_schema | openapi
- connector: cloudflare | aws_waf | akamai | splunk | elastic | custom
- config: JSONB, validated per connector
- secret_ref: encrypted nullable reference
- status: untested | ready | unavailable
- revision / source_cursor
- created_at / updated_at
```

The configuration must include a target binding. A source cannot be queried for
an arbitrary host merely because a caller knows its ID.

### Evidence runs

Add an asynchronous `EvidenceRun` rather than overloading `ScanRun`:

```text
EvidenceRun
- id
- scan_id
- run_number
- status: queued | running | completed | failed | cancelled
- requested_sources
- window_start / window_end
- source_revisions
- event_count
- observation_count
- finding_count
- aggregate_bytes
- started_at / finished_at
- error_code (fixed code, not exception text)
```

The API should expose a bounded snapshot operation:

```http
POST /scans/{scan_id}/evidence-runs
Content-Type: application/json

{
  "sources": ["waf-prod", "repo-main", "db-schema"],
  "from": "2026-09-14T00:00:00Z",
  "to": "2026-09-15T00:00:00Z",
  "mode": "snapshot"
}
```

The worker validates the source binding again after claiming the job. Source
configuration changes or revocation during execution must stop further reads.

For continuous monitoring, the same worker uses a source cursor and short
overlapping windows to tolerate delayed log delivery. A cursor must never be
trusted without the source revision and tenant binding that created it.

### Observations are not findings

Most log patterns are signals, not vulnerabilities. Add a bounded
`SecurityObservation` representation before creating a user-facing `Finding`:

```text
SecurityObservation
- id
- evidence_run_id
- detector
- fingerprint
- route_family
- principal_group (one-way pseudonym, never raw identity)
- window_start / window_end
- metrics: JSONB
- confidence: heuristic | verified
- evidence_refs: JSONB
- disposition: candidate | promoted | suppressed | expired
```

Observations may be retained for a shorter period than findings. A finding is
created or updated only after detector thresholds are met. The existing finding
fingerprint, triage and remediation mechanisms remain authoritative.

## Normalized WAF and access-log event

Each connector maps vendor-specific records to a common internal shape. The
normalized form must be designed for analysis, not raw-log archival:

```text
NormalizedRequestEvent
- observed_at
- source_id
- target_binding
- request_id (hashed or opaque, when available)
- method
- route_template (resolved or normalized)
- raw_path_hash
- query_keys (names only)
- path_identifier_features
- status
- response_bytes
- duration_ms_bucket
- waf_action: allow | block | challenge | unknown
- rule_ids (bounded)
- principal_hash (optional)
- source_ip_hash (optional, tenant-salted)
- user_agent_family
- country / ASN (optional, coarse)
- forwarded_identity (optional, hashed)
```

Values must not be retained by default. In particular, do not store:

- authorization headers or cookies;
- access tokens, API keys or session IDs;
- full query strings;
- full paths containing customer identifiers;
- request or response bodies;
- unredacted IP addresses or email addresses.

If a detector requires identifier behavior, retain only derived features such as
`numeric`, `uuid`, `monotonic_candidate`, `bucket`, `distinct_count` and a
short-lived salted hash. The original identifier must not be recoverable from
the feature record.

## MCP boundary

MCP is an adapter and investigation boundary, not an authorization bypass. Use
typed, narrow, read-only tools or resources:

```text
get_openapi_contract(scan_id)

get_code_context(
  source_id,
  commit,
  routes,
  symbols,
  max_files,
  max_bytes
)

get_database_schema(
  source_id,
  allowed_tables,
  max_tables
)

search_waf_events(
  source_id,
  start_time,
  end_time,
  route_family,
  limit
)

aggregate_waf_behavior(
  source_id,
  start_time,
  end_time,
  route_family,
  group_by
)
```

Do not expose tools named `execute_sql`, `run_command`, `checkout_code` or
`fetch_url`. The MCP server must enforce the policy even if the caller is an AI
model.

Required controls:

- tenant and scan binding on every call;
- repository allowlist and immutable commit/ref selection;
- source path allowlist and path-traversal protection;
- fixed database metadata queries only;
- database credentials with schema-only, read-only privileges;
- bounded time ranges, files, rows, tables, calls and output bytes;
- no network access from a code-analysis tool;
- response redaction before MCP output;
- audit record for source, caller, operation, limits and outcome;
- cancellation and deadline propagation.

MCP tool annotations such as `readOnlyHint` are useful metadata but are not a
security control. Authorization must be enforced by the gateway and connector.
See the [MCP tools specification](https://modelcontextprotocol.io/specification/2025-11-25/server/tools)
and [MCP schema annotations](https://modelcontextprotocol.io/specification/2025-11-25/schema).

For high-volume WAF ingestion, prefer a WAF/SIEM export, queue or log pipeline
as the data plane. MCP is appropriate for bounded, on-demand context retrieval
and investigation.

## Passive detectors

### K1 — object enumeration

Group events by a combination of:

- principal pseudonym;
- tenant or account pseudonym, when available;
- route family;
- source-IP pseudonym and user-agent family;
- time bucket.

Candidate signals:

- unusually high distinct object identifiers per identity;
- sequential or near-sequential numeric identifiers;
- high `404 -> 200` transition patterns;
- many objects accessed in a short interval;
- unusually high identifier-to-business-action ratio;
- repeated access to objects belonging to multiple tenants;
- response-size or latency differences that reveal valid identifiers;
- WAF blocks or challenges interleaved with successful requests.

The detector must compare behavior with a route-specific baseline. A fixed
threshold alone will produce noise for administrators, batch jobs and search
clients.

Example candidate evidence:

```text
Possible object enumeration on GET /orders/{id}

Identity group: pseudonymized
Window: 12 minutes
Distinct identifiers: 428
Sequentiality score: 0.73
Successful responses: 133
Not-found responses: 295
Normal baseline: 12 identifiers per identity per hour
```

This is `heuristic` unless the event source also demonstrates cross-tenant
access or the active scanner confirms unauthorized reads.

### K2 — account enumeration

Use WAF and access-log behavior to find bursts against login, registration,
password-reset and account-recovery routes. Promotion requires response-level
signals from an access/application log or active test, such as:

- different status codes;
- different response-size buckets;
- different stable error codes;
- materially different latency distributions;
- different rate-limit behavior for existing and nonexistent accounts.

WAF request volume alone is a lead, not proof of account enumeration.

### K3 — request-side sensitive-data leakage

Detect credential and PII names appearing in request metadata:

- tokens or passwords in query parameters;
- API keys in paths or query strings;
- email, phone or government identifiers in URLs;
- sensitive values in `Referer`;
- credentials visible to a third-party WAF or proxy log.

Store field names, locations, counts and redacted fingerprints, never values.

### K4 — response and schema drift

Correlate access-log response metadata and active response samples with the
canonical OpenAPI document:

- sensitive response fields not declared in the 2xx schema;
- endpoints returning materially different response shapes by identity;
- error responses containing internal implementation details;
- response-size anomalies after a route or deployment revision.

A WAF that only records request data cannot establish response-body leakage by
itself. Use API gateway or application access logs where response metadata is
available.

### K5 — shadow and authorization design mismatches

Compare the pinned source snapshot, OpenAPI operations and database schema:

- runtime route missing from OpenAPI;
- OpenAPI operation has no declared security requirement;
- object lookup appears to use an ID without an ownership predicate;
- exposed table has tenant/owner data but route access cannot be correlated to
  it;
- externally exposed sequential database identifiers;
- fields accepted by code but absent from the intended request schema.

These are advisory design findings. Source inspection and schema metadata alone
must not be marked as verified exploitation.

## Correlation model

Correlation should improve evidence without destroying provenance.

### Route mapping

Use the parsed OpenAPI operations as the canonical route vocabulary. Normalize
WAF paths to route families using:

1. exact known path;
2. method plus templated OpenAPI path;
3. bounded identifier-segment matching;
4. unresolved `unknown` route family.

Never guess a route family from arbitrary user-controlled text without retaining
the fact that the mapping was heuristic.

### Active scan correlation

At the beginning of an active scan, generate an opaque scan correlation ID and
send it in a dedicated header such as:

```text
X-AIDETECTOR-Correlation: <random opaque value>
```

The value must be random, short-lived and excluded from findings. If a gateway
preserves it into WAF/access logs, the scanner can correlate exact requests
without placing payloads or credentials into log-visible URLs.

Fallback matching may use request ID, route, method and a narrow timestamp
window, but it must be labelled approximate.

### Example correlated finding

```text
OpenAPI: GET /invoices/{id}
Source: invoice lookup appears to filter by id only
Database: invoices contains account_id
WAF: one identity accessed 96 invoice identifiers
Active scan: another identity read an object owned by the first identity
```

The finding should retain separate evidence references for each source. The
active behavioral result can be `verified`; source and WAF evidence are
supporting context, not a reason to inflate confidence independently.

## Confidence and fingerprints

Use the existing confidence vocabulary:

- `heuristic`: anomalous traffic, source suspicion, schema mismatch or missing
  control;
- `verified`: direct behavioral proof, such as a cross-identity read confirmed
  by the active scanner;
- AI adjudication may explain or prioritize evidence, but must not promote a
  heuristic observation to verified without a deterministic proof condition.

Fingerprints must identify the stable issue, not its changing counts:

```text
detector + normalized route family + issue class + boundary identity
```

Do not include request counts, timestamps, raw IDs, source IPs, payloads or
rotating correlation IDs in the fingerprint. Counts and windows belong in
evidence and observation history.

## API and UI additions

Suggested endpoints:

```text
GET    /scans/{id}/evidence-sources
PUT    /scans/{id}/evidence-sources/{source_id}
POST   /scans/{id}/evidence-sources/{source_id}/test
DELETE /scans/{id}/evidence-sources/{source_id}

POST   /scans/{id}/evidence-runs
GET    /scans/{id}/evidence-runs
GET    /scans/{id}/evidence-runs/{run_number}
GET    /scans/{id}/evidence-runs/{run_number}/observations
GET    /scans/{id}/evidence-runs/{run_number}/timeline
```

The UI should distinguish:

- active scan findings;
- passive observations;
- advisory design suggestions;
- correlated findings with multiple evidence sources.

The timeline should show route family, time window, detector and aggregate
metrics. Raw log access should remain in the source system or require an
explicit, separately authorized investigation action.

## Privacy and retention

Default retention should be short for normalized events and longer for findings:

```text
normalized event features: 7–30 days
aggregated observations: 30–90 days
promoted findings: normal scan retention
source audit records: organization policy, minimum required period
```

These are initial defaults, not hard-coded product promises. Each tenant may
need a stricter policy.

Required privacy controls:

- redact before persistence and before MCP responses;
- salt pseudonyms per tenant and rotate salts deliberately;
- never use raw identity or IP values in fingerprints;
- exclude secrets and bodies from aggregate evidence;
- enforce tenant-scoped reads on all evidence endpoints;
- record who accessed evidence and which connector was used;
- allow deletion of source configuration and retained evidence;
- make source availability and coverage visible so absence of data is not
  mistaken for clean behavior.

## Implementation increments

### K0 — contracts and threat model

- define `EvidenceSource`, `EvidenceRun` and `SecurityObservation` contracts;
- document data classifications and retention;
- add tenant/source binding rules;
- add fixed error codes and cancellation behavior;
- add contract fixtures with sanitized sample events.

### K1 — WAF snapshot adapter

- implement one vendor-neutral JSON adapter first;
- normalize events into the value-free shape above;
- support an explicit time window and hard row/byte limits;
- persist aggregates and observations, not raw events;
- add source health and coverage events.

### K2 — enumeration detector

- implement route-family mapping;
- add distinct-ID, sequentiality and response-outcome features;
- add route-specific baseline calculation;
- produce heuristic candidates with explainable metrics;
- test with positive, negative, administrator and batch-client fixtures.

### K3 — source and database context

- add pinned repository context through a read-only MCP adapter;
- reuse the existing schema-only database service and vault controls;
- add deterministic OpenAPI/code/database mismatch rules;
- keep advisory results separate from vulnerability findings.

### K4 — active correlation

- add opaque correlation headers to active probe requests;
- map WAF/access records back to active trace rows;
- attach evidence references to findings;
- preserve confidence and stable fingerprint behavior across reruns.

### K5 — account and sensitive-data detectors

- add authentication-flow enumeration signals;
- add request-side credential/PII location checks;
- add response metadata and schema-drift checks where access logs support them;
- add remediation catalogue entries and UI explanations.

### K6 — monitoring mode

- add source cursors and watermark processing;
- add scheduled evidence runs with bounded overlap;
- add observation expiry and recovery behavior;
- add alert delivery only for meaningful state changes;
- measure false-positive rate before enabling default monitoring.

## Testing and quality gates

The phase is complete only when the following are covered:

- source configuration cannot cross tenants;
- revoked or changed bindings stop an in-flight read;
- database adapters execute only fixed metadata queries;
- repository adapters cannot escape the allowed root or commit;
- MCP outputs are bounded and redacted;
- raw credentials, tokens, bodies and identifiers never reach stored evidence;
- WAF connector failures produce an unavailable source state, not a clean result;
- delayed and duplicated log events do not double-count observations;
- enumeration detection is quiet on safe/baseline fixtures;
- known enumeration fixtures produce stable fingerprints;
- active scanner findings remain unchanged when no evidence sources are present;
- evidence-only findings remain heuristic unless a direct proof condition exists;
- run diffs handle changed evidence windows as not-retested or changed scope;
- every detector has remediation and coverage documentation;
- API/frontend contracts mirror all new enums and response fields;
- retention and deletion remove evidence belonging to the requested tenant.

Suggested test modules:

```text
tests/test_evidence_sources.py
tests/test_evidence_runs.py
tests/test_waf_normalization.py
tests/test_enumeration_detector.py
tests/test_evidence_redaction.py
tests/test_mcp_boundary.py
tests/test_evidence_correlation.py
tests/test_evidence_retention.py
```

## Acceptance criteria

The first release is ready when an authorized user can:

1. configure a read-only WAF log source;
2. run a bounded evidence snapshot for a selected time window;
3. see source health, coverage and the exact window analyzed;
4. receive an explainable heuristic enumeration observation when a fixture
   exhibits sequential cross-object access;
5. see no finding for normal administrator, search or batch behavior;
6. attach a pinned OpenAPI, source revision and schema snapshot as supporting
   context;
7. correlate an active BOLA proof with the corresponding WAF behavior;
8. inspect redacted metrics without seeing credentials, raw identifiers or
   customer data;
9. rerun the snapshot and preserve finding identity and human triage;
10. revoke or delete the source and verify that its retained evidence is no
    longer accessible.

The product should report “no usable evidence” distinctly from “no anomaly
detected.” A missing WAF feed is a coverage limitation, not evidence that the
API is safe.
