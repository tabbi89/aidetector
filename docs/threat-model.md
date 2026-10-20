# Threat model

aidetector is an **active** API security scanner: it sends real attack payloads
at a target and stores credentials for that target. This document states what it
does, the risks that creates, and the controls that bound them.

## Assets

| Asset | Sensitivity | Where it lives |
| --- | --- | --- |
| Uploaded API credentials | High | Encrypted at rest (Fernet), decrypted only in the scan worker |
| Target API responses | Medium–High | Stored as finding evidence (truncated and redacted) |
| Scan findings | Medium | Postgres |
| AI provider keys | High | `.env` (gitignored), never returned by the API |

## Trust boundaries

- **Browser → API**: the UI is untrusted input; request bodies are validated
  with Pydantic. When `api_keys` is configured, every `/scans` route also
  requires `X-API-Key` or `Authorization: Bearer` authentication.
- **API → target**: outbound attack traffic. Bounded by the authorization gate,
  request budget, and target egress policy (below).
- **Worker → AI providers**: the DeepSeek executor sees finding evidence derived
  from target responses. See "AI data residency".
- **Worker → OAST server** (opt-in): out-of-band payloads embed a callback URL to
  the configured interactsh server. When the target is vulnerable it reaches that
  server; if the server is not self-hosted, that interaction (and any data the
  target appends to the callback) leaves your infrastructure. Self-host it.
- **Worker → ZAP daemon** (opt-in): ZAP receives the target URL and scans it on
  its own schedule. See the request-budget exception below.

## Controls

1. **API access control** — when `api_keys` is configured, every `/scans`
   route requires a matching key in `X-API-Key` or `Authorization: Bearer`.
   Authentication is disabled when the setting is empty to preserve the local
   development workflow. A hosted deployment must configure it. Keys map to
   tenants (`tenant:key`), and scans are scoped to the creating tenant, so one
   key cannot read or act on another tenant's scans. It is still a shared-key
   boundary within a tenant (no per-user identity), not a full authorization
   model.
2. **Authorization gate** — `POST /scans/{id}/run` requires `authorized: true`.
   No scan fires without an explicit affirmation of permission to test the target.
3. **Target egress policy** — the run endpoint validates `target_base_url`
   immediately before queueing work. Only HTTP(S) URLs are accepted. When
   `target_allowlist` is configured it is authoritative: only exact hosts and
   configured domain suffixes are accepted. Without an allowlist, cloud-metadata
   names and `169.254.0.0/16` are rejected; setting
   `target_allow_private=false` additionally requires every resolved address to
   be public. Private targets remain allowed by default for the bundled local
   lab. Because an allowlist entry explicitly overrides address classification,
   operators must never allowlist cloud-metadata names or addresses.
4. **Request budget** — `HttpProbe` enforces a per-scan request cap
   (`DEFAULT_MAX_REQUESTS`, 750) so a scan cannot flood a target. The TLS check
   uses a few direct sockets (not HTTP requests) and is outside this count.
   **Exception:** the opt-in ZAP pass runs on its own request schedule, *outside*
   this budget and cooperative cancel, bounded only by a wall-clock timeout — so
   it is gated behind an explicit per-run opt-in and a configured daemon.
5. **Cooperative cancel** — a running scan can be stopped between checks (does not
   interrupt an in-flight ZAP pass).
6. **Credential isolation** — secrets are Fernet-encrypted at rest, decrypted
   only inside the runner, never logged, and never sent to the executor model.
7. **Stored-evidence redaction** — before a finding is persisted, its description
   and evidence are recursively scrubbed of the scan's known credential secrets
   and patterns that resemble JWTs, authorization tokens, email addresses, and
   long opaque tokens. This is defense in depth, not a guarantee that arbitrary
   application-specific PII will be recognized.
8. **Benign payloads** — probes carry a unique marker, not a live exploit. The
   reflection/signature checks look for *reflection or a backend error string*.
   The out-of-band checks embed a callback URL to a server you control: a hit
   proves the vulnerability without exploiting it, but it does cause the target
   to make one outbound request (see the Worker → OAST trust boundary).
9. **AI and adjunct scanners are opt-in** — planning runs only on `plan: true`,
   adjudication on `adjudicate: true`, ZAP on `zap: true`, Kali on `kali: true`,
   and lead-confirmation tools on `confirm: true`; each also requires its own
   configured runtime. OOB is inactive unless `OAST_SERVER` is set. Failures
   degrade gracefully, leaving engine findings intact rather than failing a scan.

## Known gaps / future work

- **AI data residency**: the hosted DeepSeek executor receives finding evidence.
  For sensitive targets, self-host DeepSeek (vLLM) and point `DEEPSEEK_BASE_URL`
  at it so data stays in-house.
- **Tenant isolation is coarse** — keys map to tenants and scans are scoped to
  the creating tenant, but there is no per-user identity within a tenant and keys
  are long-lived shared secrets. Deployments with many mutually untrusted users
  still want an authenticating proxy and per-user access control in front.
- **Redaction is heuristic** — known credentials and common secret/PII shapes
  are masked, but arbitrary target-specific sensitive fields can still reach
  stored evidence or an enabled AI provider. Minimize response data and review
  target-specific exposure before scanning production systems.
- **OOB data egress** — a public (non-self-hosted) OAST server sees callbacks
  from vulnerable targets. Self-host interactsh for sensitive engagements.
- **ZAP outside the budget** — the opt-in ZAP pass is not rate-bounded by the
  engine. Enable it only against targets you can afford to have actively scanned.
- **XXE is partial** — the OOB check fuzzes JSON bodies, not XML-content-type
  bodies, so XXE only fires where a JSON value is parsed as XML downstream.
