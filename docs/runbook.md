# Runbook

Operational guide for running and maintaining aidetector.

## Services

| Service | What it does | Port |
| --- | --- | --- |
| `web` | Next.js UI | 3000 |
| `api` | FastAPI — scan control, results | 8000 |
| `worker` | Celery — runs scans | — |
| `beat` | Celery beat — dispatches scheduled scans (every 60s) | — |
| `postgres` | Database | 5432 |
| `redis` | Broker / result backend | 6379 |
| `target` | vulnbank demo target (testing only) | 9000 |
| `interactsh` | out-of-band (OAST) callback server — **opt-in** (`--profile oob`) | 8095 |
| `zap` | OWASP ZAP daemon — **opt-in** (`--profile zap`) | 8090 |
| `kali` | Kali adjunct service (nuclei + ffuf) — **opt-in** (`--profile kali`) | 8091 |

## First run

```bash
make env         # .env with a generated VAULT_KEY — api and worker must share it
make up          # build, start, wait for Postgres, apply all migrations
```

Ports in the table above are published on `127.0.0.1` (`BIND_HOST`) except
`interactsh`, which must receive callbacks; `target` is loopback-only always.
Rotate the vault key by prepending a new one: `VAULT_KEY=new,old`.

`make up` wraps compose + `alembic upgrade head`. `make help` lists every target
(`make down`, `make down-v`, `make fresh`, `make test`, `make lint`). To include
the opt-in scanners: `make up-oob`, `make up-zap`, `make up-kali`, or `make up-all`.

## Common tasks

**A scan is stuck in `running` or `queued`** — the `beat` service's
`reap_stale_scans` task fails a running scan whose worker stopped heartbeating
for `SCAN_STALE_SECONDS` (default 300) and a queued scan no worker claimed within
`SCAN_QUEUED_STALE_SECONDS` (default 6h), recording a `worker_lost` /
`queue_lost` event. If a scan stays stuck, check that `beat` is running. Once
reaped, the scan can be deleted or re-run. A single scan is also capped by
a Celery hard time limit (`SCAN_TIME_LIMIT_SECONDS`, default 2h).

**Apply a new migration**
```bash
make migrate        # or: docker compose exec api alembic upgrade head
```

**Enable AI adjudication** — set `ANTHROPIC_API_KEY` + `DEEPSEEK_API_KEY` in
`.env`, provision the isolated planner venv (see
`services/api/ai_runtime/README.md`), then run a scan with the "Run with AI"
toggle. If the key is identity-linked, prefer a standard workspace-scoped key.

**Enable out-of-band (OOB) confirmation** — blind SSRF/RFI/RCE/ESI/partial-XXE
are confirmed only when the target calls back to an OAST server you control.
Start interactsh (`make up-oob`), give the worker image the client binary
(`WITH_INTERACTSH=1 make up` — compose passes the flag through), and set
`OAST_SERVER` (and `OAST_DOMAIN`) in `.env`. Real callbacks need **public DNS
delegation** for the OAST domain to the server; a local-only network resolves
same-network HTTP/SMTP callbacks only. Without config the `oob_injection`
check is a no-op.

**Enable OWASP ZAP** — start the daemon (`make up-zap`), set `ZAP_BASE_URL`
(and `ZAP_API_KEY`) in `.env`, then tick **"Also run an OWASP ZAP active scan"**
on the run screen (or send `zap: true` to `POST /scans/{id}/run`). ZAP scans
**outside** the engine's request budget and cancellation, bounded only by
`ZAP_TIMEOUT_SECONDS`. Without config the pass emits a `zap_skipped` event.

**Enable Kali adjuncts (nuclei + endpoint discovery)** — start the service
(`make up-kali`), set `KALI_BASE_URL` (inside compose: `http://kali:8091`;
and `KALI_API_KEY` if you want the service authenticated) in `.env`, then tick
**"Also run the Kali adjuncts"** on the run screen (or send `kali: true` to
`POST /scans/{id}/run`). The service is built `FROM kalilinux/kali-rolling` with
a curated toolset (see `services/kali/README.md`). Like ZAP it runs **outside**
the engine's request budget; without config the pass emits `kali_skipped`.

**Enable sqlmap / testssl.sh in the worker** — bake the tools into the worker
image at build time (compose passes the flag through: `WITH_KALI_TOOLS=1 make
up`, or `docker compose build --build-arg WITH_KALI_TOOLS=1 worker`) and set
`SQLMAP_BIN=sqlmap` and/or `TESTSSL_BIN=testssl` in `.env` (Debian's package
installs the binary as `testssl`, no `.sh`). Both are opt-in: sqlmap runs under
the `confirm` pass and re-tests only parameters already flagged as SQLi leads
(bounded target count + timeouts); testssl runs only when a run asks for it —
the **Deep** level or `--testssl` — and audits HTTPS targets only. An unset
`SQLMAP_BIN` is a silent no-op; a requested testssl with `TESTSSL_BIN` unset, or
either binary missing, emits a `*_skipped` event.

**Monitor a production API with AWS WAF logs**. This is passive and read-only:
nothing is sent to the API.

1. In `.env`, list the log groups the deployment may read:
   `MONITORING_AWS_LOG_GROUPS=arn:aws:logs:us-west-2:257498453293:log-group:aws-waf-logs-pd_prod`.
   AWS keeps a deployment allowlist because the worker's AWS identity is
   shared; GitHub repositories are chosen per monitor instead.
2. Give the **worker** an AWS identity without storing keys in the app. Locally,
   `AWS_PROFILE=<profile> make up-aws` mounts `~/.aws` read-only (run
   `aws sso login` when the session expires). In production, use a task, pod or
   instance role. The identity needs only:
   ```json
   {"Effect": "Allow", "Action": "logs:FilterLogEvents",
    "Resource": "arn:aws:logs:us-west-2:257498453293:log-group:aws-waf-logs-pd_prod:*"}
   ```
3. Turn on Bot Control (with AI traffic analysis) on the web ACL, so log records
   carry `awswaf:managed:aws:bot-control:*` labels. The AI and bot view is built
   from those labels.
4. On **Monitoring → New monitor**, enter a name, the API base URL and the log group
   ARN. Optionally add the OpenAPI spec (or pick an existing scan) and a GitHub repo,
   branch and read-only token. Daily collection reads the previous complete UTC day after 02:00
   UTC; **Collect previous day** runs it now. The monitor shows **warming up**
   until seven consecutive days are collected: until then only leads one day
   supports on its own appear (sensitive query names, impersonated crawlers, and
   the JA4 probing, enumeration and payload leads), and baseline comparisons
   start on the eighth day. Without a contract, routes are grouped by URL shape
   and the shadow-route and bot-on-authenticated-route leads are not evaluated.
   **TLS client fingerprints (JA4)** lists the day's clients by breadth; a lead
   there names a JA4 you can block or rate-limit with a WAF JA4 match rule. With
   sampling on (`MONITORING_AWS_SAMPLE_EVENTS`), each hour contributes only its
   newest events, so a short scan outside those windows is missed.

A failed day shows a fixed code: `source_not_allowed` (ARN not allowlisted),
`credential_unavailable` (no AWS identity in the worker), `access_denied`
(missing `logs:FilterLogEvents`), `log_group_not_found`, `row_limit` (raise
`MONITORING_AWS_MAX_EVENTS`) or `deadline_exceeded` (raise
`MONITORING_COLLECT_SECONDS`).

**Explain monitoring leads with Cursor (optional)**. Build the runtime
(`WITH_CURSOR=1 make up`), then set `MONITORING_AI_PROVIDER=cursor` and
`CURSOR_API_KEY`. Each monitor's repository comes with its own fine-grained
GitHub token (**Contents: read-only**, that repository only), entered in the
monitor form and stored encrypted on its GitHub source. **Explain with AI**
on an observation runs a local Cursor agent that is offered MCP tools only:
GitHub's hosted server in read-only mode, used to find the handler behind the
route. The token's scope is the real boundary; the read-only header only narrows
the tool list. An explanation is commentary. It never changes an observation's
confidence and never creates a finding. See the
[Cursor Python SDK reference](https://prod.cursor.com/docs/sdk/python) and the
[GitHub MCP server configuration reference](https://github.com/github/github-mcp-server/blob/main/docs/server-configuration.md)
for the tool/MCP and read-only header contracts.

**Try it without AWS**. With `ENV=dev`, **Load example monitor** on
`/monitoring` builds a monitor on the bundled target with seven ordinary days
and one attack day: sequential account enumeration, an unverified AI crawler
surge, a spoofed googlebot, and one JA4 client probing paths from three
addresses and sending SQL injection payloads. **Use example target** on **New scan** fills in
the target, the spec and both identities.

**Run the test suite**
```bash
make test        # inside the api container (DB reachable → no skips)
# or locally: cd services/api && .venv/bin/pytest
```

## Troubleshooting

| Symptom | Cause | Fix |
| --- | --- | --- |
| `relation "scans" does not exist` | migrations not applied | `alembic upgrade head` |
| Scan stuck in `queued` | worker not running | check `docker compose ps worker` |
| Scheduled scans never fire | beat not running | check `docker compose ps beat` |
| `ai_skipped` event, no verdicts | planner venv/CLI/creds missing | see ai_runtime/README |
| `zap_skipped` event | `ZAP_BASE_URL` unset or daemon down | `make up-zap`, set `ZAP_BASE_URL` |
| `kali_skipped` event | `KALI_BASE_URL` unset or kali service down | `make up-kali`, set `KALI_BASE_URL` |
| `sqlmap_skipped` / `testssl_skipped` event | `*_BIN` set but tool not in worker image | rebuild worker with `WITH_KALI_TOOLS=1` |
| No `oob_injection` findings | `OAST_SERVER` unset, or no DNS delegation | see "Enable OOB" above |
| `tls_config` finds nothing on an HTTPS target | handshake failed / host unreachable from worker | check the worker can reach the target host:443 |
| CORS error in browser | API 500 (500s skip CORS headers) | check `api` logs for the real error |
| Findings all 0 | target unreachable from the worker | verify target URL resolves inside the network |

## Scaling notes

- Scans are CPU-light but network-bound; scale `worker` replicas for throughput.
- The request budget (`DEFAULT_MAX_REQUESTS`) and cadence protect targets. Set
  `ENGINE_REQUESTS_PER_SECOND` for the deployment-wide per-scan ceiling; the
  new-scan wizard or **Traffic** section can select a lower 1, 2, 5, or 10
  requests/second for the core engine and Kali. ZAP and confirmation tools manage their own traffic, and the
  write-only race check keeps its explicit bounded concurrent burst.
- AI cost is metered per scan in `token_ledger`; watch `GET /scans/{id}/cost`.
