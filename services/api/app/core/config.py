"""Application configuration, loaded from environment / .env."""

from __future__ import annotations

from functools import lru_cache
from typing import Literal

from pydantic import model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    env: str = "dev"

    database_url: str = "postgresql+psycopg://aidetector:aidetector@localhost:5432/aidetector"
    redis_url: str = "redis://localhost:6379/0"

    # Secrets vault (Fernet key). Empty in local dev falls back to an ephemeral key.
    vault_key: str = ""

    # --- API access control -------------------------------------------------
    # Comma-separated API keys accepted on every /scans route (X-API-Key or
    # Authorization: Bearer). Entries may be ``tenant:key``; bare keys belong
    # to the ``default`` tenant. EMPTY DISABLES AUTH (open local-dev API).
    api_keys: str = ""
    # Hosted deployments set this true. An empty key set stays open in dev/test;
    # a configured key or a non-dev ENV already requires authentication. This
    # flag is the explicit switch for a deployment that is neither.
    auth_required: bool = False
    # Lifetime of the token a password sign-in mints. Sessions always expire;
    # long-lived automation uses an admin-issued API token instead.
    session_hours: int = 12
    # Brute-force limits on the unauthenticated /auth routes (app/scans/
    # throttle.py). Failed sign-ins are counted per email and per client
    # address within one window; sign-up requests per client address.
    auth_login_failures_per_email: int = 10
    auth_login_failures_per_ip: int = 50
    auth_login_window_seconds: int = 900
    auth_signups_per_ip: int = 5
    auth_signup_window_seconds: int = 3600

    # --- Premium tier --------------------------------------------------------
    # Comma-separated tenant names allowed to use the premium tier. "*" (the
    # default) means every tenant may — the open-dev posture, mirroring api_keys
    # empty meaning auth disabled. A hosted deployment lists its paying tenants.
    premium_tenants: str = "*"

    def premium_tenant_set(self) -> set[str]:
        return {t.strip() for t in self.premium_tenants.split(",") if t.strip()}

    def tenant_is_premium(self, tenant: str) -> bool:
        """Whether ``tenant`` may run the premium tier (``premium: true``)."""
        allowed = self.premium_tenant_set()
        return "*" in allowed or tenant in allowed

    # --- Target egress / SSRF guard (app/core/target_guard.py) --------------
    # Cloud-metadata addresses (169.254.0.0/16, IPv6 link-local, AWS IPv6 IMDS,
    # Alibaba/Azure host endpoints — including IPv6 forms embedding them) and
    # non-http(s) schemes are ALWAYS blocked at run time, regardless of the flags
    # below.
    #
    # allow_private lets scans target RFC-1918 / loopback hosts. It defaults to
    # True because the intended use is scanning a local lab (services/target,
    # localhost). A HOSTED / MULTI-TENANT deployment MUST set it to False, which
    # then requires every target to resolve to a public IP.
    target_allow_private: bool = True
    # Comma-separated host allowlist (exact host or ".suffix" domain). When set,
    # it is authoritative: only listed hosts may be scanned and the private/
    # metadata checks are skipped for them.
    target_allowlist: str = ""
    # Ownership verification (app/core/ownership.py, app/scans/domains.py). A
    # target that resolves to any public address is scanned only once the
    # workspace proves it controls it: a DNS TXT record for the name and an
    # HTTP token served from the address the scan connects to. Private-only
    # targets and allowlisted hosts are exempt. Turning this off lets any
    # workspace aim the scanner at any public host.
    target_require_verification: bool = True
    # DNS for the TXT proof goes over DoH (JSON API), never the local resolver,
    # which the person proving ownership may control.
    domain_verification_doh_url: str = "https://cloudflare-dns.com/dns-query"
    domain_verification_timeout_seconds: float = 5.0

    # --- Outbound notifications ---------------------------------------------
    # Webhook/Slack destinations are decrypted only at delivery and re-checked
    # against the same metadata/private rules as a scan target. Private hosts
    # are refused unless explicitly enabled; the allowlist is authoritative.
    notification_timeout_seconds: int = 10
    notification_max_attempts: int = 8
    notification_batch_size: int = 20
    notification_allow_private: bool = False
    notification_allowlist: str = ""

    def notification_allowlist_set(self) -> set[str]:
        return {
            host.strip()
            for host in self.notification_allowlist.split(",")
            if host.strip()
        }

    # Remote OpenAPI $refs are disabled unless their host is explicitly listed.
    spec_ref_allowlist: str = ""

    # Engine concurrency and per-target request rate. The global request budget
    # remains an independent hard safety ceiling.
    engine_concurrency: int = 4
    engine_requests_per_second: float = 10.0
    # Local runner (the CLI heavy lane): a scan whose traffic originates on the
    # CLI machine, claimed over POST /scans/{id}/local-runs and uploaded back.
    # Off by default — it is a deployment opt-in, like the adjunct services.
    local_runner_enabled: bool = False
    # A second, separately-capped engine pass runs the core checks against paths
    # and params that discovery (ffuf/katana/arjun) found but the spec omits.
    # Independent of the main 750 budget on purpose: testing shadow endpoints
    # must not eat the budget the documented ones need, nor the reverse.
    discovery_probe_budget: int = 150
    # Concurrent requests the race/limit-overrun check fires in one burst. Small
    # on purpose: enough to win a TOCTOU window, not enough to be a load test.
    race_burst: int = 6
    # Scan liveness (app/scans/reaper.py). A running worker stamps
    # Scan.heartbeat_at every scan_heartbeat_seconds; the beat reaper fails a
    # running scan silent for scan_stale_seconds, and a queued one no worker has
    # claimed within scan_queued_stale_seconds (a lost broker message). The stale
    # window must comfortably exceed the heartbeat interval.
    scan_heartbeat_seconds: int = 30
    scan_stale_seconds: int = 300
    scan_queued_stale_seconds: int = 21600
    # Celery hard time limit for one scan. Past it the worker process is killed
    # and the reaper marks the scan failed. There is deliberately no soft limit:
    # its exception would be swallowed by the runner's check isolation.
    scan_time_limit_seconds: int = 7200
    schemathesis_cases_per_scan: int = 20
    adaptive_endpoints: int = 5
    adaptive_requests: int = 40
    adaptive_seconds: int = 90
    adaptive_tokens: int = 12000
    adaptive_cost_micros: int = 100000

    def api_key_set(self) -> set[str]:
        return set(self.api_key_tenants())

    def api_key_tenants(self) -> dict[str, str]:
        """Configured secret -> tenant mapping (``tenant:key`` or bare key)."""
        out: dict[str, str] = {}
        for raw in self.api_keys.split(","):
            entry = raw.strip()
            if not entry:
                continue
            tenant, sep, key = entry.partition(":")
            if sep and tenant.strip() and key.strip():
                out[key.strip()] = tenant.strip()[:120]
            else:
                out[entry] = "default"
        return out

    def allowlist_set(self) -> list[str]:
        return [h.strip().lower() for h in self.target_allowlist.split(",") if h.strip()]

    def spec_ref_allowlist_set(self) -> list[str]:
        return [h.strip().lower() for h in self.spec_ref_allowlist.split(",") if h.strip()]

    @model_validator(mode="after")
    def _reservation_outlives_the_call(self) -> Settings:
        # A budget claim older than the TTL is pruned as a dead caller's. If a
        # call may run longer than that, a live call's claim disappears and a
        # concurrent caller can spend the allowance it was holding.
        if self.ai_reservation_ttl_seconds <= self.ai_timeout_seconds:
            raise ValueError(
                "ai_reservation_ttl_seconds must exceed ai_timeout_seconds "
                f"({self.ai_reservation_ttl_seconds} <= {self.ai_timeout_seconds})"
            )
        return self

    def effective_planner_model(self) -> str:
        """The model that actually does the planner's job under `planner_provider`."""
        return self.executor_model if self.planner_provider == "deepseek" else self.planner_model

    # AI cascade
    anthropic_api_key: str = ""
    # Required when the API key is identity-linked (workspace-scoped).
    anthropic_workspace_id: str = ""
    # Who does the planner's job (plan, adjudicate, adaptive, propose_resource).
    # "deepseek" (default): one direct DeepSeek completion per call on
    # `executor_model` — no Claude Agent SDK, `claude` CLI or .venv-ai needed.
    # "anthropic": the Agent SDK runtime on `planner_model`, with DeepSeek as
    # its triage tool. Q&A, payloads and security review are DeepSeek either way.
    planner_provider: Literal["deepseek", "anthropic"] = "deepseek"
    planner_model: str = "claude-opus-5"
    deepseek_api_key: str = ""
    deepseek_base_url: str = "https://api.deepseek.com"
    # deepseek-chat (V4-Flash, fast/cheap) is the recommended executor. Reasoning
    # models like deepseek-v4-pro also work but are slower and spend far more
    # output tokens — the executor_max_tokens ceiling accommodates them.
    executor_model: str = "deepseek-chat"
    executor_max_tokens: int = 2000
    # How long a pre-call budget reservation is trusted. A reservation is
    # released when the call's ledger rows land; one older than this belongs to
    # a process that died mid-call and must stop counting against the tenant.
    ai_reservation_ttl_seconds: int = 900
    # Isolated Agent SDK runtime (its own venv). Empty → services/api/.venv-ai.
    ai_python: str = ""
    ai_timeout_seconds: int = 300
    # Phase K monitoring explanations are optional and never create findings.
    # Cursor runs in the isolated AI runtime with a strict MCP-only toolset.
    monitoring_ai_provider: str = "none"
    cursor_api_key: str = ""
    cursor_model: str = "composer-2.5"
    # Extra JSON object of HTTPS MCP endpoints merged into the GitHub server the
    # provider builds. Stdio/executable servers are rejected by the runtime.
    cursor_mcp_servers_json: str = ""
    monitoring_hmac_key: str = ""
    # Remote evidence integrations are deployment opt-ins, exact names only.
    # AWS entries are log-group ARNs (a trailing ":*" is fine) or region:group.
    monitoring_aws_log_groups: str = ""
    # Application Load Balancer ARNs whose CloudWatch metrics the worker may read, for
    # the response codes and latency AWS WAF logs do not carry. Needs no access logging;
    # the worker's identity needs cloudwatch:GetMetricData.
    monitoring_aws_load_balancers: str = ""
    # Ceiling for reading one day's load balancer metrics. Also clamped to what is left
    # of the collection task's own time limit: a task killed mid-read saves nothing, so
    # the WAF day it already read would be lost with it.
    monitoring_alb_collect_seconds: int = 60
    # Bounds for collecting one AWS day. Events are normalized page by page, so
    # worker memory tracks the event cap rather than the raw log volume.
    # Events are folded into aggregates page by page, so memory follows distinct
    # clients and routes, not volume; these are safety bounds, time is the budget.
    monitoring_aws_max_events: int = 5_000_000
    monitoring_aws_max_calls: int = 20_000
    monitoring_collect_seconds: int = 1800
    # Hourly windows read at once; FilterLogEvents allows 5 requests/s per account.
    #: Short-window detection: seconds a WAF record may take to reach CloudWatch,
    #: the per-window read limits, and how often enabled monitors are evaluated.
    monitoring_rapid_lag_seconds: int = 300
    monitoring_rapid_collect_seconds: int = 180
    monitoring_rapid_max_events: int = 200_000
    monitoring_rapid_interval_seconds: int = 300
    monitoring_aws_concurrency: int = 4
    # Events kept per collected day, split evenly across its 24 UTC hours (the
    # newest of each hour). 0 reads the whole day, which can take many minutes.
    monitoring_aws_sample_events: int = 20_000
    # GitHub's hosted MCP server for monitoring explanations. Each monitor brings
    # its own repository and read-only token; there is no deployment allowlist.
    monitoring_github_mcp_url: str = "https://api.githubcopilot.com/mcp/x/repos/readonly"
    # One explanation reads a repository through many MCP calls, so it gets its
    # own ceiling, longer than the scan-time AI timeout.
    monitoring_ai_timeout_seconds: int = 600

    # Out-of-band (OAST) interaction server for blind-vuln confirmation. Empty →
    # OOB checks stay inactive (scans run with engine findings only). Point at a
    # self-hosted interactsh-server domain, e.g. "oast.internal".
    oast_server: str = ""
    oast_token: str = ""
    oast_client_binary: str = "interactsh-client"
    # The collector a CLI run's runner registers with. Separate from the server
    # lane's on purpose: the claim hands its token to every CLI user who claims
    # a run, so point it at a public collector meant for that (its targets must
    # reach it over the internet). Empty → OOB checks stay inactive on CLI runs.
    runner_oast_server: str = ""
    runner_oast_token: str = ""
    # Per-run cap on the AI proposal calls a local run may make to the service
    # (resource refinement and, later, the other in-loop AI passes), so a runner
    # cannot spend tokens without bound. Each call is still priced on the ledger.
    runner_ai_call_budget: int = 30

    # OWASP ZAP daemon (opt-in, heavier parallel scanner). Empty base URL → the
    # ZAP pass is skipped. ZAP runs on its own request/cancel model, NOT the
    # engine's 750-request budget — see app/engine/zap.py.
    zap_base_url: str = ""
    zap_api_key: str = ""
    # Ceiling on how long we wait for ZAP's spider+active-scan before giving up.
    zap_timeout_seconds: int = 600
    zap_poll_seconds: float = 3.0

    # Wall-clock ceiling for the WHOLE adjunct phase (confirm tools + testssl +
    # Kali, combined). Once spent, remaining adjunct passes are skipped so a scan
    # can't hang for tens of minutes in a slow external tool. The AI cascade has
    # its own separate timeout and runs after this.
    adjunct_budget_seconds: int = 600

    # sqlmap confirmation of SQLi leads (opt-in, like OAST). Empty → off. The
    # pass re-tests only parameters the engine already flagged, bounded by
    # max_targets and a wall-clock timeout — see app/engine/sqlmap_confirm.py.
    sqlmap_bin: str = ""
    sqlmap_timeout_seconds: int = 300
    sqlmap_max_targets: int = 5

    # dalfox confirmation of XSS leads (opt-in, like sqlmap). Empty → off.
    # Re-tests only parameters the engine flagged as XSS leads — a dalfox
    # "verified" PoC upgrades the lead to a confirmed CWE-79 finding.
    dalfox_bin: str = ""
    dalfox_timeout_seconds: int = 180
    dalfox_max_targets: int = 5

    # commix confirmation of command-injection leads (opt-in, like sqlmap).
    # Empty → off. Re-tests only parameters flagged as cmdi leads.
    commix_bin: str = ""
    commix_timeout_seconds: int = 300
    commix_max_targets: int = 5

    # tplmap confirmation of SSTI leads (opt-in, like sqlmap). Empty → off.
    # tplmap is a deprecated Python-2 tool not packaged in Debian — provision it
    # yourself and point TPLMAP_BIN at the launcher (see tplmap_confirm.py).
    tplmap_bin: str = ""
    tplmap_timeout_seconds: int = 240
    tplmap_max_targets: int = 5

    # testssl.sh deep transport audit (opt-in, like OAST). Empty → off; HTTPS
    # targets only — see app/engine/testssl_scan.py.
    testssl_bin: str = ""
    testssl_timeout_seconds: int = 300

    # Kali adjunct service (opt-in per run via `kali: true`): nuclei templates +
    # endpoint discovery. Runs OUTSIDE the engine's request budget and
    # cancellation model, like ZAP — see app/engine/kali.py.
    kali_base_url: str = ""
    kali_api_key: str = ""
    kali_timeout_seconds: int = 900


@lru_cache
def get_settings() -> Settings:
    return Settings()


settings = get_settings()
