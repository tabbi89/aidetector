"""Monitoring: evidence sources, WAF/rapid ingest, briefings, bots, routes and clients."""

from __future__ import annotations

import uuid
from datetime import date, datetime
from typing import Any, Literal

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    SecretStr,
    model_validator,
)

from app.api.schemas.common import ResponseModel
from app.monitoring.contracts import SourceInput
from app.monitoring.rapid import ApplicationSignal


class MonitoringCreate(BaseModel):
    name: str = Field(min_length=1, max_length=160)
    target_binding: str = Field(min_length=1, max_length=2048)
    source_ids: list[str] = Field(default_factory=list, max_length=32)
    # Daily is the default and the only cadence dispatched by the first slice.
    schedule_minutes: int = Field(default=1440, ge=1440, le=100000)
    minimum_baseline_days: int = Field(default=7, ge=7, le=30)
    schedule_enabled: bool = False
    retention_days: int = Field(default=90, ge=31, le=90)


class MonitoringOut(ResponseModel):
    model_config = ConfigDict(from_attributes=True)
    id: uuid.UUID
    tenant_id: str
    name: str
    target_binding: str
    source_ids: list[str] = []
    schedule_minutes: int
    minimum_baseline_days: int
    schedule_enabled: bool
    rapid_enabled: bool = False
    retention_days: int
    scan_id: uuid.UUID | None = None
    status: Literal["active", "paused"]
    last_observation_date: date | None = None
    last_run_at: datetime | None = None
    created_at: datetime


class WafIngestRequest(BaseModel):
    """Raw adapter input; records are normalized before they reach storage."""

    observation_date: date | None = None
    records: list[dict[str, Any]] = Field(min_length=0, max_length=10000)
    source_revisions: dict[str, str] = Field(default_factory=dict, max_length=32)


class MonitoringRunOut(ResponseModel):
    model_config = ConfigDict(from_attributes=True)
    id: uuid.UUID
    monitor_id: uuid.UUID
    observation_date: date
    status: Literal["queued", "collecting", "awaiting_evidence", "complete", "failed", "cancelled"]
    state: Literal["no_data", "warming_up", "baseline_ready", "degraded", "anomaly"]
    error_code: str | None = None
    scope_revision: str
    correlations: list[dict[str, Any]] = []
    baseline_start: date | None = None
    baseline_end: date | None = None
    baseline_days_available: int
    data_quality: Literal["unknown", "missing", "warming_up", "sufficient"]
    source_revisions: dict[str, str] = {}
    metrics: dict[str, Any] = {}
    observations: list[dict[str, Any]] = []
    started_at: datetime | None = None
    finished_at: datetime | None = None
    created_at: datetime


class MonitoringRapidIngest(BaseModel):
    """A complete rolling hour, submitted repeatedly by a trusted log pipeline."""

    model_config = ConfigDict(extra="forbid")
    window_start: datetime
    window_end: datetime
    waf_records: list[dict[str, Any]] = Field(default_factory=list, max_length=10000)
    application_events: list[ApplicationSignal] = Field(default_factory=list, max_length=10000)


class MonitoringRapidRunOut(ResponseModel):
    model_config = ConfigDict(from_attributes=True)
    id: uuid.UUID
    monitor_id: uuid.UUID
    window_start: datetime
    window_end: datetime
    observations: list[dict[str, Any]]
    skipped: dict[str, str]
    pulse: dict[str, Any]
    waf_count: int
    application_count: int
    created_at: datetime


class EvidenceSourceCreate(SourceInput):
    pass


class EvidenceSourceOut(ResponseModel):
    model_config = ConfigDict(from_attributes=True)
    id: uuid.UUID
    name: str
    target_binding: str
    connector: Literal["json_snapshot", "aws_cloudwatch", "aws_alb", "github"]
    config: dict[str, Any]
    has_credentials: bool
    error_code: str | None = None
    watermark: date | None = None
    revision: int
    status: Literal["ready", "untested", "unavailable", "revoked"]
    created_at: datetime


class MonitoringUpdate(BaseModel):
    model_config = ConfigDict(extra="forbid")
    status: Literal["active", "paused"]
    schedule_enabled: bool = False
    retention_days: int = Field(default=90, ge=31, le=90)


class MonitoringContextInput(BaseModel):
    model_config = ConfigDict(extra="forbid")
    scan_id: uuid.UUID
    repository_source_id: uuid.UUID | None = None
    include_database: bool = False


class MonitoringTriageInput(BaseModel):
    model_config = ConfigDict(extra="forbid")
    fingerprint: str = Field(pattern=r"^[0-9a-f]{64}$")
    disposition: Literal["candidate", "suppressed", "reviewed"]


class MonitoringAlertOut(ResponseModel):
    model_config = ConfigDict(from_attributes=True)
    id: uuid.UUID
    monitor_id: uuid.UUID
    observation_date: date
    state: str
    acknowledged: bool
    created_at: datetime


class BotCrawlerOut(ResponseModel):
    """One bot as AWS WAF Bot Control labelled it; empty strings when unlabelled."""

    name: str
    organization: str
    category: str
    verification: str
    requests: int
    allowed: int
    blocked: int
    challenged: int


class BotSeriesDayOut(ResponseModel):
    day: date
    by_category: dict[str, int]


class AgentLogLine(ResponseModel):
    at: str
    text: str


class MonitoringBriefingOut(ResponseModel):
    """The latest AI traffic briefing: commentary on the evidence, never evidence."""

    status: Literal["none", "pending", "complete", "unavailable"]
    requested_at: str | None = None
    finished_at: str | None = None
    days: int | None = None
    evidence_through: str | None = None
    # Parts of the evidence cut to fit the prompt budget; empty when it was sent whole.
    evidence_trimmed: list[str] = []
    reason: str | None = None
    provider: str | None = None
    model: str | None = None
    text: str | None = None
    structured: dict[str, Any] | None = None
    tokens_in: int | None = None
    tokens_out: int | None = None
    log: list[AgentLogLine] = []


class MonitoringBotsOut(ResponseModel):
    days: int
    requests: int
    bot_requests: int
    ai_requests: int
    verified_ai: int
    unverified_ai: int
    verified_ai_pct: float | None = None
    unverified_ai_pct: float | None = None
    by_category: dict[str, int]
    crawlers: list[BotCrawlerOut]
    crawler_count: int
    series: list[BotSeriesDayOut]


class RouteDayOut(ResponseModel):
    day: date
    requests: int
    # Share of that day's collected events, so sampled and full days compare.
    share: float
    blocked: int
    not_found: int


class RouteTrendOut(ResponseModel):
    route: str
    total_requests: int
    latest_day: date
    latest_requests: int
    latest_share: float
    baseline_share: float | None = None
    change: float | None = None
    score: float | None = None
    state: Literal["warming_up", "normal", "anomaly"]
    series: list[RouteDayOut]


class MonitoringRoutesOut(ResponseModel):
    days: int
    sampled: bool
    minimum_baseline_days: int
    routes: list[RouteTrendOut]


class ClientRouteOut(ResponseModel):
    route: str
    requests: int


class ClientIdentifiersOut(ResponseModel):
    """The route where one client reached the most identifiers; parameter names only."""

    route: str
    distinct: int
    sequentiality: float
    parameters: list[str]


class ClientAttackPathOut(ResponseModel):
    """A payload-matched request path, kept verbatim as sent."""

    path: str
    requests: int


class ClientFingerprintOut(ResponseModel):
    """One JA4 TLS client fingerprint's breadth for a day.

    ``eligible`` excludes the operator's allow-rule traffic (``trusted``) and
    verified bots; addresses, paths, routes and identifiers count only eligible
    requests. Payload matches count every request.
    """

    ja4: str
    requests: int
    eligible: int
    trusted: int
    verified_bot: int
    blocked: int
    challenged: int
    addresses: int
    paths: int
    routes: int
    hours: int
    top_routes: list[ClientRouteOut]
    identifiers: ClientIdentifiersOut | None = None
    attack_requests: int
    attack_allowed: int
    attack_labels: dict[str, int]
    attack_route: str | None = None
    #: Paths of payload-matched requests, as sent. Populated only for requests a
    #: managed attack rule matched, so these are the sender's payloads, not a
    #: client's data; the query string is never included.
    attack_paths: list[ClientAttackPathOut] = []
    attack_paths_total: int = 0
    bot: str | None = None
    flags: list[
        Literal["ja4_endpoint_probing", "ja4_identifier_enumeration", "ja4_request_manipulation"]
    ]


class MonitoringClientsOut(ResponseModel):
    day: date | None = None
    sampled: bool
    clients_total: int
    without_fingerprint: int
    clients: list[ClientFingerprintOut]


class MonitoringSetupOut(ResponseModel):
    """A monitor's setup as the edit form shows it. The token itself is never returned."""

    name: str
    target_binding: str
    waf_log_group_arn: str | None = None
    alb_arn: str | None = None
    github_repository: str | None = None
    github_ref: str | None = None
    github_token_set: bool = False
    scan_id: uuid.UUID | None = None
    schedule_enabled: bool
    rapid_enabled: bool = False


class MonitoringSetupUpdate(BaseModel):
    """Edit a monitor's setup. A field left out is unchanged; ``null`` removes it.

    ``target_binding`` and the WAF log group are not editable: they are what the
    baseline compares day to day, so changing either is a different monitor, and
    mixing both streams' days into one baseline would make every comparison wrong.
    """

    model_config = ConfigDict(extra="forbid")
    name: str | None = Field(default=None, min_length=1, max_length=160)
    schedule_enabled: bool | None = None
    rapid_enabled: bool | None = None
    alb_arn: str | None = Field(default=None, min_length=1, max_length=300)
    github_repository: str | None = Field(
        default=None, max_length=200, pattern=r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$"
    )
    github_ref: str | None = Field(default=None, min_length=1, max_length=255)
    # Left out keeps the stored token; send one to replace it.
    github_token: SecretStr | None = Field(default=None, min_length=1, max_length=512)
    openapi: str | None = Field(default=None, min_length=1, max_length=5_000_000)
    scan_id: uuid.UUID | None = None

    @model_validator(mode="after")
    def one_contract(self) -> MonitoringSetupUpdate:
        if self.openapi is not None and self.scan_id is not None:
            raise ValueError("provide an OpenAPI document or a scan_id, not both")
        for field in ("name", "schedule_enabled", "rapid_enabled", "github_ref"):
            if field in self.model_fields_set and getattr(self, field) is None:
                raise ValueError(f"{field} cannot be removed")
        return self


class MonitoringSetup(BaseModel):
    """One-step monitor: WAF log group, with an optional contract and repository."""

    model_config = ConfigDict(extra="forbid")
    name: str = Field(min_length=1, max_length=160)
    target_binding: str = Field(min_length=1, max_length=2048)
    # Optional contract: a spec to import, or an existing scan's operations.
    openapi: str | None = Field(default=None, min_length=1, max_length=5_000_000)
    scan_id: uuid.UUID | None = None
    waf_log_group_arn: str = Field(min_length=1, max_length=700)
    # Optional Application Load Balancer whose CloudWatch metrics add the response codes
    # and latency that AWS WAF logs lack. Needs no access logging.
    alb_arn: str | None = Field(default=None, min_length=1, max_length=300)
    github_repository: str | None = Field(
        default=None, max_length=200, pattern=r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$"
    )
    github_ref: str = Field(default="main", min_length=1, max_length=255)
    # This monitor's own read-only token for that repository. Encrypted on the
    # GitHub source, never returned and never placed in an AI prompt.
    github_token: SecretStr | None = Field(default=None, min_length=1, max_length=512)
    schedule_enabled: bool = True

    @model_validator(mode="after")
    def one_contract(self) -> MonitoringSetup:
        if self.openapi is not None and self.scan_id is not None:
            raise ValueError("provide an OpenAPI document or a scan_id, not both")
        return self
