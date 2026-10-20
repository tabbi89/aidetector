"""Daily infrastructure-monitoring configuration and immutable run summaries."""

from __future__ import annotations

import uuid
from datetime import date, datetime

from sqlalchemy import Boolean, Date, DateTime, ForeignKey, Integer, String, Text, UniqueConstraint
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column

from app.models.base import Base, created_at_col, uuid_pk


class InfrastructureMonitor(Base):
    """A tenant-scoped, read-only telemetry monitor scheduled once per day."""

    __tablename__ = "infrastructure_monitors"

    id: Mapped[uuid.UUID] = uuid_pk()
    tenant_id: Mapped[str] = mapped_column(String(120), index=True)
    name: Mapped[str] = mapped_column(String(160))
    target_binding: Mapped[str] = mapped_column(String(2048))
    source_ids: Mapped[list] = mapped_column(JSONB, default=list, server_default="[]")
    schedule_minutes: Mapped[int] = mapped_column(Integer, default=1440, server_default="1440")
    minimum_baseline_days: Mapped[int] = mapped_column(Integer, default=7, server_default="7")
    status: Mapped[str] = mapped_column(String(20), default="active", server_default="active")
    scan_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("scans.id", ondelete="SET NULL"))
    schedule_enabled: Mapped[bool] = mapped_column(Boolean, default=False, server_default="false")
    #: Opt-in: read the newest hour of WAF logs every few minutes for short-window leads.
    rapid_enabled: Mapped[bool] = mapped_column(Boolean, default=False, server_default="false")
    retention_days: Mapped[int] = mapped_column(Integer, default=90, server_default="90")
    context: Mapped[dict] = mapped_column(JSONB, default=dict, server_default="{}")
    triage: Mapped[dict] = mapped_column(JSONB, default=dict, server_default="{}")
    #: The latest on-demand AI traffic briefing; commentary, never evidence.
    ai_briefing: Mapped[dict] = mapped_column(JSONB, default=dict, server_default="{}")
    last_observation_date: Mapped[date | None] = mapped_column(Date, nullable=True)
    last_run_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = created_at_col()


class MonitoringRun(Base):
    """One daily observation and its deterministic, value-free aggregates."""

    __tablename__ = "monitoring_runs"
    __table_args__ = (
        UniqueConstraint("monitor_id", "observation_date", name="uq_monitoring_run_day"),
    )

    id: Mapped[uuid.UUID] = uuid_pk()
    monitor_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("infrastructure_monitors.id", ondelete="CASCADE"), index=True
    )
    observation_date: Mapped[date] = mapped_column(Date)
    status: Mapped[str] = mapped_column(String(20), default="queued", server_default="queued")
    state: Mapped[str] = mapped_column(String(24), default="no_data", server_default="no_data")
    error_code: Mapped[str | None] = mapped_column(String(40))
    claim: Mapped[uuid.UUID | None] = mapped_column()
    scope_revision: Mapped[str] = mapped_column(String(64), default="", server_default="")
    correlations: Mapped[list] = mapped_column(JSONB, default=list, server_default="[]")
    baseline_start: Mapped[date | None] = mapped_column(Date, nullable=True)
    baseline_end: Mapped[date | None] = mapped_column(Date, nullable=True)
    baseline_days_available: Mapped[int] = mapped_column(Integer, default=0, server_default="0")
    data_quality: Mapped[str] = mapped_column(
        String(20), default="unknown", server_default="unknown"
    )
    source_revisions: Mapped[dict] = mapped_column(JSONB, default=dict, server_default="{}")
    metrics: Mapped[dict] = mapped_column(JSONB, default=dict, server_default="{}")
    observations: Mapped[list] = mapped_column(JSONB, default=list, server_default="[]")
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = created_at_col()


class MonitoringRapidRun(Base):
    """One complete rolling log window, storing findings but never raw records."""

    __tablename__ = "monitoring_rapid_runs"
    __table_args__ = (
        UniqueConstraint(
            "monitor_id", "window_start", "window_end", name="uq_monitoring_rapid_window"
        ),
    )

    id: Mapped[uuid.UUID] = uuid_pk()
    monitor_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("infrastructure_monitors.id", ondelete="CASCADE"), index=True
    )
    window_start: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    window_end: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    observations: Mapped[list] = mapped_column(JSONB, default=list, server_default="[]")
    skipped: Mapped[dict] = mapped_column(JSONB, default=dict, server_default="{}")
    #: Exact, value-free totals for the final five minutes of this rolling hour.
    pulse: Mapped[dict] = mapped_column(JSONB, default=dict, server_default="{}")
    waf_count: Mapped[int] = mapped_column(Integer, default=0, server_default="0")
    application_count: Mapped[int] = mapped_column(Integer, default=0, server_default="0")
    created_at: Mapped[datetime] = created_at_col()


class EvidenceSource(Base):
    """Immutable binding for a read-only uploaded JSON log source."""

    __tablename__ = "evidence_sources"

    id: Mapped[uuid.UUID] = uuid_pk()
    tenant_id: Mapped[str] = mapped_column(String(120), index=True)
    name: Mapped[str] = mapped_column(String(160))
    target_binding: Mapped[str] = mapped_column(String(2048))
    connector: Mapped[str] = mapped_column(String(32), default="json_snapshot")
    config: Mapped[dict] = mapped_column(JSONB, default=dict, server_default="{}")
    secret_ref: Mapped[str | None] = mapped_column(Text)
    error_code: Mapped[str | None] = mapped_column(String(40))
    watermark: Mapped[date | None] = mapped_column(Date)
    revision: Mapped[int] = mapped_column(Integer, default=1, server_default="1")
    status: Mapped[str] = mapped_column(String(20), default="ready", server_default="ready")
    created_at: Mapped[datetime] = created_at_col()

    @property
    def has_credentials(self) -> bool:
        return bool(self.secret_ref)


class EvidenceAudit(Base):
    __tablename__ = "evidence_audit"
    id: Mapped[uuid.UUID] = uuid_pk()
    tenant_id: Mapped[str] = mapped_column(String(120), index=True)
    source_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("evidence_sources.id", ondelete="CASCADE")
    )
    action: Mapped[str] = mapped_column(String(32))
    outcome: Mapped[str] = mapped_column(String(40))
    created_at: Mapped[datetime] = created_at_col()


class MonitoringAlert(Base):
    __tablename__ = "monitoring_alerts"
    id: Mapped[uuid.UUID] = uuid_pk()
    monitor_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("infrastructure_monitors.id", ondelete="CASCADE"), index=True
    )
    observation_date: Mapped[date] = mapped_column(Date)
    state: Mapped[str] = mapped_column(String(24))
    acknowledged: Mapped[bool] = mapped_column(Boolean, default=False, server_default="false")
    created_at: Mapped[datetime] = created_at_col()
