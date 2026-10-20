"""Persistence and daily lifecycle for infrastructure monitoring."""
from __future__ import annotations

import hashlib
import hmac
import uuid
from datetime import UTC, date, datetime, timedelta
from typing import Any

from sqlalchemy import delete, select, update
from sqlalchemy.orm import Session

from app.core.config import settings
from app.domain.enums import CONFIDENCE_RANK, SEVERITY_RANK, Confidence, Severity
from app.models.monitoring import (
    InfrastructureMonitor,
    MonitoringAlert,
    MonitoringRapidRun,
    MonitoringRun,
)
from app.monitoring import analysis, bots, clients, lb
from app.monitoring.accumulate import day_metrics
from app.monitoring.waf import normalize_waf_event


def create_monitor(
    db: Session,
    *,
    tenant_id: str,
    name: str,
    target_binding: str,
    source_ids: list[str],
    schedule_minutes: int,
    minimum_baseline_days: int,
    schedule_enabled: bool = False,
    retention_days: int = 90,
) -> InfrastructureMonitor:
    monitor = InfrastructureMonitor(
        tenant_id=tenant_id,
        name=name,
        target_binding=target_binding,
        source_ids=source_ids,
        schedule_minutes=schedule_minutes,
        minimum_baseline_days=minimum_baseline_days,
        schedule_enabled=schedule_enabled,
        retention_days=retention_days,
    )
    from app.monitoring.sources import validate_binding

    validate_binding(db, tenant_id, target_binding, source_ids)
    db.add(monitor)
    db.commit()
    db.refresh(monitor)
    return monitor


def get_monitor(db: Session, monitor_id: uuid.UUID, tenant_id: str) -> InfrastructureMonitor | None:
    return db.scalar(
        select(InfrastructureMonitor).where(
            InfrastructureMonitor.id == monitor_id,
            InfrastructureMonitor.tenant_id == tenant_id,
        )
    )


def list_monitors(db: Session, tenant_id: str) -> list[InfrastructureMonitor]:
    return list(
        db.scalars(
            select(InfrastructureMonitor)
            .where(InfrastructureMonitor.tenant_id == tenant_id)
            .order_by(InfrastructureMonitor.created_at.desc())
        )
    )


def prepare_daily_run(
    db: Session, monitor: InfrastructureMonitor, day: date, *, commit: bool = True
) -> MonitoringRun:
    """Create one idempotent daily run; no target traffic is performed."""
    row = db.scalar(
        select(MonitoringRun).where(
            MonitoringRun.monitor_id == monitor.id,
            MonitoringRun.observation_date == day,
        )
    )
    if row is None:
        row = MonitoringRun(monitor_id=monitor.id, observation_date=day)
        db.add(row)
        db.flush()
        if commit:
            db.commit()
            db.refresh(row)
    return row


def mark_awaiting_evidence(db: Session, run: MonitoringRun) -> MonitoringRun:
    """Keep a scheduled day out of the baseline until its source sends data."""
    if run.status in {"queued", "collecting"}:
        run.status = "awaiting_evidence"
        run.data_quality = "missing"
        run.state = "no_data"
        run.finished_at = datetime.now(UTC)
    db.commit()
    db.refresh(run)
    return run


def ingest_waf_records(
    db: Session,
    monitor: InfrastructureMonitor,
    records: list[dict[str, Any]],
    *,
    observation_date: date,
    source_revisions: dict[str, str],
) -> MonitoringRun:
    """Normalize and aggregate a day's records, then compare seven days."""
    run = prepare_daily_run(db, monitor, observation_date)
    if run.status == "complete" and run.source_revisions == source_revisions:
        return run

    salt = _monitoring_salt(monitor.tenant_id)
    normalized = [normalize_waf_event(record, salt=salt) for record in records]
    return ingest_normalized_events(
        db, monitor, normalized, observation_date=observation_date,
        source_revisions=source_revisions,
    )


def ingest_normalized_events(
    db: Session,
    monitor: InfrastructureMonitor,
    normalized: list,
    *,
    observation_date: date,
    source_revisions: dict[str, str],
) -> MonitoringRun:
    return ingest_day_metrics(
        db,
        monitor,
        day_metrics(normalized),
        observation_date=observation_date,
        source_revisions=source_revisions,
    )


def ingest_day_metrics(
    db: Session,
    monitor: InfrastructureMonitor,
    current: dict,
    *,
    observation_date: date,
    source_revisions: dict[str, str],
) -> MonitoringRun:
    """Persist one day's already-folded aggregates, then compare seven days."""
    run = prepare_daily_run(db, monitor, observation_date, commit=False)
    if run.status == "complete" and run.source_revisions == source_revisions:
        return run

    previous = list(
        db.scalars(
            select(MonitoringRun)
            .where(
                MonitoringRun.monitor_id == monitor.id,
                MonitoringRun.observation_date < observation_date,
                MonitoringRun.status == "complete",
            )
            .order_by(MonitoringRun.observation_date.desc())
            .limit(90)
        )
    )
    days = sorted(row.observation_date for row in previous)
    run.status = "complete"
    run.state = "no_data" if not current.get("event_count") else "warming_up"
    run.data_quality = (
        "sufficient" if len(days) >= monitor.minimum_baseline_days else "warming_up"
    )
    run.baseline_days_available = len(days)
    run.baseline_start = days[0] if days else None
    run.baseline_end = days[-1] if days else None
    run.source_revisions = source_revisions
    run.metrics = current
    run.correlations = []
    # Leave the prior observations in place until ``recompute`` replaces them.
    # It uses their stable fingerprints to carry AI explanations across a
    # revised collection of the same day.
    run.started_at = run.started_at or datetime.now(UTC)
    run.finished_at = datetime.now(UTC)
    monitor.last_observation_date = observation_date
    monitor.last_run_at = datetime.now(UTC)
    recompute(db, monitor)
    db.commit()
    db.refresh(run)
    return run


def open_observations(observations: list[dict] | None) -> list[dict]:
    """The ones still asking for a decision; a suppressed lead is an answered one."""
    return [o for o in observations or [] if o.get("disposition") != "suppressed"]


def _rank(observation: dict) -> tuple[int, int, int, int, str]:
    """Worst first: still-open, then severity, proof over leads, baseline over one day.

    Reads the same ranks the scan side sorts by (``app.domain.enums``) so an
    observation and a finding cannot disagree about which of two is worse.
    """
    try:
        severity = SEVERITY_RANK[Severity(str(observation.get("severity")))]
    except ValueError:
        severity = SEVERITY_RANK[Severity.info]
    try:
        confidence = CONFIDENCE_RANK[Confidence(str(observation.get("confidence")))]
    except ValueError:
        confidence = CONFIDENCE_RANK[Confidence.heuristic]
    baseline = 0 if observation.get("basis") == "single_day" else 1
    answered = 1 if observation.get("disposition") == "suppressed" else 0
    return (answered, -severity, -confidence, -baseline, str(observation.get("type", "")))


def sort_observations(observations: list[dict]) -> list[dict]:
    return sorted(observations, key=_rank)


def recompute(db: Session, monitor: InfrastructureMonitor) -> None:
    runs = list(db.scalars(select(MonitoringRun).where(
        MonitoringRun.monitor_id == monitor.id,
    ).order_by(MonitoringRun.observation_date.asc()).limit(90)))
    by_day = {row.observation_date: row for row in runs}
    old_state = runs[-1].state if runs else "no_data"
    protected = bots.protected_routes(monitor.context)
    for row in runs:
        if row.status != "complete":
            continue
        history = []
        for offset in range(1, monitor.minimum_baseline_days + 1):
            prior = by_day.get(row.observation_date - timedelta(days=offset))
            if prior is None or prior.status != "complete" or not prior.metrics.get("event_count"):
                break
            history.append(prior.metrics)
        row.baseline_days_available = len(history)
        row.baseline_start = (
            row.observation_date - timedelta(days=len(history)) if history else None
        )
        row.baseline_end = row.observation_date - timedelta(days=1) if history else None
        explained = {
            o.get("fingerprint"): o["ai_explanation"]
            for o in row.observations or []
            if o.get("ai_explanation")
        }
        has_contract = bool(monitor.context.get("routes"))
        if len(history) < monitor.minimum_baseline_days:
            # Before the baseline exists, show what one day supports on its own.
            observations = analysis.assess_day(
                row.metrics, has_contract=has_contract
            ) + bots.assess_day(row.metrics.get("bots"), protected=protected)
        else:
            observations = analysis.assess(
                row.metrics, history, monitor.minimum_baseline_days,
                has_contract=has_contract,
            ) + bots.assess(
                row.metrics.get("bots"),
                [day.get("bots") or {} for day in history],
                monitor.minimum_baseline_days,
                protected=protected,
            )
        # JA4 thresholds are absolute, so they apply before and after the baseline.
        observations += clients.assess_day(row.metrics.get("clients"))
        # Load balancer hours are judged against the same hours on the earlier days that
        # have metrics; before there are enough, only server errors are.
        observations += lb.assess(
            row.metrics.get("origin"),
            [day.get("origin") for day in history],
            monitor.minimum_baseline_days,
        )
        # An explanation belongs to the issue, so it survives a recomputed day, and a
        # person's triage outranks the detector's hardcoded "candidate" -- the detectors
        # are stateless and re-derive it every recompute, so it has to be re-applied
        # here or suppressing an observation silently does nothing.
        row.observations = sort_observations([
            {
                **o,
                **({"ai_explanation": explained[o["fingerprint"]]}
                   if o["fingerprint"] in explained else {}),
                **({"disposition": monitor.triage[o["fingerprint"]]}
                   if o["fingerprint"] in monitor.triage else {}),
            }
            for o in observations
        ])
        if not row.metrics.get("event_count"):
            row.state, row.data_quality = "no_data", "missing"
        elif len(history) < monitor.minimum_baseline_days:
            row.state, row.data_quality = "warming_up", "warming_up"
        else:
            row.data_quality = "sufficient"
            # Suppressed observations are a person saying "this one is fine here", so a
            # day whose leads are all suppressed is a normal day, not a standing anomaly.
            row.state = "anomaly" if open_observations(row.observations) else "baseline_ready"
    # A failed collection is resolved once that day collects: close its alerts.
    collected = [row.observation_date for row in runs if row.status == "complete"]
    if collected:
        db.execute(
            update(MonitoringAlert)
            .where(
                MonitoringAlert.monitor_id == monitor.id,
                MonitoringAlert.state == "degraded",
                MonitoringAlert.acknowledged.is_(False),
                MonitoringAlert.observation_date.in_(collected),
            )
            .values(acknowledged=True)
        )
    if runs and runs[-1].state != old_state and runs[-1].state in {
        "anomaly", "baseline_ready", "no_data"
    }:
        db.add(MonitoringAlert(
            monitor_id=monitor.id, observation_date=runs[-1].observation_date,
            state=runs[-1].state,
        ))
        from app.notifications.events import (
            monitor_alert_event,
            monitor_recovered_event,
        )

        monitor_alert_event(
            db,
            tenant_slug=monitor.tenant_id,
            monitor_id=monitor.id,
            monitor_name=monitor.name,
            state=runs[-1].state,
            observation_date=runs[-1].observation_date,
        )
        if old_state in {"anomaly", "degraded", "rapid_anomaly"} and runs[-1].state in {
            "baseline_ready", "no_data"
        }:
            monitor_recovered_event(
                db,
                tenant_slug=monitor.tenant_id,
                monitor_id=monitor.id,
                monitor_name=monitor.name,
                observation_date=runs[-1].observation_date,
            )


def expire_evidence(db: Session, monitor: InfrastructureMonitor) -> None:
    cutoff = datetime.now(UTC).date() - timedelta(days=monitor.retention_days)
    db.execute(delete(MonitoringRun).where(
        MonitoringRun.monitor_id == monitor.id,
        MonitoringRun.observation_date < cutoff,
    ))
    db.execute(delete(MonitoringAlert).where(
        MonitoringAlert.monitor_id == monitor.id,
        MonitoringAlert.observation_date < cutoff,
    ))
    db.execute(delete(MonitoringRapidRun).where(
        MonitoringRapidRun.monitor_id == monitor.id,
        MonitoringRapidRun.window_end < datetime.now(UTC) - timedelta(days=monitor.retention_days),
    ))


def _monitoring_salt(tenant_id: str) -> bytes:
    configured = settings.monitoring_hmac_key or settings.vault_key or "dev-only-monitoring-key"
    return hmac.new(
        configured.encode("utf-8"), tenant_id.encode("utf-8"), hashlib.sha256
    ).digest()
