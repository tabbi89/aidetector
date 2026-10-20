"""Persist short-window findings, never the source records that produced them.

Two producers feed the same evaluation: a trusted pipeline posting a complete hour
(``ingest``), and the scheduled reader that pulls the last hour of an enabled
monitor's CloudWatch WAF log group itself (``collect_recent``).
"""

from __future__ import annotations

import logging
import traceback
import uuid
from collections import Counter
from collections.abc import Callable, Sequence
from datetime import UTC, datetime, timedelta
from typing import TYPE_CHECKING, Any, cast

from fastapi import HTTPException
from sqlalchemy import select
from sqlalchemy.dialects.postgresql import insert
from sqlalchemy.engine import CursorResult
from sqlalchemy.orm import Session

from app.core.config import settings
from app.core.db import SessionLocal
from app.models.monitoring import (
    EvidenceSource,
    InfrastructureMonitor,
    MonitoringAlert,
    MonitoringRapidRun,
    MonitoringRun,
)
from app.monitoring import demo, remote, sources
from app.monitoring.contracts import RouteBinding, SourceConfig, SourceUnavailable
from app.monitoring.rapid import (
    ApplicationSignal,
    assess_application,
    assess_waf,
    deduplicate_app,
)
from app.monitoring.routes import BASELINE_WINDOW
from app.monitoring.service import _monitoring_salt
from app.monitoring.waf import NormalizedWafEvent, normalize_waf_event

if TYPE_CHECKING:
    from app.api.schemas import MonitoringRapidIngest

log = logging.getLogger(__name__)

WINDOW = timedelta(hours=1)
PULSE_WINDOW = timedelta(minutes=5)


def pulse_summary(
    waf: Sequence[NormalizedWafEvent],
    application: Sequence[ApplicationSignal],
    *,
    end: datetime,
    explicit_contract: bool,
) -> dict:
    """Aggregate the final five minutes without retaining request values or identities."""
    start = end - PULSE_WINDOW
    recent_waf = [event for event in waf if start <= event.observed_at <= end]
    recent_application = [
        event for event in application if start <= event.occurred_at.astimezone(UTC) <= end
    ]
    actions = Counter(event.action.upper() for event in recent_waf)
    attacks = [event for event in recent_waf if event.attack_labels]
    labels = Counter(label for event in attacks for label in event.attack_labels)
    routes = Counter(f"{event.method} {event.route_family}" for event in recent_waf)
    clients = {event.source_ip_hash for event in recent_waf if event.source_ip_hash}
    bot_rows = [event for event in recent_waf if event.bot_category or event.bot_name]
    return {
        "minutes": 5,
        "requests": len(recent_waf),
        "allowed": actions["ALLOW"],
        "blocked": actions["BLOCK"] + actions["BLOCKED"],
        "challenged": actions["CAPTCHA"] + actions["CHALLENGE"],
        "counted": actions["COUNT"],
        "other_actions": len(recent_waf) - sum(actions[action] for action in (
            "ALLOW", "BLOCK", "BLOCKED", "CAPTCHA", "CHALLENGE", "COUNT",
        )),
        "attack_requests": len(attacks),
        "attack_allowed": sum(event.action.upper() == "ALLOW" for event in attacks),
        "off_spec_requests": (
            sum(event.route_mapping != "declared" for event in recent_waf)
            if explicit_contract else None
        ),
        "distinct_routes": len(routes),
        "distinct_clients": len(clients),
        "bot_requests": len(bot_rows),
        "unverified_bot_requests": sum(
            event.bot_verification != "verified" for event in bot_rows
        ),
        "application_events": len(recent_application),
        "top_attack_labels": [
            {"label": label, "requests": count}
            for label, count in sorted(labels.items(), key=lambda item: (-item[1], item[0]))[:5]
        ],
        "top_routes": [
            {"route": route, "requests": count}
            for route, count in sorted(routes.items(), key=lambda item: (-item[1], item[0]))[:5]
        ],
    }


def _routes(db: Session, monitor: InfrastructureMonitor) -> list[RouteBinding]:
    """The same route vocabulary the daily reader maps with, so families compare."""
    source = db.get(EvidenceSource, monitor.source_ids[0]) if monitor.source_ids else None
    if source is not None and source.tenant_id == monitor.tenant_id:
        return sources.bound_routes(source, monitor)
    return [RouteBinding.model_validate(route) for route in monitor.context.get("routes", [])]


def known_routes(
    db: Session, monitor: InfrastructureMonitor, before: datetime
) -> frozenset[str] | None:
    """Route families the daily baseline has seen, or None while it is warming up."""
    runs = db.scalars(select(MonitoringRun).where(
        MonitoringRun.monitor_id == monitor.id,
        MonitoringRun.status == "complete",
        MonitoringRun.observation_date < before.date(),
    ).order_by(MonitoringRun.observation_date.desc()).limit(BASELINE_WINDOW)).all()
    days = [
        run.metrics["routes"] for run in runs
        if isinstance(run.metrics.get("routes"), dict) and run.metrics.get("event_count")
    ]
    if len(days) < monitor.minimum_baseline_days:
        return None
    return frozenset(route for day in days for route in day)


def evaluate(
    db: Session,
    monitor: InfrastructureMonitor,
    start: datetime,
    end: datetime,
    waf: Sequence[NormalizedWafEvent],
    application: Sequence[ApplicationSignal] = (),
    *,
    coverage: str | None = None,
) -> MonitoringRapidRun:
    """Score one window and store its observations; a stored window is returned as is."""
    existing = _window(db, monitor, start, end)
    if existing is not None:
        return existing
    explicit = monitor.context.get("openapi_explicit") is True
    known = None if explicit else known_routes(db, monitor, end)
    salt = _monitoring_salt(monitor.tenant_id)
    observations = assess_waf(
        waf, end=end, explicit_contract=explicit, known_routes=known,
    ) + assess_application(application, end=end, salt=salt)
    observations = [
        {**item, "disposition": monitor.triage.get(item["fingerprint"], "candidate")}
        for item in observations
    ]
    skipped: dict[str, str] = {}
    if not explicit:
        skipped["path_discovery"] = "explicit Swagger/OpenAPI contract not provided"
        if known is None:
            skipped["slow_recon"] = (
                f"no contract, and fewer than {monitor.minimum_baseline_days} "
                "complete daily runs to learn known routes from"
            )
    if coverage:
        # A cut-short or unreadable window is not a quiet one.
        skipped["coverage"] = coverage
    prior = db.scalars(select(MonitoringRapidRun).where(
        MonitoringRapidRun.monitor_id == monitor.id,
        MonitoringRapidRun.window_end > end - WINDOW,
        MonitoringRapidRun.window_end < end,
    )).all()
    # Windows overlap; a lead already raised within the last hour updates in the
    # table but does not alert again.
    already = {observation.get("fingerprint") for run in prior for observation in run.observations}
    new_alerts = [
        observation for observation in observations
        if observation["fingerprint"] not in already
        and observation["disposition"] != "suppressed"
    ]
    statement = insert(MonitoringRapidRun).values(
        monitor_id=monitor.id, window_start=start, window_end=end,
        observations=observations, skipped=skipped,
        pulse=pulse_summary(
            waf, application, end=end, explicit_contract=explicit,
        ),
        waf_count=len(waf), application_count=len(application),
    ).on_conflict_do_nothing(constraint="uq_monitoring_rapid_window")
    inserted = cast(CursorResult[Any], db.execute(statement)).rowcount
    if inserted and new_alerts:
        db.add(MonitoringAlert(
            monitor_id=monitor.id, observation_date=end.date(), state="rapid_anomaly",
        ))
        from app.notifications.events import monitor_alert_event

        monitor_alert_event(
            db,
            tenant_slug=monitor.tenant_id,
            monitor_id=monitor.id,
            monitor_name=monitor.name,
            state="rapid_anomaly",
            observation_date=end.date(),
        )
    db.commit()
    result = _window(db, monitor, start, end)
    assert result is not None
    return result


def _window(
    db: Session, monitor: InfrastructureMonitor, start: datetime, end: datetime
) -> MonitoringRapidRun | None:
    return db.scalar(select(MonitoringRapidRun).where(
        MonitoringRapidRun.monitor_id == monitor.id,
        MonitoringRapidRun.window_start == start,
        MonitoringRapidRun.window_end == end,
    ))


def ingest(
    db: Session, monitor: InfrastructureMonitor, body: MonitoringRapidIngest
) -> MonitoringRapidRun:
    """Accept one complete UTC hour; repeated delivery of a window is idempotent."""
    now = datetime.now(UTC)
    start, end = body.window_start, body.window_end
    if (
        start.tzinfo is None or end.tzinfo is None
        or start.utcoffset() is None or end.utcoffset() is None
        or end - start != WINDOW
        or end > now + timedelta(seconds=30)
        or end < now - timedelta(minutes=15)
    ):
        raise HTTPException(422, "submit a complete recent one-hour UTC window")
    if monitor.status != "active":
        raise HTTPException(409, "monitor is paused")
    start, end = start.astimezone(UTC), end.astimezone(UTC)
    existing = _window(db, monitor, start, end)
    if existing is not None:
        return existing

    salt = _monitoring_salt(monitor.tenant_id)
    routes = _routes(db, monitor)
    waf = []
    seen: set[str] = set()
    for record in body.waf_records:
        try:
            event = normalize_waf_event(record, salt=salt, routes=routes)
        except (ValueError, TypeError, OverflowError, OSError):
            raise HTTPException(422, "invalid WAF record") from None
        if not start <= event.observed_at <= end:
            raise HTTPException(422, "WAF record outside window")
        if event.request_id_hash and event.request_id_hash in seen:
            continue
        if event.request_id_hash:
            seen.add(event.request_id_hash)
        waf.append(event)
    application = deduplicate_app(body.application_events)
    if any(not start <= event.occurred_at.astimezone(UTC) <= end for event in application):
        raise HTTPException(422, "application event outside window")
    return evaluate(db, monitor, start, end, waf, application)


def current_window(now: datetime | None = None) -> tuple[datetime, datetime]:
    """The newest complete hour, aligned to the evaluation interval.

    It ends ``monitoring_rapid_lag_seconds`` back so late WAF delivery has landed,
    and on an interval boundary so every worker picks the same window.
    """
    now = now or datetime.now(UTC)
    step = max(60, settings.monitoring_rapid_interval_seconds)
    lagged = int((now - timedelta(seconds=settings.monitoring_rapid_lag_seconds)).timestamp())
    end = datetime.fromtimestamp(lagged - lagged % step, UTC)
    return end - WINDOW, end


def collect_recent(
    monitor_id: str, window_end: str | None = None, now: datetime | None = None
) -> dict:
    """Read and score one complete hour of an enabled monitor's WAF log group.

    ``window_end`` is the window the dispatcher chose. A message that waited in the
    queue past its window is dropped: a newer tick owns the newer hour, and reading
    both would spend the account's FilterLogEvents quota twice.
    """
    start, end = current_window(now)
    if window_end is not None and datetime.fromisoformat(window_end) != end:
        return {"status": "stale"}
    with SessionLocal() as db:
        monitor = db.get(InfrastructureMonitor, uuid.UUID(monitor_id))
        if monitor is None or monitor.status != "active" or not monitor.rapid_enabled:
            return {"status": "disabled"}
        if _window(db, monitor, start, end) is not None:
            return {"status": "duplicate"}
        source = db.get(EvidenceSource, monitor.source_ids[0]) if monitor.source_ids else None
        if (
            settings.env == "dev"
            and monitor.name == demo.MONITOR_NAME
            and monitor.target_binding == demo.TARGET
            and source is not None
            and source.tenant_id == monitor.tenant_id
            and source.connector == "json_snapshot"
        ):
            salt, routes = _monitoring_salt(monitor.tenant_id), _routes(db, monitor)
            demo_waf = [
                normalize_waf_event(record, salt=salt, routes=routes)
                for record in demo.rapid_records(end, attack=True)
            ]
            run = evaluate(db, monitor, start, end, demo_waf)
            return {"status": "complete", "run_id": str(run.id)}
        if (
            source is None
            or source.tenant_id != monitor.tenant_id
            or source.connector != "aws_cloudwatch"
        ):
            return {"status": "no_cloudwatch_source"}
        waf: list[NormalizedWafEvent] = []
        coverage: str | None = None
        monitor_uuid, tenant_id, target = monitor.id, monitor.tenant_id, monitor.target_binding
        source_id, revision, revoked = source.id, source.revision, source.status == "revoked"
        salt, routes = _monitoring_salt(tenant_id), _routes(db, monitor)
        config: SourceConfig | None = None
        credentials: dict = {}
        try:
            config, credentials = sources.bound_config(source), sources.read_credentials(source)
        except SourceUnavailable as exc:
            coverage = f"unavailable: {exc.code}"
        # Nothing is held open across a read that can take minutes.
        db.commit()

        def guard() -> None:
            with SessionLocal() as fresh:
                live = fresh.get(EvidenceSource, source_id)
                owner = fresh.get(InfrastructureMonitor, monitor_uuid)
                if (
                    live is None or live.status == "revoked" or live.revision != revision
                    or live.tenant_id != tenant_id or live.target_binding != target
                    or owner is None or owner.status != "active" or not owner.rapid_enabled
                    or owner.source_ids != [str(source_id)]
                    or owner.target_binding != target
                ):
                    raise SourceUnavailable("binding_changed")

        if revoked:
            coverage = "unavailable: source_unavailable"
        elif config is not None:
            try:
                waf, incomplete = remote.cloudwatch_window(
                    config, credentials, start, end, guard, salt=salt, routes=routes,
                )
                coverage = f"incomplete: {incomplete}" if incomplete else None
            except SourceUnavailable as exc:
                if exc.code == "binding_changed":
                    return {"status": "binding_changed"}
                waf, coverage = [], f"unavailable: {exc.code}"
            except Exception as exc:  # noqa: BLE001 - never surface raw log data
                frame = traceback.extract_tb(exc.__traceback__)[-1]
                log.warning(
                    "rapid monitoring read error: %s at %s:%s",
                    type(exc).__name__, frame.filename, frame.lineno,
                )
                waf, coverage = [], "unavailable: source_unavailable"
        if not revoked:
            try:
                guard()  # paused, opted out or rebound while the read ran
            except SourceUnavailable:
                return {"status": "binding_changed"}
        fresh_monitor = db.get(InfrastructureMonitor, monitor_uuid)
        if fresh_monitor is None:
            return {"status": "disabled"}
        run = evaluate(db, fresh_monitor, start, end, waf, coverage=coverage)
        log.info(
            "rapid monitoring window %s-%s: %d events, %d observations%s",
            start, end, run.waf_count, len(run.observations),
            f" ({coverage})" if coverage else "",
        )
        return {"status": "complete", "run_id": str(run.id)}


def dispatch(enqueue: Callable[[str, str], object], now: datetime | None = None) -> dict:
    """Enqueue every active, opted-in monitor whose newest window is not stored yet."""
    start, end = current_window(now)
    with SessionLocal() as db:
        ids = [
            str(monitor.id)
            for monitor in db.scalars(select(InfrastructureMonitor).where(
                InfrastructureMonitor.status == "active",
                InfrastructureMonitor.rapid_enabled.is_(True),
            ))
            if _window(db, monitor, start, end) is None
        ]
    dispatched = []
    for monitor_id in ids:
        try:
            enqueue(monitor_id, end.isoformat())
            dispatched.append(monitor_id)
        except Exception:  # noqa: BLE001 - the next tick retries
            continue
    return {"dispatched": dispatched}
