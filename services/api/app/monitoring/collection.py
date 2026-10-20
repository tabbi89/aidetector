"""Daily read-only collection with generation claims and bounded overlap."""

from __future__ import annotations

import logging
import time
import traceback
import uuid
from datetime import UTC, datetime, timedelta

from fastapi import HTTPException
from sqlalchemy import delete, select, update

from app.core.config import settings
from app.core.db import SessionLocal
from app.models.monitoring import (
    EvidenceAudit,
    EvidenceSource,
    InfrastructureMonitor,
    MonitoringAlert,
    MonitoringRun,
)
from app.monitoring import remote, service, sources
from app.monitoring.contracts import ORIGIN_SOURCE_KEY, SourceUnavailable

#: Seconds of the collection task's hard limit kept back for persisting the day after
#: the reads. The limit is ``monitoring_collect_seconds + 120``.
PERSIST_RESERVE = 60
#: Below this, an origin read is not started: it would be cut off before it could finish.
MIN_ORIGIN_SECONDS = 30

log = logging.getLogger(__name__)


def _read_origin(
    origin_id: str,
    tenant_id: str,
    day,
    waf_guard,
    *,
    started: float,
) -> tuple[dict, dict[str, str]]:
    """Read the linked load balancer's metrics; any failure is recorded, never raised.

    The origin read only adds response codes to a WAF day already read, so a missing,
    revoked or unreadable load balancer must cost those and nothing else. A cancel or a changed
    WAF binding is different -- the caller re-checks ``waf_guard`` after this returns,
    so those still end the whole day.
    """
    remaining = (
        started + settings.monitoring_collect_seconds + 120 - PERSIST_RESERVE - time.monotonic()
    )
    with SessionLocal() as db:
        origin = db.get(EvidenceSource, origin_id)
        if (
            origin is None
            or origin.tenant_id != tenant_id
            or origin.status == "revoked"
            or origin.connector != "aws_alb"
        ):
            return {"error": "source_unavailable"}, {}
        revision = origin.revision
        try:
            config, credentials = sources.bound_config(origin), sources.read_credentials(origin)
        except SourceUnavailable as exc:
            return {"error": exc.code}, {origin_id: f"{revision}:error:{exc.code}"}
    if remaining < MIN_ORIGIN_SECONDS:
        return {"error": "no_time_left"}, {origin_id: f"{revision}:error:no_time_left"}

    def guard() -> None:
        waf_guard()
        with SessionLocal() as fresh:
            live = fresh.get(EvidenceSource, origin_id)
            if live is None or live.status == "revoked" or live.revision != revision:
                raise SourceUnavailable("binding_changed")

    try:
        metrics, digest = remote.alb_metrics(
            config,
            credentials,
            day,
            guard,
            seconds=min(settings.monitoring_alb_collect_seconds, remaining),
        )
    except SourceUnavailable as exc:
        log.warning("monitoring origin read failed: %s", exc.code)
        return {"error": exc.code}, {origin_id: f"{revision}:error:{exc.code}"}
    except Exception as exc:  # noqa: BLE001 - a parser bug must not cost the WAF day
        frame = traceback.extract_tb(exc.__traceback__)[-1]
        log.warning(
            "monitoring origin read error: %s at %s:%s",
            type(exc).__name__, frame.filename, frame.lineno,
        )
        return {"error": "source_unavailable"}, {origin_id: f"{revision}:error:source_unavailable"}
    return metrics, {origin_id: f"{revision}:{digest}"}


def collect(monitor_id: str, run_id: str | None = None) -> dict:
    started = time.monotonic()
    with SessionLocal() as db:
        monitor = db.get(InfrastructureMonitor, monitor_id)
        if monitor is None or monitor.status != "active":
            return {"status": "missing_or_paused"}
        run = (
            db.get(MonitoringRun, run_id)
            if run_id
            else service.prepare_daily_run(
                db, monitor, datetime.now(UTC).date() - timedelta(days=1), commit=False
            )
        )
        if run is None or run.monitor_id != monitor.id:
            return {"status": "run_binding_mismatch"}
        run = db.scalar(select(MonitoringRun).where(MonitoringRun.id == run.id).with_for_update())
        assert run is not None
        if run.status != "queued":
            return {"status": run.status, "duplicate": True}
        if not monitor.source_ids:
            service.mark_awaiting_evidence(db, run)
            return {"status": "awaiting_evidence"}
        source = db.get(EvidenceSource, monitor.source_ids[0])
        if source is None or source.status == "revoked" or source.tenant_id != monitor.tenant_id:
            run.status, run.state, run.error_code = "failed", "degraded", "source_unavailable"
            db.commit()
            return {"status": "failed"}
        if source.connector == "json_snapshot":
            service.mark_awaiting_evidence(db, run)
            return {"status": "awaiting_evidence"}
        claim = uuid.uuid4()
        run.claim, run.status, run.started_at = claim, "collecting", datetime.now(UTC)
        run.error_code = None
        source_id, revision, tenant_id, day, run_uuid = (
            source.id,
            source.revision,
            source.tenant_id,
            run.observation_date,
            run.id,
        )
        origin_id = monitor.context.get(ORIGIN_SOURCE_KEY)
        db.commit()
        log.info(
            "monitoring collect started: monitor %s, day %s, run %s", monitor_id, day, run_uuid
        )
        try:
            config, credentials = sources.bound_config(source), sources.read_credentials(source)

            def guard() -> None:
                with SessionLocal() as fresh:
                    live = fresh.get(EvidenceSource, source_id)
                    owner = fresh.get(InfrastructureMonitor, monitor_id)
                    slot = fresh.get(MonitoringRun, run_uuid)
                    if (
                        live is None
                        or live.status == "revoked"
                        or live.revision != revision
                        or live.tenant_id != tenant_id
                        or owner is None
                        or owner.status != "active"
                        or owner.source_ids != [str(source_id)]
                        or live.target_binding != owner.target_binding
                        or slot is None
                        or slot.claim != claim
                        or slot.status != "collecting"
                    ):
                        raise SourceUnavailable("binding_changed")

            def report(snapshot: dict) -> None:
                # Progress lives in metrics until the day completes and replaces it.
                with SessionLocal() as fresh:
                    fresh.execute(
                        update(MonitoringRun)
                        .where(
                            MonitoringRun.id == run_uuid,
                            MonitoringRun.claim == claim,
                            MonitoringRun.status == "collecting",
                        )
                        .values(metrics={"progress": snapshot})
                    )
                    fresh.commit()

            routes = sources.bound_routes(source, monitor)
            guard()
            metrics, event_count, digest = remote.cloudwatch_events(
                config,
                credentials,
                day,
                guard,
                salt=service._monitoring_salt(tenant_id),
                routes=routes,
                progress=report,
            )
            guard()
            origin_revisions: dict[str, str] = {}
            if origin_id:
                metrics["origin"], origin_revisions = _read_origin(
                    str(origin_id), tenant_id, day, guard, started=started
                )
                # A cancel raised inside the origin read was recorded as an origin error;
                # re-checking the WAF binding here is what still ends the whole day.
                guard()
            sources.ingest_metrics(
                db,
                uuid.UUID(monitor_id),
                tenant_id,
                source_id,
                revision,
                day,
                metrics,
                digest,
                expected_claim=claim,
                extra_revisions=origin_revisions,
            )
            log.info("monitoring collect complete: run %s, %d events", run_uuid, event_count)
            return {"status": "complete", "run_id": str(run_uuid)}
        except (SourceUnavailable, HTTPException) as exc:
            code = exc.code if isinstance(exc, SourceUnavailable) else "binding_changed"
        except Exception as exc:
            # Provider/parse errors never surface raw source data or credentials:
            # log the exception type and where it was raised, never its message.
            code = "source_unavailable"
            frame = traceback.extract_tb(exc.__traceback__)[-1]
            log.warning(
                "monitoring collect error: %s at %s:%s",
                type(exc).__name__,
                frame.filename,
                frame.lineno,
            )
        log.warning("monitoring collect failed: run %s, %s", run_uuid, code)
        db.rollback()
        # Re-read the row: a cancel may have released the claim while the cached
        # instance still holds it, and a cancel must not be overwritten.
        slot = db.scalar(
            select(MonitoringRun)
            .where(MonitoringRun.id == run_uuid)
            .with_for_update()
            .execution_options(populate_existing=True)
        )
        if slot is not None and slot.claim == claim and slot.status == "collecting":
            slot.claim, slot.status, slot.state = None, "failed", "degraded"
            slot.error_code, slot.finished_at = code, datetime.now(UTC)
            # One open alert per failing day: retries must not stack duplicates.
            open_alert = db.scalar(
                select(MonitoringAlert.id)
                .where(
                    MonitoringAlert.monitor_id == slot.monitor_id,
                    MonitoringAlert.observation_date == day,
                    MonitoringAlert.state == "degraded",
                    MonitoringAlert.acknowledged.is_(False),
                )
                .limit(1)
            )
            if open_alert is None:
                db.add(
                    MonitoringAlert(
                        monitor_id=slot.monitor_id, observation_date=day, state="degraded"
                    )
                )
                from app.notifications.events import monitor_alert_event

                monitor = db.get(InfrastructureMonitor, slot.monitor_id)
                if monitor is not None:
                    monitor_alert_event(
                        db,
                        tenant_slug=monitor.tenant_id,
                        monitor_id=monitor.id,
                        monitor_name=monitor.name,
                        state="degraded",
                        observation_date=day,
                    )
            live = db.get(EvidenceSource, source_id)
            if live and live.status != "revoked" and live.revision == revision:
                live.status, live.error_code = "unavailable", code
                sources.audit(db, live, "collect", code)
            db.commit()
        return {"status": "failed", "error_code": code}


def dispatch(enqueue) -> dict:
    now = datetime.now(UTC)
    jobs = []
    with SessionLocal() as db:
        for monitor in db.scalars(select(InfrastructureMonitor)):
            service.expire_evidence(db, monitor)
            if monitor.status != "active" or not monitor.schedule_enabled or now.hour < 2:
                continue
            # Rebuild a three-day overlap once per UTC day for delayed delivery.
            for offset in (3, 2, 1):
                day = now.date() - timedelta(days=offset)
                run = service.prepare_daily_run(db, monitor, day, commit=False)
                if run.status == "collecting":
                    stale_after = settings.monitoring_collect_seconds + 180
                    if run.started_at and (now - run.started_at).total_seconds() > stale_after:
                        run.status, run.claim, run.state = "failed", None, "degraded"
                        run.error_code = "worker_timeout"
                    else:
                        continue
                if run.finished_at and run.finished_at.date() == now.date():
                    continue
                run.status, run.claim, run.error_code = "queued", None, None
                jobs.append((str(monitor.id), str(run.id)))
        db.execute(delete(EvidenceAudit).where(EvidenceAudit.created_at < now - timedelta(days=90)))
        db.commit()
    dispatched = []
    for monitor_id, run_id in jobs:
        try:
            enqueue(monitor_id, run_id)
            dispatched.append(run_id)
        except Exception:
            # Leave the slot queued: the next hourly dispatch retries it.
            continue
    return {"dispatched": dispatched}
