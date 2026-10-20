"""Celery tasks — background scan execution, scheduled dispatch, stale-scan reaping."""

from __future__ import annotations

import logging
import threading
import uuid
from datetime import UTC, datetime
from types import TracebackType
from typing import Any

from sqlalchemy import update

from app.core.config import settings
from app.core.db import SessionLocal
from app.engine.runner import run_scan
from app.models.scan import Scan, ScanStatus
from app.scans.reaper import StaleLimits, reap_stale
from app.scans.run_options import RunOptions
from app.scans.scheduler import dispatch_due
from app.workers.celery_app import celery

log = logging.getLogger("aidetector.tasks")


def stamp_heartbeat(scan_id: uuid.UUID) -> None:
    """Record that a worker is still running this scan. Never raises."""
    db = SessionLocal()
    try:
        db.execute(
            update(Scan)
            .where(Scan.id == scan_id, Scan.status == ScanStatus.running)
            .values(heartbeat_at=datetime.now(UTC))
        )
        db.commit()
    except Exception:  # noqa: BLE001 — a missed beat must never fail a scan
        log.warning("heartbeat for scan %s failed", scan_id, exc_info=True)
        db.rollback()
    finally:
        db.close()


class Heartbeat:
    """Stamp ``Scan.heartbeat_at`` on a timer while a run executes.

    A thread with its own session rather than a stamp on every journal event: an
    adjunct or AI stage can run for many minutes without emitting one, and a
    live-but-quiet run must not look like a dead worker. When the process dies
    the thread dies with it — which is exactly the signal the reaper reads.
    """

    def __init__(self, scan_id: uuid.UUID, interval: float) -> None:
        self._scan_id = scan_id
        self._interval = interval
        self._stop = threading.Event()
        self._thread = threading.Thread(target=self._beat, name="aidetector-heartbeat", daemon=True)

    def _beat(self) -> None:
        while not self._stop.wait(self._interval):
            stamp_heartbeat(self._scan_id)

    def __enter__(self) -> Heartbeat:
        self._thread.start()
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> None:
        self._stop.set()
        self._thread.join(timeout=self._interval + 5)


@celery.task(
    name="run_scan",
    # Hard limit only. A soft limit raises SoftTimeLimitExceeded, an Exception
    # the runner's per-check and per-stage isolation would swallow: the run
    # would carry on, possibly with a cleanup abandoned mid-way. The hard limit
    # kills the process instead, and the reaper marks the scan failed.
    time_limit=settings.scan_time_limit_seconds,
)
def run_scan_task(scan_id: str, options: dict | None = None) -> dict:
    """Load a scan in its own session and run the engine against it.

    ``options`` arrives as a plain dict because it crosses the queue as JSON;
    ``RunOptions.from_dict`` drops any flag this worker version doesn't know, so
    a message enqueued by a newer API doesn't crash an older worker.
    """
    db = SessionLocal()
    opts = RunOptions.from_dict(options)
    # Where the settings came from rides in the options dict (see the run route)
    # and is not an option: from_dict has already dropped it from ``opts``.
    config_source = (options or {}).get("config_source")
    if not isinstance(config_source, dict):
        config_source = None
    claimed = None
    try:
        scan = db.get(Scan, scan_id)
        if scan is None:
            log.warning("run_scan_task: scan %s not found", scan_id)
            return {"scan_id": scan_id, "status": "missing"}
        # Queue delivery can be duplicated. Claim the queued row atomically
        # before any target traffic; a second worker must not start another run.
        claimed = db.execute(
            update(Scan)
            .where(Scan.id == scan.id, Scan.status == ScanStatus.queued)
            .values(
                status=ScanStatus.running,
                heartbeat_at=datetime.now(UTC),
                claimed_at=datetime.now(UTC),
            )
            .returning(Scan.id)
        ).scalar_one_or_none()
        db.commit()
        db.refresh(scan)
        if claimed is None:
            return {"scan_id": scan_id, "status": scan.status.value, "duplicate": True}
        # Only a CLI run from a project file carries a source; a web or
        # scheduled run keeps the original call.
        extra: dict[str, Any] = {"config_source": config_source} if config_source else {}
        with Heartbeat(scan.id, settings.scan_heartbeat_seconds):
            findings = run_scan(db, scan, options=opts, **extra)
        from app.notifications.events import completed_run_events

        latest_run = max(scan.runs, key=lambda item: item.run_number, default=None)
        if latest_run is not None:
            completed_run_events(db, scan, latest_run)
            db.commit()
        return {
            "scan_id": scan_id,
            "status": scan.status.value,
            "findings": len(findings),
        }
    except Exception as exc:
        log.exception("run_scan_task failed for %s", scan_id)
        db.rollback()
        scan = db.get(Scan, scan_id)
        if scan is not None and claimed is not None:
            scan.status = ScanStatus.failed
            # A failure before the run journal opened (credential resolution,
            # transport setup) has recorded nothing yet; say why here.
            if scan.failure_reason is None:
                from app.models.event import ScanEvent
                from app.scans.journal import describe_failure

                scan.failure_reason = describe_failure(exc)
                scan.events.append(ScanEvent(
                    stage="error", pct=scan.progress,
                    message=f"scan failed before it started — {scan.failure_reason}",
                ))
            from app.notifications.events import run_failed_event

            run_failed_event(db, scan)
            db.commit()
        raise
    finally:
        db.close()


@celery.task(name="dispatch_scheduled_scans")
def dispatch_scheduled_scans() -> dict:
    """Celery-beat task: enqueue any scans whose schedule is due."""
    db = SessionLocal()
    try:
        ids = dispatch_due(
            db,
            datetime.now(UTC),
            lambda scan_id, options: run_scan_task.delay(scan_id, options=options),
        )
        if ids:
            log.info("dispatched %d scheduled scans", len(ids))
        return {"dispatched": ids}
    finally:
        db.close()


@celery.task(name="prune_auth_throttle")
def prune_auth_throttle() -> dict:
    """Celery-beat task: delete sign-in/sign-up counters whose window closed."""
    from app.scans import throttle

    db = SessionLocal()
    try:
        pruned = throttle.prune(db)
        db.commit()
        return {"pruned": pruned}
    finally:
        db.close()


@celery.task(name="reap_stale_scans")
def reap_stale_scans() -> dict:
    """Celery-beat task: fail scans whose worker died or never picked them up."""
    db = SessionLocal()
    try:
        ids = reap_stale(
            db,
            datetime.now(UTC),
            StaleLimits(
                running_seconds=settings.scan_stale_seconds,
                queued_seconds=settings.scan_queued_stale_seconds,
            ),
        )
        if ids:
            log.warning("reaped %d stale scans: %s", len(ids), ids)
        return {"reaped": ids}
    finally:
        db.close()


@celery.task(name="deliver_notifications")
def deliver_notifications() -> dict:
    """Celery-beat task: drain due webhook/Slack deliveries."""
    from app.notifications.dispatch import dispatch_pending

    db = SessionLocal()
    try:
        return dispatch_pending(db)
    finally:
        db.close()


@celery.task(name="dispatch_overdue_work")
def dispatch_overdue_work() -> dict:
    """Celery-beat task: enqueue one event per overdue work item per due date."""
    from app.notifications.events import work_overdue_events

    db = SessionLocal()
    try:
        queued = work_overdue_events(db)
        db.commit()
        return {"queued": queued}
    finally:
        db.close()


@celery.task(name="run_monitoring", time_limit=settings.monitoring_collect_seconds + 120)
def run_monitoring_task(monitor_id: str, run_id: str | None = None) -> dict:
    from app.monitoring.collection import collect

    return collect(monitor_id, run_id)


@celery.task(name="dispatch_daily_monitoring")
def dispatch_daily_monitoring() -> dict:
    from app.monitoring.collection import dispatch

    return dispatch(run_monitoring_task.delay)


@celery.task(
    name="run_rapid_monitoring", time_limit=settings.monitoring_rapid_collect_seconds + 60
)
def run_rapid_monitoring_task(monitor_id: str, window_end: str | None = None) -> dict:
    from app.monitoring.rapid_service import collect_recent

    return collect_recent(monitor_id, window_end)


@celery.task(name="dispatch_rapid_monitoring")
def dispatch_rapid_monitoring() -> dict:
    from app.monitoring.rapid_service import dispatch

    # A message older than one interval belongs to a window a newer tick has taken.
    return dispatch(lambda monitor_id, window_end: run_rapid_monitoring_task.apply_async(
        (monitor_id, window_end), expires=settings.monitoring_rapid_interval_seconds,
    ))


@celery.task(
    name="explain_monitoring_observation",
    time_limit=settings.monitoring_ai_timeout_seconds + 60,
)
def explain_monitoring_observation(monitor_id: str, run_id: str, fingerprint: str) -> dict:
    from app.monitoring.explain import run_explanation

    return run_explanation(monitor_id, run_id, fingerprint)


@celery.task(
    name="brief_monitoring_traffic",
    time_limit=settings.monitoring_ai_timeout_seconds + 60,
)
def brief_monitoring_traffic(monitor_id: str) -> dict:
    from app.monitoring.briefing import run_briefing

    return run_briefing(monitor_id)


class _AnalysisJournal:
    """The slice of a run journal the post-upload AI passes use.

    The scan is still ``running`` while a local run is analysed, so no other run
    can open over it and events go straight onto its log.
    """

    def __init__(self, db: Any, scan: Scan, run: Any) -> None:
        self.db, self.scan, self.run_row = db, scan, run

    def event(self, stage: str, pct: int, message: str) -> None:
        from app.models.event import ScanEvent

        self.scan.events.append(ScanEvent(stage=stage, pct=pct, message=message))
        self.db.commit()

    def cancelled(self) -> bool:
        return False


@celery.task(
    name="analyze_local_run",
    # Both AI passes at their own timeout, plus the database work around them.
    time_limit=2 * settings.ai_timeout_seconds + 120,
)
def analyze_local_run(run_id: str) -> dict:
    """The AI passes a local run asked for, then its completion.

    Adjudication judges the uploaded findings and the security design review
    reads the spec and schema snapshot; neither sends target traffic, so both
    run here, where the AI budget and ledger are. Every AI failure degrades to
    an event, and the run completes either way (``app/scans/local_runs``).
    """
    from types import SimpleNamespace

    from app.db_schema.snapshots import latest_snapshot
    from app.engine import ai_phases
    from app.engine.security_review import review_security_design
    from app.models.scan import ScanRun
    from app.scans import local_runs
    from app.scans.workspace import is_premium
    from app.specs.parser import load_spec

    db = SessionLocal()
    try:
        run = db.get(ScanRun, run_id)
        if run is None or (run.executor or {}).get("kind") != "local_runner":
            return {"run_id": run_id, "status": "missing"}
        # Only the analysis the upload queued: a redelivered message must not
        # spend the budget twice or reopen a finished run.
        if run.status != local_runs.ANALYSING:
            return {"run_id": run_id, "status": "duplicate"}
        scan = run.scan
        options = run.options or {}
        journal = _AnalysisJournal(db, scan, run)
        with Heartbeat(scan.id, settings.scan_heartbeat_seconds):
            if options.get("adjudicate"):
                try:
                    ai_phases.adjudicate_findings(
                        db, scan, None, journal.event, premium=bool(options.get("premium"))
                    )
                except Exception:  # noqa: BLE001 — never fail a run on AI problems
                    log.exception("adjudication failed for local run %s", run_id)
                    journal.event("ai_skipped", scan.progress, "AI adjudication unavailable")
                db.commit()
            if options.get("security_review"):
                spec = None
                if scan.spec_text:
                    try:
                        spec = load_spec(scan.spec_text)
                    except Exception:  # noqa: BLE001 — an unparsable spec is "no spec"
                        spec = None
                # Schema context is a premium input, as it is on a server run.
                snap = latest_snapshot(db, scan.id) if is_premium(db, scan.tenant_id) else None
                ctx = SimpleNamespace(
                    spec=spec, redact=None, schema_context=snap.context if snap else None
                )
                try:
                    review_security_design(ctx, journal)
                except Exception:  # noqa: BLE001
                    log.exception("security review failed for local run %s", run_id)
                db.commit()
            local_runs.finish_local_run(db, scan, run)
            db.commit()
        return {"run_id": run_id, "status": run.status}
    finally:
        db.close()
