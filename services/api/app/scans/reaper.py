"""Recovering scans whose worker is gone.

Every guard in the API refuses to touch an active scan: edits and deletes 409,
a re-run 409s, and the scheduler skips it. That is right while a worker is
writing to the rows — and a trap when the worker has died. A process killed
mid-scan (OOM, deploy, hard time limit) leaves ``running`` behind with nobody
left to change it, and a broker that loses a message leaves ``queued`` behind
the same way. Cancelling only sets a flag no worker will read.

``Scan.heartbeat_at`` is the clock. It is stamped at queue time, at claim, and
on a timer while the task runs (``app/workers/tasks.py``). A scan whose stamp is
older than its limit is marked ``failed`` with an event saying why, which
returns it to a state every guard accepts.

Rows are locked ``SKIP LOCKED``: a worker claiming the same queued scan either
wins before the reaper looks or re-reads the row as ``failed`` and stands down.
"""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta

from sqlalchemy import and_, or_, select
from sqlalchemy.orm import Session

from app.models.event import ScanEvent
from app.models.scan import Scan, ScanStatus


@dataclass(frozen=True)
class StaleLimits:
    """How long each active state may go without a heartbeat."""

    running_seconds: int
    queued_seconds: int


def stale_scans(db: Session, now: datetime, limits: StaleLimits) -> list[Scan]:
    running_cutoff = now - timedelta(seconds=limits.running_seconds)
    queued_cutoff = now - timedelta(seconds=limits.queued_seconds)
    stmt = (
        select(Scan)
        .where(
            or_(
                and_(
                    Scan.status == ScanStatus.running,
                    or_(Scan.heartbeat_at.is_(None), Scan.heartbeat_at < running_cutoff),
                ),
                and_(
                    Scan.status == ScanStatus.queued,
                    or_(Scan.heartbeat_at.is_(None), Scan.heartbeat_at < queued_cutoff),
                ),
            )
        )
        .with_for_update(skip_locked=True)
    )
    return list(db.execute(stmt).scalars().all())


def reap_stale(db: Session, now: datetime, limits: StaleLimits) -> list[str]:
    """Fail every scan whose worker has gone quiet or never started. Returns ids."""
    reaped: list[str] = []
    for scan in stale_scans(db, now, limits):
        # A local run that uploaded its findings and then lost its AI-analysis
        # worker has a complete result already; finish it rather than failing the
        # scan. The lingering security review settles to unavailable on read.
        analysing = next((r for r in scan.runs if r.status == "analysing"), None)
        if analysing is not None:
            from app.scans.local_runs import finish_local_run

            analysing.run_token_hash = None
            scan.events.append(ScanEvent(
                stage="ai_skipped",
                pct=scan.progress,
                message=(
                    f"the AI analysis stopped reporting for over {limits.running_seconds}s; "
                    "the run was completed with its uploaded findings, without AI verdicts"
                ),
            ))
            finish_local_run(db, scan, analysing)
            reaped.append(str(scan.id))
            continue
        was_running = scan.status == ScanStatus.running
        scan.status = ScanStatus.failed
        scan.cancel_requested = False
        # Close the history row the dead executor opened, so the run list does
        # not show a run that is still going. A local run is driven from the CLI
        # machine, which has no Celery hard time limit — the heartbeat is the
        # only thing that would ever notice it died, so the reaper is that run's
        # sole backstop.
        local_run_lost = False
        for run in scan.runs:
            if run.status == "running":
                run.status = "failed"
                run.finished_at = now
                # A dead run's per-run token must never authenticate a late
                # upload that would resurrect the scan.
                run.run_token_hash = None
                if (run.executor or {}).get("kind") == "local_runner":
                    local_run_lost = True
        if was_running:
            stage = "worker_lost"
            who = "the local runner" if local_run_lost else "the worker"
            message = (
                f"{who} stopped reporting for over {limits.running_seconds}s "
                "(crashed, killed, or hit its time limit); the scan was marked failed. "
                "Anything it created on the target may not have been cleaned up."
            )
        else:
            stage = "queue_lost"
            message = (
                f"no worker picked the scan up within {limits.queued_seconds}s "
                "(was the queue message lost?); the scan was marked failed"
            )
        scan.failure_reason = message
        scan.events.append(ScanEvent(stage=stage, pct=scan.progress, message=message))
        from app.notifications.events import run_failed_event

        run_failed_event(db, scan)
        reaped.append(str(scan.id))
    db.commit()
    return reaped
