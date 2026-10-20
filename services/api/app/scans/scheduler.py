"""Recurring-scan dispatch.

A scan with a schedule re-runs every `schedule_minutes`. `dispatch_due` finds
scans whose `next_run_at` has passed, advances the next run, and enqueues each —
via an injected callable so it is testable without Celery.

A schedule is a standing run request, so it carries the options it was
authorized with (``Scan.schedule_options``) and every scheduled run uses exactly
those. The one thing re-decided at dispatch is entitlement: a tenant that has
since lost the premium tier gets its premium passes dropped rather than a run it
is no longer entitled to.
"""
from __future__ import annotations

import logging
from collections.abc import Callable
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models.scan import Scan, ScanStatus
from app.scans import workspace
from app.scans.run_options import RunOptions

# A scan already queued/running is skipped so schedules don't stack up.
_BUSY = {ScanStatus.queued, ScanStatus.running}

log = logging.getLogger("aidetector.scheduler")


def due_scans(db: Session, now: datetime) -> list[Scan]:
    stmt = select(Scan).where(
        Scan.schedule_minutes.is_not(None),
        Scan.next_run_at.is_not(None),
        Scan.next_run_at <= now,
    )
    return list(db.execute(stmt).scalars().all())


def scheduled_options(scan: Scan, db: Session) -> RunOptions:
    """The options a scheduled run of ``scan`` launches with, entitlement re-checked."""
    options = RunOptions.from_dict(scan.schedule_options)
    if not workspace.is_premium(db, scan.tenant_id):
        options = replace(options, premium=False, adaptive=False, resource_refine=False)
    return options


def dispatch_due(
    db: Session,
    now: datetime,
    enqueue: Callable[[str, dict[str, Any]], None],
) -> list[str]:
    """Enqueue due scans with their saved options; advance next_run_at.

    Returns the dispatched scan ids. A scan whose message the broker refuses
    is put back as it was and its admission withdrawn: nothing was queued, so
    it must neither sit ``queued`` until the reaper fails it nor spend the
    workspace's daily allowance. The schedule has still advanced.
    """
    dispatched: list[tuple[Scan, ScanStatus, Any, dict[str, Any]]] = []
    for scan in due_scans(db, now):
        # Always advance the schedule so a busy/absent run doesn't wedge it.
        scan.next_run_at = now + timedelta(minutes=scan.schedule_minutes or 0)
        if scan.status in _BUSY or not scan.operations:
            continue
        # A schedule is a standing run request, so it answers the same
        # admission gate as a manual run. A refused dispatch leaves the scan
        # untouched and tries again next cycle; the schedule still advanced.
        try:
            admission = workspace.admit_run(
                db, scan.tenant_id, scan_id=scan.id, source="schedule", now=now
            )
        except workspace.RunLimit:
            continue
        previous_status = scan.status
        scan.status = ScanStatus.queued
        scan.failure_reason = None
        scan.progress = 0
        scan.cancel_requested = False
        scan.heartbeat_at = now  # the reaper's clock starts at queue time
        scan.queued_at = now
        # The session does not autoflush: without this the next due scan's
        # admission query cannot see that this one is now queued.
        db.flush()
        dispatched.append(
            (scan, previous_status, admission, scheduled_options(scan, db).to_dict())
        )
    db.commit()
    sent: list[str] = []
    for scan, previous_status, admission, options in dispatched:
        try:
            enqueue(str(scan.id), options)
        except Exception:  # noqa: BLE001 — one refused message must not strand the rest
            log.exception("scheduled scan %s could not be queued", scan.id)
            scan.status = previous_status
            if admission is not None:
                db.delete(admission)
            db.commit()
            continue
        sent.append(str(scan.id))
    return sent


def set_schedule(
    db: Session, scan: Scan, minutes: int | None, options: RunOptions | None = None
) -> Scan:
    """Enable (minutes>0) or clear (None) a scan's recurring schedule.

    ``options`` are what every scheduled run will use; omitted means a default
    read-only scan. Clearing forgets them, so re-enabling states (and
    re-authorizes) them again.
    """
    if minutes and minutes > 0:
        scan.schedule_minutes = minutes
        scan.next_run_at = datetime.now(UTC) + timedelta(minutes=minutes)
        scan.schedule_options = (options or RunOptions()).to_dict()
    else:
        scan.schedule_minutes = None
        scan.next_run_at = None
        scan.schedule_options = {}
    db.commit()
    db.refresh(scan)
    return scan
