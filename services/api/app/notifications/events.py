"""Turn scan/work state transitions into value-free outbox events.

Every event has a stable ``dedup_key``: the delivery table's unique constraint
turns "enqueue the same unchanged state twice" into one row. An endpoint sees
only the events it subscribed to and only at or above its minimum severity.
"""
from __future__ import annotations

from datetime import UTC, date, datetime
from typing import Any

from sqlalchemy import select
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.orm import Session

from app.domain.enums import SEVERITY_RANK, Severity
from app.models.finding_work import FindingWork
from app.models.notification import NotificationDelivery, NotificationEndpoint
from app.models.scan import Scan, ScanRun
from app.scans.workspace import ensure_tenant

KNOWN_EVENTS = frozenset(
    {
        "finding.new",
        "work.overdue",
        "run.failed",
        "run.recovered",
        "test",
    }
)


def enqueue(
    db: Session,
    *,
    tenant_slug: str,
    event_type: str,
    dedup_key: str,
    payload: dict[str, Any],
    severity: str,
) -> int:
    """Insert one delivery per subscribed endpoint; duplicates are ignored."""
    if event_type not in KNOWN_EVENTS:
        raise ValueError(f"unknown notification event: {event_type}")
    ensure_tenant(db, tenant_slug)
    try:
        rank = SEVERITY_RANK[Severity(severity)]
    except ValueError:
        rank = SEVERITY_RANK[Severity.medium]
    endpoints = db.scalars(
        select(NotificationEndpoint).where(
            NotificationEndpoint.tenant_slug == tenant_slug,
            NotificationEndpoint.active.is_(True),
        )
    ).all()
    inserted = 0
    for endpoint in endpoints:
        if event_type not in (endpoint.events or []):
            continue
        try:
            minimum = SEVERITY_RANK[Severity(endpoint.min_severity)]
        except ValueError:
            minimum = SEVERITY_RANK[Severity.medium]
        if rank < minimum:
            continue
        stmt = (
            pg_insert(NotificationDelivery)
            .values(
                tenant_slug=tenant_slug,
                endpoint_id=endpoint.id,
                event_type=event_type,
                dedup_key=dedup_key,
                payload=payload,
            )
            .on_conflict_do_nothing(
                index_elements=["endpoint_id", "dedup_key"]
            )
            .returning(NotificationDelivery.id)
        )
        # ``rowcount`` is -1 for ON CONFLICT DO NOTHING under psycopg; a
        # RETURNING row is the exact "inserted, not deduplicated" signal.
        if db.scalar(stmt) is not None:
            inserted += 1
    return inserted


def _previous_run(
    db: Session, scan_id: object, run_number: int
) -> ScanRun | None:
    return db.scalar(
        select(ScanRun)
        .where(
            ScanRun.scan_id == scan_id,
            ScanRun.run_number < run_number,
        )
        .order_by(ScanRun.run_number.desc())
        .limit(1)
    )


def new_finding_events(db: Session, scan: Scan, run: ScanRun) -> int:
    """Findings in this run whose fingerprint was absent from the previous run."""
    previous = _previous_run(db, scan.id, run.run_number)
    old = {
        str(row.get("fingerprint") or "")
        for row in ((previous.findings_snapshot if previous else None) or [])
        if row.get("fingerprint")
    }
    inserted = 0
    for row in run.findings_snapshot or []:
        fingerprint = str(row.get("fingerprint") or "")
        if not fingerprint or fingerprint in old:
            continue
        severity = str(row.get("severity") or "medium")
        payload = {
            "event": "finding.new",
            "scan_id": str(scan.id),
            "run_number": run.run_number,
            "fingerprint": fingerprint,
            "check": row.get("check"),
            "severity": severity,
            "confidence": row.get("confidence") or "heuristic",
            "title": row.get("title"),
            "occurred_at": datetime.now(UTC).isoformat(),
        }
        inserted += enqueue(
            db,
            tenant_slug=scan.tenant_id,
            event_type="finding.new",
            dedup_key=f"finding:{scan.id}:{fingerprint}:{run.run_number}",
            payload=payload,
            severity=severity,
        )
    return inserted


def completed_run_events(db: Session, scan: Scan, run: ScanRun) -> int:
    """New findings plus a recovery after a failed run, if that is the shape."""
    if run.status != "completed":
        return 0
    inserted = new_finding_events(db, scan, run)
    previous = _previous_run(db, scan.id, run.run_number)
    if previous is not None and previous.status == "failed":
        inserted += enqueue(
            db,
            tenant_slug=scan.tenant_id,
            event_type="run.recovered",
            dedup_key=f"run:{scan.id}:{run.run_number}:recovered",
            payload={
                "event": "run.recovered",
                "scan_id": str(scan.id),
                "run_number": run.run_number,
                "occurred_at": datetime.now(UTC).isoformat(),
            },
            severity="medium",
        )
    return inserted


def run_failed_event(db: Session, scan: Scan) -> int:
    """One failure event per run (or per scan when it failed before a run row)."""
    run = max(scan.runs, key=lambda item: item.run_number, default=None)
    suffix = str(run.run_number) if run is not None else "unstarted"
    return enqueue(
        db,
        tenant_slug=scan.tenant_id,
        event_type="run.failed",
        dedup_key=f"run:{scan.id}:{suffix}:failed",
        payload={
            "event": "run.failed",
            "scan_id": str(scan.id),
            "run_number": run.run_number if run is not None else None,
            "failure_reason": scan.failure_reason,
            "occurred_at": datetime.now(UTC).isoformat(),
        },
        severity="high",
    )


def work_overdue_events(db: Session, today: date | None = None) -> int:
    """One event per overdue work item per due date."""
    current = today or datetime.now(UTC).date()
    rows = db.execute(
        select(FindingWork, Scan)
        .join(Scan, FindingWork.scan_id == Scan.id)
        .where(
            FindingWork.due_date.is_not(None),
            FindingWork.due_date < current,
            FindingWork.status.not_in(("resolved", "accepted_risk")),
        )
    ).all()
    inserted = 0
    for work, scan in rows:
        payload = {
            "event": "work.overdue",
            "work_id": str(work.id),
            "scan_id": str(scan.id),
            "fingerprint": work.fingerprint,
            "owner": work.owner,
            "status": work.status,
            "due_date": work.due_date.isoformat() if work.due_date else None,
            "occurred_at": datetime.now(UTC).isoformat(),
        }
        inserted += enqueue(
            db,
            tenant_slug=scan.tenant_id,
            event_type="work.overdue",
            dedup_key=f"work:{work.id}:{work.due_date.isoformat()}",
            payload=payload,
            severity="medium",
        )
    return inserted
