"""Scan-level operations: create, list, retarget and delete.

The operation set lives in ``app.scans.operations`` and credentials in
``app.scans.credentials``.
"""
from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import func, select
from sqlalchemy.orm import Session, selectinload

from app.domain.enums import Verdict
from app.models.finding import Finding
from app.models.scan import Scan, ScanRun, ScanStatus
from app.scans.operations import retarget_operations
from app.scans.views import FindingCountsView, ScanListEntry


def create_scan(db: Session, target_base_url: str, tenant_id: str = "default") -> Scan:
    scan = Scan(
        target_base_url=target_base_url,
        tenant_id=tenant_id,
        status=ScanStatus.draft,
    )
    db.add(scan)
    db.commit()
    db.refresh(scan)
    return scan


def update_target(db: Session, scan: Scan, target_base_url: str) -> Scan:
    """Change the scan's target base URL (only when not actively running).

    Operation routes depend on the target too, so they are re-derived from the
    spec (:func:`app.scans.operations.retarget_operations`) — even when the URL
    is unchanged, which repairs routes an earlier target change left stale.
    """
    previous = scan.target_base_url
    scan.target_base_url = target_base_url
    retarget_operations(scan, previous)
    db.commit()
    db.refresh(scan)
    return scan


def update_request_rate(db: Session, scan: Scan, requests_per_second: int) -> Scan:
    """Change the saved per-scan request cadence when the scan is idle."""
    scan.requests_per_second = requests_per_second
    db.commit()
    db.refresh(scan)
    return scan


def delete_scan(db: Session, scan: Scan) -> None:
    """Delete a scan and everything hanging off it.

    Every child relationship cascades (operations, runs, credential profiles,
    findings, events, ledger, adjudication cache), so the encrypted credential
    secrets go with it. Irreversible — callers gate this on the scan not being
    active.
    """
    db.delete(scan)
    db.commit()


def get_scan(db: Session, scan_id: uuid.UUID, tenant_id: str | None = None) -> Scan | None:
    stmt = (
        select(Scan)
        .where(Scan.id == scan_id)
        .options(
            selectinload(Scan.operations),
            selectinload(Scan.credential_profiles),
            selectinload(Scan.findings),
            selectinload(Scan.events),
            selectinload(Scan.ledger),
        )
    )
    if tenant_id is not None:
        stmt = stmt.where(Scan.tenant_id == tenant_id)
    return db.execute(stmt).scalar_one_or_none()


def get_scan_row(
    db: Session, scan_id: uuid.UUID, tenant_id: str | None = None
) -> Scan | None:
    """The scan row alone — no relationship eager loads.

    The detail read needs the graph; a progress poll needs a handful of columns.
    Keeping this separate is what makes ``GET /scans/{id}/progress`` O(1)
    instead of loading every finding, event and ledger row on the scan.
    """
    stmt = select(Scan).where(Scan.id == scan_id)
    if tenant_id is not None:
        stmt = stmt.where(Scan.tenant_id == tenant_id)
    return db.execute(stmt).scalar_one_or_none()


def list_scans(
    db: Session,
    tenant_id: str | None = None,
    *,
    limit: int | None = None,
    offset: int = 0,
) -> list[ScanListEntry]:
    """Every scan in the tenant, newest first, with the index page's metrics.

    The counts and last-run stamps come from two grouped queries covering the
    whole page rather than from per-scan loads: the index lists every scan an
    account has, so a query per scan makes the page cost grow with the account.
    ``limit``/``offset`` bound the page; the API supplies a default cap.
    """
    stmt = select(Scan)
    if tenant_id is not None:
        stmt = stmt.where(Scan.tenant_id == tenant_id)
    stmt = stmt.order_by(Scan.created_at.desc())
    if limit is not None:
        stmt = stmt.limit(limit).offset(offset)
    scans = list(db.execute(stmt).scalars().all())

    ids = [scan.id for scan in scans]
    counts = _live_finding_counts(db, ids)
    last_runs = _last_run_at(db, ids)

    summaries = []
    for scan in scans:
        summaries.append(
            ScanListEntry(
                scan=scan,
                finding_counts=counts.get(scan.id, FindingCountsView()),
                last_run_at=last_runs.get(scan.id),
            )
        )
    return summaries


def _live_finding_counts(
    db: Session, scan_ids: list[uuid.UUID]
) -> dict[uuid.UUID, FindingCountsView]:
    """Live findings per scan and severity, in one grouped query.

    ``live`` means a human has not dismissed it: a false positive someone
    triaged away must not keep a scan looking alarming.
    """
    if not scan_ids:
        return {}
    stmt = (
        select(Finding.scan_id, Finding.severity, func.count())
        .where(Finding.scan_id.in_(scan_ids), Finding.verdict != Verdict.dismissed)
        .group_by(Finding.scan_id, Finding.severity)
    )
    counts: dict[uuid.UUID, FindingCountsView] = {}
    for scan_id, severity, total in db.execute(stmt):
        setattr(counts.setdefault(scan_id, FindingCountsView()), severity.value, total)
    return counts


def _last_run_at(db: Session, scan_ids: list[uuid.UUID]) -> dict[uuid.UUID, datetime]:
    """When each scan last started a run — one grouped query, not one per scan."""
    if not scan_ids:
        return {}
    stmt = (
        select(ScanRun.scan_id, func.max(ScanRun.started_at))
        .where(ScanRun.scan_id.in_(scan_ids))
        .group_by(ScanRun.scan_id)
    )
    return {scan_id: started_at for scan_id, started_at in db.execute(stmt)}
