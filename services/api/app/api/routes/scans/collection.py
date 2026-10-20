from __future__ import annotations

from datetime import UTC, datetime

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session

from app.api import schemas
from app.core.db import get_db
from app.models.scan import Scan
from app.scans import service, workspace

from ._shared import (
    _ACTIVE,
    SCAN_ROUTER_KWARGS,
    AdminDep,
    EditableScanDep,
    LightScanDep,
    ScanDep,
    ScanWriteDep,
    TenantId,
)

router = APIRouter(**SCAN_ROUTER_KWARGS)


@router.post("", response_model=schemas.ScanOut, status_code=201)
def create_scan(
    body: schemas.ScanCreate,
    principal: ScanWriteDep,
    db: Session = Depends(get_db),
) -> Scan:
    scan = service.create_scan(db, body.target_base_url, principal.tenant)
    workspace.record_audit(
        db,
        principal,
        "scan.created",
        "scan",
        scan.id,
        {"target": scan.target_base_url},
    )
    db.commit()
    return scan


@router.post("/example", response_model=schemas.ScanOut, status_code=201)
def create_example_scan(
    principal: ScanWriteDep, db: Session = Depends(get_db)
) -> Scan:
    """Dev only: the bundled target with its live spec and both seed identities, not run."""
    from app.monitoring.setup import create_example_scan as create

    scan = create(db, principal.tenant)
    workspace.record_audit(
        db, principal, "scan.created", "scan", scan.id, {"example": True}
    )
    db.commit()
    return scan


@router.patch("/{scan_id}", response_model=schemas.ScanOut)
def update_scan(
    body: schemas.ScanUpdate,
    scan: EditableScanDep,
    principal: ScanWriteDep,
    db: Session = Depends(get_db),
) -> Scan:
    """Edit the scan's target base URL. Rejected while a scan is active."""
    scan = service.update_target(db, scan, body.target_base_url.strip())
    workspace.record_audit(
        db,
        principal,
        "scan.target_updated",
        "scan",
        scan.id,
        {"target": scan.target_base_url},
    )
    db.commit()
    return scan


@router.put("/{scan_id}/request-rate", response_model=schemas.ScanOut)
def update_request_rate(
    body: schemas.RequestRateUpdate,
    scan: EditableScanDep,
    principal: ScanWriteDep,
    db: Session = Depends(get_db),
) -> Scan:
    """Save the request cadence used by manual and scheduled runs."""
    scan = service.update_request_rate(db, scan, body.requests_per_second)
    workspace.record_audit(
        db,
        principal,
        "scan.rate_updated",
        "scan",
        scan.id,
        {"requests_per_second": scan.requests_per_second},
    )
    db.commit()
    return scan


@router.put("/{scan_id}/managed-config", response_model=schemas.ScanOut)
def set_managed_config(
    body: schemas.ManagedConfigIn,
    scan: ScanDep,
    principal: ScanWriteDep,
    db: Session = Depends(get_db),
) -> Scan:
    """Record which settings a project file (aidetector.yml) owns.

    Metadata only: it changes nothing a run does, so it is accepted while a scan
    runs and needs no authorization. The web reads it to mark those settings
    read-only.
    """
    scan.managed_config = {
        **body.model_dump(),
        "updated_at": datetime.now(UTC).isoformat(),
    }
    workspace.record_audit(
        db, principal, "scan.config_managed", "scan", scan.id
    )
    db.commit()
    db.refresh(scan)
    return scan


@router.delete("/{scan_id}/managed-config", response_model=schemas.ScanOut)
def clear_managed_config(
    scan: ScanDep,
    principal: ScanWriteDep,
    db: Session = Depends(get_db),
) -> Scan:
    """Hand every setting back to the web."""
    scan.managed_config = {}
    workspace.record_audit(
        db, principal, "scan.config_released", "scan", scan.id
    )
    db.commit()
    db.refresh(scan)
    return scan


@router.get("", response_model=list[schemas.ScanSummary])
def list_scans(
    tenant_id: TenantId,
    limit: int = Query(default=500, ge=1, le=1000),
    offset: int = Query(default=0, ge=0),
    db: Session = Depends(get_db),
) -> list[schemas.ScanSummary]:
    return [
        _scan_summary(entry)
        for entry in service.list_scans(
            db, tenant_id, limit=limit, offset=offset
        )
    ]


def _scan_summary(entry: service.ScanListEntry) -> schemas.ScanSummary:
    """Map the service's plain projection onto the HTTP response model."""
    summary = schemas.ScanSummary.model_validate(entry.scan)
    summary.finding_counts = schemas.FindingCounts(**vars(entry.finding_counts))
    summary.last_run_at = entry.last_run_at
    return summary


@router.get("/{scan_id}", response_model=schemas.ScanOut)
def get_scan(scan: ScanDep) -> Scan:
    return scan


@router.get("/{scan_id}/progress", response_model=schemas.ScanProgressOut)
def get_scan_progress(scan: LightScanDep) -> schemas.ScanProgressOut:
    """The fields a running scan changes, without its collections.

    The web polls this every second while a scan is active; ``GET /scans/{id}``
    remains the full detail read.
    """
    return schemas.ScanProgressOut.model_validate(scan)


@router.delete("/{scan_id}")
def delete_scan(
    scan: ScanDep, admin: AdminDep, db: Session = Depends(get_db)
) -> dict[str, str]:
    """Delete a scan and all of its data. Refused while a scan is active."""
    if scan.status in _ACTIVE:
        # A worker is still writing to this scan's rows — cancel first. Phrased
        # for the action rather than using the generic editable guard.
        raise HTTPException(status_code=409, detail="cancel the scan before deleting it")
    workspace.record_audit(db, admin, "scan.deleted", "scan", scan.id)
    service.delete_scan(db, scan)
    return {"status": "deleted"}
