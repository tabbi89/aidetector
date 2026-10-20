from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from app.api import schemas
from app.core.db import get_db
from app.models.scan import Scan
from app.scans import scheduler, workspace

from ._shared import (
    SCAN_ROUTER_KWARGS,
    ScanDep,
    ScanWriteDep,
    _require_run_authorization,
    _require_target_allowed,
)

router = APIRouter(**SCAN_ROUTER_KWARGS)


@router.put("/{scan_id}/schedule", response_model=schemas.ScanOut)
def set_schedule(
    body: schemas.ScheduleRequest,
    scan: ScanDep,
    principal: ScanWriteDep,
    db: Session = Depends(get_db),
) -> Scan:
    """Enable or clear a recurring schedule (re-run every N minutes).

    Enabling one starts active scans nobody will click "run" for, so it answers
    the same authorization and entitlement gates as a manual run, and saves the
    options every scheduled run will use. Clearing needs no authorization.
    """
    if not body.minutes:
        scheduler.set_schedule(db, scan, None)
        workspace.record_audit(
            db, principal, "schedule.cleared", "scan", scan.id
        )
        db.commit()
        return scan
    body = _require_run_authorization(body, principal.tenant, db)
    if not scan.operations:
        raise HTTPException(status_code=400, detail="upload a spec before scheduling")
    _require_target_allowed(scan, db)
    if body.requests_per_second is not None:
        scan.requests_per_second = body.requests_per_second
    scheduler.set_schedule(db, scan, body.minutes, body.to_options())
    workspace.record_audit(
        db,
        principal,
        "schedule.updated",
        "scan",
        scan.id,
        {"minutes": body.minutes},
    )
    db.commit()
    return scan
