"""What a scan knows about its database schema — read-only, from local runs.

There is no route that saves a database connection: schema context is
configured in ``aidetector.yml`` and read by the CLI's local runner on the
machine it runs on, so the password never reaches this server. These routes
only show what the newest local runs captured and let a user forget it.
"""

from __future__ import annotations

from typing import Literal

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.api.routes.scans import EditableScanDep, ScanDep
from app.api.schemas import ErrorOut, ResponseModel
from app.core.auth import PrincipalDep, require_mutation_role
from app.core.db import get_db
from app.db_schema import snapshots
from app.models.scan import Scan, ScanStatus
from app.scans import workspace

router = APIRouter(
    prefix="/scans/{scan_id}/schema-context",
    tags=["database schema"],
    responses={code: {"model": ErrorOut} for code in (401, 404, 409)},
)


class SchemaAttempt(ResponseModel):
    run_number: int
    status: Literal["available", "unavailable"]
    reason: str | None
    captured_at: str


class SchemaTableSummary(ResponseModel):
    schema_name: str
    table_name: str
    column_count: int
    constraint_count: int


class SchemaSnapshotSummary(ResponseModel):
    run_number: int
    captured_at: str
    warnings: list[str]
    tables: list[SchemaTableSummary]


class SchemaContextOut(ResponseModel):
    #: The newest local run that tried to read the schema, successful or not.
    latest: SchemaAttempt | None
    #: The newest snapshot the scan's AI passes will use.
    snapshot: SchemaSnapshotSummary | None


class SchemaContextDeleted(ResponseModel):
    removed: int


@router.get("", response_model=SchemaContextOut)
def get_schema_context(scan: ScanDep, db: Session = Depends(get_db)) -> SchemaContextOut:
    attempt = snapshots.latest_attempt(db, scan.id)
    latest = None
    if attempt is not None:
        stored = attempt.schema_context
        latest = SchemaAttempt(
            run_number=attempt.run_number,
            status="available" if stored.get("status") == "available" else "unavailable",
            reason=stored.get("reason"),
            captured_at=str(stored.get("captured_at") or ""),
        )
    snap = snapshots.latest_snapshot(db, scan.id)
    summary = None
    if snap is not None:
        summary = SchemaSnapshotSummary(
            run_number=snap.run_number,
            captured_at=snap.captured_at,
            warnings=[str(w) for w in snap.context["warnings"]],
            tables=[
                SchemaTableSummary(
                    schema_name=str(t.get("schema_name", "")),
                    table_name=str(t.get("table_name", "")),
                    column_count=len(t.get("columns") or []),
                    constraint_count=len(t.get("constraints") or []),
                )
                for t in snap.context["tables"]
            ],
        )
    return SchemaContextOut(latest=latest, snapshot=summary)


@router.delete(
    "",
    response_model=SchemaContextDeleted,
    dependencies=[Depends(require_mutation_role)],
)
def forget_schema_context(
    scan: EditableScanDep,
    principal: PrincipalDep,
    db: Session = Depends(get_db),
) -> SchemaContextDeleted:
    # A running scan may be about to read the snapshot (or a local run about to
    # upload one); lock the parent row and refuse rather than race it.
    current = db.scalar(
        select(Scan)
        .where(Scan.id == scan.id)
        .with_for_update()
        .execution_options(populate_existing=True)
    )
    if current is None:
        raise HTTPException(status_code=404, detail="scan not found")
    if current.status in {ScanStatus.queued, ScanStatus.running}:
        raise HTTPException(status_code=409, detail="cannot modify a scan while it is running")
    removed = snapshots.forget(db, scan.id)
    workspace.record_audit(
        db, principal, "schema_context.forgotten", "scan", scan.id, {"runs": removed}
    )
    db.commit()
    return SchemaContextDeleted(removed=removed)
