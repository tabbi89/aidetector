"""Where a scan's schema context comes from: the snapshots its local runs uploaded.

The server never connects to a target database. A local run reads the schema
on the CLI machine and stores the structure on its ``ScanRun.schema_context``;
every later consumer on this scan — adaptive validation, AI resource
refinement, the security design review, a monitor's context — reads the newest
*available* one from here. One read per run, all configured tables, and no
password at rest.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass
from typing import Any

from sqlalchemy import select, update
from sqlalchemy.orm import Session

from app.models.scan import ScanRun


@dataclass(frozen=True)
class Snapshot:
    """A usable schema snapshot and the run that captured it."""

    run_id: uuid.UUID
    run_number: int
    captured_at: str
    context: dict[str, Any]  # {"tables": [...], "warnings": [...]}


def _attempted() -> Any:
    return ScanRun.schema_context.has_key("status")


def latest_snapshot(db: Session, scan_id: uuid.UUID) -> Snapshot | None:
    """The newest snapshot a local run of this scan read successfully."""
    run = db.scalar(
        select(ScanRun)
        .where(
            ScanRun.scan_id == scan_id,
            ScanRun.schema_context["status"].astext == "available",
        )
        .order_by(ScanRun.run_number.desc())
        .limit(1)
    )
    if run is None:
        return None
    stored = run.schema_context
    return Snapshot(
        run_id=run.id,
        run_number=run.run_number,
        captured_at=str(stored.get("captured_at") or ""),
        context={
            "tables": list(stored.get("tables") or []),
            "warnings": list(stored.get("warnings") or []),
        },
    )


def latest_attempt(db: Session, scan_id: uuid.UUID) -> ScanRun | None:
    """The newest run that tried to read the schema, whether or not it could."""
    return db.scalar(
        select(ScanRun)
        .where(ScanRun.scan_id == scan_id, _attempted())
        .order_by(ScanRun.run_number.desc())
        .limit(1)
    )


def forget(db: Session, scan_id: uuid.UUID) -> int:
    """Clear every stored attempt on this scan; returns how many runs held one."""
    result = db.execute(
        update(ScanRun)
        .where(ScanRun.scan_id == scan_id, _attempted())
        .values(schema_context={})
        .execution_options(synchronize_session=False)
    )
    return int(getattr(result, "rowcount", 0) or 0)
