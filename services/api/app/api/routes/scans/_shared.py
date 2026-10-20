from __future__ import annotations

import uuid
from typing import Annotated, Any

from fastapi import Depends, HTTPException
from sqlalchemy.orm import Session

from app.api import schemas
from app.core.auth import (
    AdminDep,
    Principal,
    ScanWriteDep,
    TenantId,
    require_mutation_role,
)
from app.core.db import get_db
from app.core.ownership import OwnershipNotProven
from app.core.target_guard import TargetNotAllowed
from app.models.scan import Scan, ScanStatus
from app.scans import domains, policy, service
from app.scans.domains import Clearance
from app.scans.run_levels import Lane

_ACTIVE = {ScanStatus.queued, ScanStatus.running}

# Every scan route is gated by the principal dependency. With no key configured
# it is a no-op admin in dev/test; a hosted deployment sets a key or
# AUTH_REQUIRED. The router-level mutation gate makes every non-read handler
# analyst-or-admin, so a viewer cannot write by forgetting a route-level guard.
SCAN_ROUTER_KWARGS: dict[str, Any] = {
    "prefix": "/scans",
    "tags": ["scans"],
    "dependencies": [Depends(require_mutation_role)],
    "responses": {
        400: {"model": schemas.ErrorOut, "description": "Invalid request or scan state"}
    },
}

__all__ = [
    "AdminDep",
    "EditableScanDep",
    "LightScanDep",
    "Principal",
    "SCAN_ROUTER_KWARGS",
    "ScanDep",
    "ScanWriteDep",
    "TenantId",
    "_ACTIVE",
    "_latest_run",
    "_require_premium",
    "_require_run_authorization",
    "_require_runnable",
    "_require_target_allowed",
    "load_editable_scan",
    "load_scan",
    "load_scan_light",
]


def load_scan(
    scan_id: uuid.UUID, tenant_id: TenantId, db: Session = Depends(get_db)
) -> Scan:
    """The scan named in the path, scoped to the caller's tenant. 404 otherwise."""
    scan = service.get_scan(db, scan_id, tenant_id)
    if scan is None:
        raise HTTPException(status_code=404, detail="scan not found")
    return scan


def load_editable_scan(scan: Scan = Depends(load_scan)) -> Scan:
    """A scan that may be modified — refused while a worker is writing to it.

    Replacing operations or credentials mid-scan would corrupt the running
    engine pass, and deleting the scan would pull rows out from under it.
    """
    if scan.status in _ACTIVE:
        raise HTTPException(
            status_code=409, detail="cannot modify a scan while it is running"
        )
    return scan


#: A scan the handler only reads.
ScanDep = Annotated[Scan, Depends(load_scan)]
#: A scan the handler modifies — carries the not-running guard.
EditableScanDep = Annotated[Scan, Depends(load_editable_scan)]


def load_scan_light(
    scan_id: uuid.UUID, tenant_id: TenantId, db: Session = Depends(get_db)
) -> Scan:
    """The scan row only, for a poll that must not load its collections."""
    scan = service.get_scan_row(db, scan_id, tenant_id)
    if scan is None:
        raise HTTPException(status_code=404, detail="scan not found")
    return scan


#: A scan the handler polls for volatile state — no relationship eager loads.
LightScanDep = Annotated[Scan, Depends(load_scan_light)]


def _require_run_authorization[R: schemas.RunRequest](
    body: R,
    tenant_id: str,
    db: Session,
    *,
    lane: Lane = "server",
) -> R:
    """The gates every path that starts scans answers — a manual run or a schedule.

    A schedule used to be treated as metadata, so enabling one skipped the
    authorization gate while starting active scans nobody would click "run" for.
    The policy lives in :mod:`app.scans.policy`; this adapter only maps its
    domain errors onto status codes.

    Returns the request with its scan level expanded into plain flags
    (``RunRequest.resolved``). Callers must carry on with the returned request:
    it is what the gates judged, so it is what runs.
    """
    from app.scans.workspace import is_premium

    entitled = is_premium(db, tenant_id)
    # Authorization is read from what the caller sent, never from the expanded
    # copy: an expansion only names passes, so it can never answer this gate.
    authorized = body.authorized
    body = body.resolved(entitled=entitled, lane=lane)
    try:
        policy.authorize_run(
            authorized=authorized,
            options=body.to_options(),
            tenant_id=tenant_id,
            premium=entitled,
        )
    except policy.RunNotAuthorized as exc:
        raise HTTPException(status_code=403, detail=str(exc)) from exc
    except policy.PremiumRequired as exc:
        raise HTTPException(status_code=402, detail=str(exc)) from exc
    except policy.RunOptionConflict as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    return body


def _require_target_allowed(
    scan: Scan, db: Session, *, allow_private: bool | None = None
) -> Clearance:
    """SSRF/egress guard and ownership proof, answered before anything is queued.

    A public target needs this workspace's DNS TXT record and HTTP token
    (``app/scans/domains``); the worker repeats the proof at scan start.
    ``allow_private`` overrides the server's egress flag for a lane that does
    not egress from the server (the local-runner claim); a public target still
    needs its ownership proof, and cloud metadata is still always refused.
    """
    try:
        policy.require_target_allowed(scan.target_base_url, allow_private=allow_private)
        return domains.clear_target(
            db, scan.tenant_id, scan.target_base_url, allow_private=allow_private
        )
    except OwnershipNotProven as exc:
        raise HTTPException(status_code=422, detail=f"target not verified: {exc}") from exc
    except TargetNotAllowed as exc:
        raise HTTPException(status_code=422, detail=f"target not allowed: {exc}") from exc


def _require_runnable(
    scan: Scan, db: Session, *, allow_private: bool | None = None
) -> Clearance:
    """What a scan must be before any lane may start it: specced, scoped, idle, allowed.

    Shared by the worker run and the local-runner claim so the two lanes cannot
    drift. Callers answer ``_require_run_authorization`` *before* this — the
    authorization gate is always the first refusal a caller sees. ``allow_private``
    is threaded to the egress guard for the local lane (see
    :func:`_require_target_allowed`).
    """
    if not scan.operations:
        raise HTTPException(status_code=400, detail="upload a spec before running")
    if not any(op.enabled for op in scan.operations):
        raise HTTPException(status_code=400, detail="select at least one operation to run")
    # Not EditableScanDep: an already-running scan is its own 409, and the
    # authorization gate must be answered before anything else.
    if scan.status in _ACTIVE:
        raise HTTPException(status_code=409, detail="scan already running")
    return _require_target_allowed(scan, db, allow_private=allow_private)


def _require_premium(tenant_id: str, db: Session) -> None:
    """Team collaboration is a premium feature, like the pentest report.

    The UI hides the panel for a free tenant, but the boundary belongs to the
    API: a hidden control is not an entitlement check. The workspace plan is the
    source, with ``premium_tenants`` retained as a dev override.
    """
    from app.scans.workspace import is_premium

    if not is_premium(db, tenant_id):
        raise HTTPException(status_code=402, detail="premium tier required")


def _latest_run(scan: Scan):
    """The most recent run, or None if the scan has never run."""
    return max(scan.runs, key=lambda r: r.run_number, default=None)
