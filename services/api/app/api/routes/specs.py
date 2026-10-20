"""Reading a spec before a scan exists: what ``aidetector init`` asks.

Nothing here stores the spec or contacts a target. Remote ``$ref``s are never
fetched (an empty allowlist), so a spec posted here cannot make the server
reach anywhere.
"""
from __future__ import annotations

from fastapi import APIRouter, HTTPException

from app.api import schemas
from app.api.auth_hints import hints_out
from app.core.auth import ScanWriteDep
from app.specs.parser import SpecError, load_spec

router = APIRouter(
    prefix="/specs",
    tags=["specs"],
    # Setup, not reading: the same members who can configure a scan may ask.
    responses={code: {"model": schemas.ErrorOut} for code in (401, 403, 422)},
)


@router.post("/auth-hints", response_model=schemas.AuthHintsOut)
def spec_auth_hints(
    body: schemas.AuthHintsRequest, principal: ScanWriteDep
) -> schemas.AuthHintsOut:
    """Suggest identity setup (public, one key, or roles) from a spec's security."""
    try:
        data = load_spec(body.spec, remote_ref_allowlist=[])
    except SpecError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    return hints_out(data)
