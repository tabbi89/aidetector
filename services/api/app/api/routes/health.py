"""Health and readiness endpoints."""
from __future__ import annotations

from fastapi import APIRouter, Depends
from sqlalchemy import text
from sqlalchemy.orm import Session

from app.api.schemas import HealthOut
from app.core.auth import Principal, auth_required, require_api_key, require_principal
from app.core.config import settings
from app.core.db import get_db

router = APIRouter(tags=["health"])


@router.get("/health", response_model=HealthOut)
def health() -> dict[str, str | bool]:
    """Liveness — the process is up."""
    return {"status": "ok", "examples": settings.env == "dev"}


@router.get("/health/ready")
def ready(db: Session = Depends(get_db)) -> dict[str, str]:
    """Readiness — the database is reachable."""
    db.execute(text("SELECT 1"))
    return {"status": "ready", "database": "ok"}


@router.get("/auth/status")
def auth_status(
    principal: Principal = Depends(require_principal),
    db: Session = Depends(get_db),
) -> dict[str, object]:
    """Who the caller is, and whether this deployment requires a key at all.

    A cheap probe for the UI's connection state: it touches no sidecar, unlike
    ``/capabilities``. It is also the one place a browser can learn that the
    API is open (``auth_required`` false) — worth saying out loud in the UI,
    because an open scanner is an unauthenticated active-scan endpoint.
    """
    user = (
        {
            "id": str(principal.user_id),
            "email": principal.email,
            "display_name": principal.display_name,
        }
        if principal.user_id is not None
        else None
    )
    return {
        "tenant": principal.tenant,
        "auth_required": auth_required(db),
        "role": principal.role.value,
        "user": user,
    }


@router.get("/capabilities")
def capabilities(
    tenant: str = Depends(require_api_key),
    db: Session = Depends(get_db),
) -> dict[str, object]:
    """What this deployment can run, and what this tenant may run.

    ``passes`` answers for the deployment and is cached briefly — the probes are
    network calls to sidecars. ``premium`` answers for the calling tenant and is
    never cached per tenant, so a plan change lands on the next request.
    """
    from app.scans.capabilities import capabilities as current
    from app.scans.capabilities import entitlement
    from app.scans.run_levels import LEVELS, expand

    premium = entitlement(tenant, db)
    entitled = bool(premium["available"])

    def flags(level: str, *, ai: bool, writes: bool) -> frozenset[str]:
        return expand(level, ai=ai, writes=writes, entitled=entitled, lane="local")  # type: ignore[arg-type]

    # What each level turns on for this tenant on the local (CLI) lane, so a
    # client previews the server's expansion instead of keeping its own copy.
    levels = {
        level: {
            "passes": sorted(flags(level, ai=False, writes=False)),
            "ai": sorted(
                flags(level, ai=True, writes=False) - flags(level, ai=False, writes=False)
            ),
            "ai_with_writes": sorted(
                flags(level, ai=True, writes=True) - flags(level, ai=True, writes=False)
            ),
        }
        for level in LEVELS
    }
    return {"passes": current(), "premium": premium, "levels": levels}
