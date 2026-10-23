"""Dev-only scan setup against the bundled vulnerable target."""
from __future__ import annotations

import httpx
from fastapi import HTTPException
from sqlalchemy.orm import Session

from app.core.config import settings
from app.core.target_guard import TargetNotAllowed
from app.domain.enums import AuthType
from app.models.scan import Scan
from app.scans import credentials, operations
from app.scans import service as scans
from app.scans.policy import require_target_allowed
from app.scans.views import CredentialInput

EXAMPLE_TARGET = "http://target:9000"
EXAMPLE_CREDENTIALS = (("alice", "user", "alice-token"), ("admin", "admin", "admin-token"))
MAX_EXAMPLE_SPEC_BYTES = 2_000_000


def examples_enabled() -> bool:
    return settings.env == "dev"


def _require_examples() -> None:
    if not examples_enabled():
        raise HTTPException(404, "not found")


def _allowed_target(target: str) -> None:
    try:
        require_target_allowed(target)
    except TargetNotAllowed:
        raise HTTPException(422, "target binding is not allowed") from None


def fetch_example_spec() -> str:
    """The bundled target's live OpenAPI document, so the example never drifts from it."""
    _allowed_target(EXAMPLE_TARGET)
    try:
        with httpx.Client(timeout=5, follow_redirects=False, trust_env=False) as client:
            response = client.get(f"{EXAMPLE_TARGET}/openapi.json")
    except httpx.HTTPError:
        response = None
    if (
        response is None
        or response.status_code != 200
        or len(response.content) > MAX_EXAMPLE_SPEC_BYTES
    ):
        raise HTTPException(503, "example target unavailable; start the stack with make up")
    return response.text


def create_example_scan(db: Session, tenant_id: str) -> Scan:
    """A scan of the bundled target with its spec and both seed identities, not yet run."""
    _require_examples()
    spec = fetch_example_spec()
    scan = scans.create_scan(db, EXAMPLE_TARGET, tenant_id)
    try:
        operations.ingest_spec(db, scan, spec)
        for name, role, token in EXAMPLE_CREDENTIALS:
            credentials.add_credential(
                db,
                scan,
                CredentialInput(
                    name=name,
                    role=role,
                    auth_type=AuthType.header,
                    header_name="Authorization",
                    secret=token,
                ),
            )
    except Exception:
        db.rollback()
        scans.delete_scan(db, scan)
        raise
    db.refresh(scan)
    return scan
