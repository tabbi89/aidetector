"""A scan's credential profiles. Secrets are encrypted here and never read back."""
from __future__ import annotations

import uuid

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.vault import encrypt
from app.models.credential import CredentialProfile
from app.models.scan import Scan
from app.scans.views import CredentialInput


def _apply_metadata(cred: CredentialProfile, payload: CredentialInput) -> None:
    """Copy the non-secret fields a create and an edit both set."""
    cred.name = payload.name
    cred.role = payload.role
    cred.privilege = payload.privilege
    cred.tenant = payload.tenant
    cred.auth_type = payload.auth_type
    cred.header_name = payload.header_name
    cred.refresh_url = payload.refresh_url
    cred.refresh_token_field = payload.refresh_token_field
    cred.access_token_field = payload.access_token_field
    cred.grant_type = payload.grant_type
    cred.token_url = payload.token_url
    cred.grant_params = payload.grant_params or {}


def _credential_name_taken(
    db: Session, scan_id: uuid.UUID, name: str, *, exclude_id: uuid.UUID | None = None
) -> bool:
    """Whether this scan already has a credential with that name."""
    stmt = select(CredentialProfile.id).where(
        CredentialProfile.scan_id == scan_id, CredentialProfile.name == name
    )
    if exclude_id is not None:
        stmt = stmt.where(CredentialProfile.id != exclude_id)
    return db.scalar(stmt.limit(1)) is not None


def add_credential(
    db: Session, scan: Scan, payload: CredentialInput
) -> CredentialProfile:
    if payload.local_only and (payload.secret or payload.refresh_secret):
        raise ValueError("a local-only identity's secret stays on the CLI machine")
    if not payload.local_only and not payload.secret:
        raise ValueError("a credential requires a secret")
    if _credential_name_taken(db, scan.id, payload.name):
        raise ValueError(
            f"a credential named {payload.name!r} already exists on this scan"
        )
    cred = CredentialProfile(
        scan_id=scan.id,
        # Encrypted at rest; a local-only identity has nothing to store.
        secret_ref="" if payload.local_only else encrypt(payload.secret or ""),
        local_only=payload.local_only,
        refresh_secret_ref=(encrypt(payload.refresh_secret) if payload.refresh_secret else None),
    )
    _apply_metadata(cred, payload)
    db.add(cred)
    db.commit()
    db.refresh(cred)
    return cred


def update_credential(
    db: Session, scan: Scan, cred_id: uuid.UUID, payload: CredentialInput
) -> CredentialProfile | None:
    """Edit metadata; replace the encrypted secret only if a new one is given."""
    cred = db.get(CredentialProfile, cred_id)
    if cred is None or cred.scan_id != scan.id:
        return None
    if cred.local_only and (payload.secret or payload.refresh_secret):
        # An edit must not quietly turn a local-only identity into a stored
        # one: re-create it to move its secret to the server.
        raise ValueError(
            f"identity {cred.name!r} is local-only: its secret stays on the CLI machine"
        )
    if _credential_name_taken(db, scan.id, payload.name, exclude_id=cred.id):
        raise ValueError(
            f"a credential named {payload.name!r} already exists on this scan"
        )
    _apply_metadata(cred, payload)
    if payload.secret:
        cred.secret_ref = encrypt(payload.secret)
    if payload.refresh_secret:
        cred.refresh_secret_ref = encrypt(payload.refresh_secret)
    db.commit()
    db.refresh(cred)
    return cred


def delete_credential(db: Session, scan: Scan, cred_id: uuid.UUID) -> bool:
    cred = db.get(CredentialProfile, cred_id)
    if cred is None or cred.scan_id != scan.id:
        return False
    db.delete(cred)
    db.commit()
    return True
