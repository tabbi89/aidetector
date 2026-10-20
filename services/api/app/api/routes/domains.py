"""Prove a workspace controls a public scan target before it may be scanned.

Issuing a token and checking it are workspace-admin actions: a verified host is
a standing statement that this workspace may aim active payloads at it. The
scan-start gate (``app/scans/domains.clear_target``) repeats the proof live on
every run, so deleting a record or unpublishing the token stops future scans.
"""
from __future__ import annotations

import uuid
from urllib.parse import urlsplit

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.api import schemas
from app.core import ownership
from app.core.auth import AdminDep, PrincipalDep
from app.core.db import get_db
from app.core.pinning import url_host
from app.models.domain import DomainVerification
from app.scans import domains, workspace

router = APIRouter(prefix="/workspace/domains", tags=["domains"])


def _netloc(host: str) -> str:
    # An IPv6 literal is stored without brackets; a URL needs them back.
    return f"[{host}]" if ":" in host else host


def _out(row: DomainVerification) -> schemas.DomainVerificationOut:
    return schemas.DomainVerificationOut(
        id=row.id,
        host=row.host,
        token=row.token,
        dns_record_name=(
            None if ownership.is_ip_literal(row.host) else ownership.dns_record_name(row.host)
        ),
        dns_record_value=ownership.dns_record_value(row.token),
        http_path=f"{ownership.WELL_KNOWN}{row.token}",
        http_url=ownership.token_url(f"https://{_netloc(row.host)}", row.token),
        verified_at=row.verified_at,
        last_checked_at=row.last_checked_at,
        last_error=row.last_error,
        last_checks=[schemas.DomainProofOut(**check) for check in row.last_checks or []],
        created_at=row.created_at,
    )


def _owned(db: Session, tenant: str, domain_id: uuid.UUID) -> DomainVerification:
    row = db.get(DomainVerification, domain_id)
    if row is None or row.tenant_slug != tenant:
        raise HTTPException(status_code=404, detail="domain not found")
    return row


@router.get("", response_model=list[schemas.DomainVerificationOut])
def list_domains(
    principal: PrincipalDep, db: Session = Depends(get_db)
) -> list[schemas.DomainVerificationOut]:
    rows = db.scalars(
        select(DomainVerification)
        .where(DomainVerification.tenant_slug == principal.tenant)
        .order_by(DomainVerification.host)
    ).all()
    return [_out(row) for row in rows]


@router.post("", response_model=schemas.DomainVerificationOut, status_code=201)
def add_domain(
    body: schemas.DomainVerificationIn,
    principal: AdminDep,
    db: Session = Depends(get_db),
) -> schemas.DomainVerificationOut:
    try:
        host = ownership.normalize_host(body.host)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    if domains.record_for(db, principal.tenant, host) is not None:
        raise HTTPException(status_code=409, detail=f"'{host}' is already listed")
    workspace.ensure_tenant(db, principal.tenant)
    row = DomainVerification(
        tenant_slug=principal.tenant,
        host=host,
        token=ownership.new_token(),
        created_by_user_id=principal.user_id,
    )
    db.add(row)
    db.flush()
    workspace.record_audit(
        db, principal, "domain.added", "domain_verification", row.id, {"host": host}
    )
    db.commit()
    db.refresh(row)
    return _out(row)


@router.post("/{domain_id}/verify", response_model=schemas.DomainVerificationOut)
def verify_domain(
    domain_id: uuid.UUID,
    principal: AdminDep,
    body: schemas.DomainVerifyRequest | None = None,
    db: Session = Depends(get_db),
) -> schemas.DomainVerificationOut:
    """Run both proofs now and record the result. A failed check is a 200 with
    ``last_error`` set — the check ran; the proof is what failed."""
    row = _owned(db, principal.tenant, domain_id)
    url = (body.url if body else None) or f"https://{row.host}"
    parts = urlsplit(url.strip())
    if parts.scheme not in ("http", "https"):
        raise HTTPException(status_code=422, detail="url must be http or https")
    if url_host(url) != row.host:
        raise HTTPException(status_code=422, detail=f"url must be on host '{row.host}'")
    domains.verify_domain(db, row, url)
    workspace.record_audit(
        db,
        principal,
        "domain.verified" if row.verified_at else "domain.verify_failed",
        "domain_verification",
        row.id,
        {"host": row.host},
    )
    db.commit()
    db.refresh(row)
    return _out(row)


@router.delete("/{domain_id}")
def delete_domain(
    domain_id: uuid.UUID,
    principal: AdminDep,
    db: Session = Depends(get_db),
) -> dict[str, str]:
    row = _owned(db, principal.tenant, domain_id)
    workspace.record_audit(
        db, principal, "domain.deleted", "domain_verification", row.id, {"host": row.host}
    )
    db.delete(row)
    db.commit()
    return {"status": "deleted"}
