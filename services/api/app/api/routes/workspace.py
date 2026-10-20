"""Workspace membership, roles, API tokens and the audit feed."""
from __future__ import annotations

import uuid

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.ai.budget import month_start, spend_micros
from app.api import schemas
from app.core.auth import AdminDep, PrincipalDep
from app.core.db import get_db
from app.domain.permissions import Role
from app.models.identity import ApiToken, AuditLog, Membership, User
from app.models.scan import Scan, ScanStatus
from app.scans import accounts, workspace

router = APIRouter(prefix="/workspace", tags=["workspace"])


def _user_out(user: User) -> schemas.WorkspaceUserOut:
    return schemas.WorkspaceUserOut(
        id=user.id, email=user.email, display_name=user.display_name
    )


def _member_out(membership: Membership) -> schemas.MemberOut:
    return schemas.MemberOut(
        user_id=membership.user_id,
        email=membership.user.email,
        display_name=membership.user.display_name,
        role=Role(membership.role),
        created_at=membership.created_at,
    )


def _token_out(
    token: ApiToken, membership: Membership
) -> dict[str, object]:
    return {
        "id": token.id,
        "user_id": membership.user_id,
        "email": membership.user.email,
        "display_name": membership.user.display_name,
        "prefix": token.prefix,
        "last4": token.last4,
        "label": token.label,
        "created_at": token.created_at,
        "last_used_at": token.last_used_at,
        "expires_at": token.expires_at,
        "revoked_at": token.revoked_at,
    }


def _audit_out(row: AuditLog) -> schemas.AuditOut:
    return schemas.AuditOut(
        id=row.id,
        actor=_user_out(row.actor) if row.actor is not None else None,
        action=row.action,
        object_type=row.object_type,
        object_id=row.object_id,
        summary=row.summary or {},
        created_at=row.created_at,
    )


def _budget_out(db: Session, principal: AdminDep) -> schemas.BudgetOut:
    tenant = workspace.ensure_tenant(db, principal.tenant)
    month_spent = spend_micros(db, principal.tenant, since=month_start())
    active = int(
        db.scalar(
            select(func.count())
            .select_from(Scan)
            .where(
                Scan.tenant_id == principal.tenant,
                Scan.status.in_((ScanStatus.queued, ScanStatus.running)),
            )
        )
        or 0
    )
    queued = int(
        db.scalar(
            select(func.count())
            .select_from(Scan)
            .where(
                Scan.tenant_id == principal.tenant,
                Scan.status == ScanStatus.queued,
            )
        )
        or 0
    )
    remaining = (
        max(0, tenant.ai_monthly_micros - month_spent)
        if tenant.ai_monthly_micros is not None
        else None
    )
    return schemas.BudgetOut(
        tenant=tenant.slug,
        plan=tenant.plan,
        ai_monthly_micros=tenant.ai_monthly_micros,
        ai_per_scan_micros=tenant.ai_per_scan_micros,
        max_concurrent_runs=tenant.max_concurrent_runs,
        max_queued_runs=tenant.max_queued_runs,
        scans_per_day=tenant.scans_per_day,
        month_spent_micros=month_spent,
        month_remaining_micros=remaining,
        active_runs=active,
        queued_runs=queued,
    )


@router.get("/budgets", response_model=schemas.BudgetOut)
def get_budgets(
    principal: AdminDep, db: Session = Depends(get_db)
) -> schemas.BudgetOut:
    return _budget_out(db, principal)


@router.put("/budgets", response_model=schemas.BudgetOut)
def set_budgets(
    body: schemas.BudgetIn,
    principal: AdminDep,
    db: Session = Depends(get_db),
) -> schemas.BudgetOut:
    """Set the workspace's AI spend and run-admission limits.

    Omitted fields stay unchanged; an explicit null removes that limit.
    """
    tenant = workspace.ensure_tenant(db, principal.tenant)
    changed = body.model_dump(exclude_unset=True)
    for field, value in changed.items():
        setattr(tenant, field, value)
    workspace.record_audit(
        db,
        principal,
        "workspace.budgets_updated",
        "tenant",
        tenant.slug,
        changed,
    )
    db.commit()
    return _budget_out(db, principal)


@router.get("", response_model=schemas.WorkspaceOut)
def get_workspace(
    principal: PrincipalDep, db: Session = Depends(get_db)
) -> schemas.WorkspaceOut:
    tenant = workspace.ensure_tenant(db, principal.tenant)
    db.commit()
    return schemas.WorkspaceOut(
        tenant=tenant.slug,
        name=tenant.name,
        plan=tenant.plan,
        role=principal.role,
        user=(
            schemas.WorkspaceUserOut(
                id=principal.user_id,
                email=principal.email or "",
                display_name=principal.display_name or "",
            )
            if principal.user_id is not None
            else None
        ),
        members=workspace.member_count(db, principal.tenant),
    )


@router.get("/members", response_model=list[schemas.MemberOut])
def list_members(
    principal: PrincipalDep, db: Session = Depends(get_db)
) -> list[schemas.MemberOut]:
    return [
        _member_out(m)
        for m in workspace.list_members(db, principal.tenant)
    ]


@router.post(
    "/members", response_model=schemas.MemberOut, status_code=201
)
def add_member(
    body: schemas.MemberIn,
    principal: AdminDep,
    db: Session = Depends(get_db),
) -> schemas.MemberOut:
    workspace.ensure_tenant(db, principal.tenant)
    try:
        membership = workspace.add_member(
            db,
            principal.tenant,
            email=body.email,
            display_name=body.display_name,
            role=body.role,
        )
    except workspace.DuplicateMember as exc:
        raise HTTPException(
            status_code=409, detail=f"{exc} is already a member"
        ) from exc
    workspace.record_audit(
        db,
        principal,
        "member.added",
        "membership",
        membership.user_id,
        {"email": membership.user.email, "role": membership.role},
    )
    db.commit()
    db.refresh(membership)
    return _member_out(membership)


@router.patch(
    "/members/{user_id}", response_model=schemas.MemberOut
)
def change_member_role(
    user_id: uuid.UUID,
    body: schemas.MemberRoleIn,
    principal: AdminDep,
    db: Session = Depends(get_db),
) -> schemas.MemberOut:
    try:
        membership = workspace.change_role(
            db, principal.tenant, user_id, body.role
        )
    except workspace.NotAMember as exc:
        raise HTTPException(
            status_code=404, detail="member not found"
        ) from exc
    except workspace.LastAdmin as exc:
        raise HTTPException(
            status_code=409,
            detail="the workspace must keep at least one admin",
        ) from exc
    workspace.record_audit(
        db,
        principal,
        "member.role_changed",
        "membership",
        user_id,
        {"role": body.role.value},
    )
    db.commit()
    db.refresh(membership)
    return _member_out(membership)


@router.delete("/members/{user_id}")
def remove_member(
    user_id: uuid.UUID,
    principal: AdminDep,
    db: Session = Depends(get_db),
) -> dict[str, str]:
    try:
        workspace.remove_member(db, principal.tenant, user_id)
    except workspace.NotAMember as exc:
        raise HTTPException(
            status_code=404, detail="member not found"
        ) from exc
    except workspace.LastAdmin as exc:
        raise HTTPException(
            status_code=409,
            detail="the workspace must keep at least one admin",
        ) from exc
    workspace.record_audit(
        db, principal, "member.removed", "membership", user_id
    )
    db.commit()
    return {"status": "deleted"}


@router.get("/tokens", response_model=list[schemas.TokenOut])
def list_tokens(
    principal: AdminDep, db: Session = Depends(get_db)
) -> list[schemas.TokenOut]:
    rows: list[schemas.TokenOut] = []
    for token in workspace.list_tokens(db, principal.tenant):
        rows.append(
            schemas.TokenOut(
                **_token_out(token, token.membership)
            )
        )
    return rows


@router.post(
    "/tokens", response_model=schemas.TokenCreated, status_code=201
)
def create_token(
    body: schemas.TokenIn,
    principal: AdminDep,
    db: Session = Depends(get_db),
) -> schemas.TokenCreated:
    workspace.ensure_tenant(db, principal.tenant)
    try:
        raw, token, membership = workspace.create_token(
            db,
            principal.tenant,
            body.user_id,
            label=body.label,
            expires_at=body.expires_at,
        )
    except workspace.NotAMember as exc:
        raise HTTPException(
            status_code=404, detail="member not found"
        ) from exc
    workspace.record_audit(
        db,
        principal,
        "token.created",
        "api_token",
        token.id,
        {"label": token.label, "prefix": token.prefix},
    )
    db.commit()
    db.refresh(token)
    return schemas.TokenCreated(
        **_token_out(token, membership), token=raw
    )


@router.delete("/tokens/{token_id}")
def revoke_token(
    token_id: uuid.UUID,
    principal: AdminDep,
    db: Session = Depends(get_db),
) -> dict[str, str]:
    if not workspace.revoke_token(db, principal.tenant, token_id):
        raise HTTPException(status_code=404, detail="token not found")
    workspace.record_audit(
        db, principal, "token.revoked", "api_token", token_id
    )
    db.commit()
    return {"status": "revoked"}


@router.get("/audit", response_model=list[schemas.AuditOut])
def get_audit(
    principal: AdminDep,
    limit: int = 100,
    db: Session = Depends(get_db),
) -> list[schemas.AuditOut]:
    return [
        _audit_out(row)
        for row in workspace.list_audit(db, principal.tenant, limit)
    ]


@router.get("/signups", response_model=list[schemas.PendingSignupOut])
def list_signups(
    principal: AdminDep, db: Session = Depends(get_db)
) -> list[schemas.PendingSignupOut]:
    return [
        schemas.PendingSignupOut(
            user_id=user.id,
            email=user.email,
            display_name=user.display_name,
            requested_at=user.created_at,
        )
        for user in accounts.list_signups(db)
    ]


@router.post(
    "/signups/{user_id}/approve", response_model=schemas.MemberOut
)
def approve_signup(
    user_id: uuid.UUID,
    body: schemas.SignupApproveIn,
    principal: AdminDep,
    db: Session = Depends(get_db),
) -> schemas.MemberOut:
    try:
        membership = accounts.approve_signup(
            db, principal.tenant, user_id, body.role
        )
    except accounts.NotPending as exc:
        raise HTTPException(
            status_code=404, detail="sign-up request not found"
        ) from exc
    workspace.record_audit(
        db,
        principal,
        "signup.approved",
        "membership",
        user_id,
        {"email": membership.user.email, "role": membership.role},
    )
    db.commit()
    db.refresh(membership)
    return _member_out(membership)


@router.delete("/signups/{user_id}")
def reject_signup(
    user_id: uuid.UUID,
    principal: AdminDep,
    db: Session = Depends(get_db),
) -> dict[str, str]:
    try:
        user = accounts.reject_signup(db, user_id)
    except accounts.NotPending as exc:
        raise HTTPException(
            status_code=404, detail="sign-up request not found"
        ) from exc
    workspace.record_audit(
        db, principal, "signup.rejected", "user", user_id, {"email": user.email}
    )
    db.commit()
    return {"status": "rejected"}
