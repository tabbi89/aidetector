"""Workspace membership, people, API tokens and the audit trail.

All functions are tenant-scoped by the caller's workspace slug. The token
plaintext is returned once from :func:`create_token` and never stored; only its
SHA-256 digest reaches the database.
"""
from __future__ import annotations

import secrets
import uuid
from datetime import UTC, datetime

from sqlalchemy import func, select
from sqlalchemy.orm import Session, joinedload

from app.core.auth import Principal, token_digest
from app.core.config import settings
from app.domain.permissions import Role
from app.models.identity import (
    ApiToken,
    AuditLog,
    Membership,
    RunAdmission,
    Tenant,
    User,
)
from app.models.scan import Scan, ScanStatus


class DuplicateMember(Exception):
    """That person is already a member of this workspace."""


class NotAMember(Exception):
    """No membership for that user in this workspace."""


class LastAdmin(Exception):
    """The change would leave the workspace with no administrator."""


class RunLimit(Exception):
    """The workspace's active/queued/daily run limit refused this run."""

    def __init__(self, reason: str):
        self.reason = reason
        super().__init__(reason)


def admit_run(
    db: Session,
    slug: str,
    *,
    scan_id: uuid.UUID | None = None,
    source: str = "manual",
    now: datetime | None = None,
) -> RunAdmission | None:
    """Enforce the workspace's run limits under a row lock, and record the
    accepted execution. Returns that record (``None`` for a workspace with no
    tenant row), so a caller whose execution then fails to queue can delete it.

    ``max_concurrent_runs`` counts queued + running so a burst cannot pile up
    behind one worker. The tenant row lock serializes two enqueues, making the
    count exact rather than advisory. The daily allowance counts
    :class:`RunAdmission` rows — one per accepted execution, written here and
    flushed so a later admission in the same transaction sees it.
    """
    tenant = db.get(Tenant, slug, with_for_update=True)
    if tenant is None:
        return None
    active = int(
        db.scalar(
            select(func.count())
            .select_from(Scan)
            .where(
                Scan.tenant_id == slug,
                Scan.status.in_((ScanStatus.queued, ScanStatus.running)),
            )
        )
        or 0
    )
    if (
        tenant.max_concurrent_runs is not None
        and active >= tenant.max_concurrent_runs
    ):
        raise RunLimit("concurrent_run_limit")
    queued = int(
        db.scalar(
            select(func.count())
            .select_from(Scan)
            .where(
                Scan.tenant_id == slug,
                Scan.status == ScanStatus.queued,
            )
        )
        or 0
    )
    if tenant.max_queued_runs is not None and queued >= tenant.max_queued_runs:
        raise RunLimit("queued_run_limit")
    current = now or datetime.now(UTC)
    if tenant.scans_per_day is not None:
        day = current.replace(hour=0, minute=0, second=0, microsecond=0)
        used = int(
            db.scalar(
                select(func.count())
                .select_from(RunAdmission)
                .where(
                    RunAdmission.tenant_slug == slug,
                    RunAdmission.created_at >= day,
                )
            )
            or 0
        )
        if used >= tenant.scans_per_day:
            raise RunLimit("daily_scan_limit")
    admission = RunAdmission(
        tenant_slug=slug, scan_id=scan_id, source=source, created_at=current
    )
    db.add(admission)
    db.flush()
    return admission


def ensure_tenant(db: Session, slug: str, name: str | None = None) -> Tenant:
    """Return the workspace row, creating it for an operator/bootstrap key."""
    tenant = db.get(Tenant, slug)
    if tenant is None:
        tenant = Tenant(slug=slug, name=name or slug.replace("-", " ").title())
        db.add(tenant)
        db.flush()
    return tenant


def list_members(db: Session, slug: str) -> list[Membership]:
    return list(
        db.scalars(
            select(Membership)
            .where(Membership.tenant_slug == slug)
            .options(joinedload(Membership.user))
            .order_by(Membership.created_at, Membership.user_id)
        )
    )


def find_membership(
    db: Session, slug: str, user_id: uuid.UUID
) -> Membership | None:
    return db.scalar(
        select(Membership)
        .where(
            Membership.tenant_slug == slug,
            Membership.user_id == user_id,
        )
        .options(joinedload(Membership.user))
    )


def add_member(
    db: Session,
    slug: str,
    *,
    email: str,
    display_name: str,
    role: Role,
) -> Membership:
    email = email.strip().lower()
    user = db.scalar(select(User).where(User.email == email))
    if user is None:
        user = User(
            email=email,
            display_name=display_name.strip() or email.split("@")[0],
        )
        db.add(user)
        db.flush()
    if db.scalar(
        select(Membership.id).where(
            Membership.tenant_slug == slug, Membership.user_id == user.id
        )
    ):
        raise DuplicateMember(email)
    membership = Membership(
        tenant_slug=slug, user_id=user.id, role=role.value
    )
    db.add(membership)
    db.flush()
    return membership


def _admin_count(
    db: Session, slug: str, *, exclude_user_id: uuid.UUID | None = None
) -> int:
    stmt = select(func.count()).select_from(Membership).where(
        Membership.tenant_slug == slug,
        Membership.role == Role.admin.value,
    )
    if exclude_user_id is not None:
        stmt = stmt.where(Membership.user_id != exclude_user_id)
    return int(db.scalar(stmt) or 0)


def change_role(
    db: Session, slug: str, user_id: uuid.UUID, role: Role
) -> Membership:
    # Lock the workspace row for the whole check-and-write. Without it two
    # admins demoting each other concurrently each see the other still present,
    # both pass the last-admin check, and the workspace ends with none.
    db.get(Tenant, slug, with_for_update=True)
    membership = find_membership(db, slug, user_id)
    if membership is None:
        raise NotAMember(str(user_id))
    if (
        membership.role == Role.admin.value
        and role is not Role.admin
        and _admin_count(db, slug, exclude_user_id=user_id) == 0
    ):
        raise LastAdmin()
    membership.role = role.value
    db.flush()
    return membership


def remove_member(db: Session, slug: str, user_id: uuid.UUID) -> None:
    # Same serialization as change_role: removal is the other way to lose the
    # last administrator.
    db.get(Tenant, slug, with_for_update=True)
    membership = find_membership(db, slug, user_id)
    if membership is None:
        raise NotAMember(str(user_id))
    if (
        membership.role == Role.admin.value
        and _admin_count(db, slug, exclude_user_id=user_id) == 0
    ):
        raise LastAdmin()
    db.delete(membership)
    db.flush()


def create_token(
    db: Session,
    slug: str,
    user_id: uuid.UUID,
    *,
    label: str,
    expires_at: datetime | None,
) -> tuple[str, ApiToken, Membership]:
    membership = find_membership(db, slug, user_id)
    if membership is None:
        raise NotAMember(str(user_id))
    raw = secrets.token_urlsafe(32)
    token = ApiToken(
        membership_id=membership.id,
        token_hash=token_digest(raw),
        prefix=raw[:8],
        last4=raw[-4:],
        label=label.strip(),
        expires_at=expires_at,
    )
    db.add(token)
    db.flush()
    return raw, token, membership


def list_tokens(db: Session, slug: str) -> list[ApiToken]:
    return list(
        db.scalars(
            select(ApiToken)
            .join(Membership, ApiToken.membership_id == Membership.id)
            .where(
                Membership.tenant_slug == slug,
                ApiToken.revoked_at.is_(None),
                # Browser sign-in sessions are not workspace credentials.
                ApiToken.kind == "api",
            )
            .options(joinedload(ApiToken.membership).joinedload(Membership.user))
            .order_by(ApiToken.created_at.desc())
        )
    )


def revoke_token(db: Session, slug: str, token_id: uuid.UUID) -> bool:
    token = db.scalar(
        select(ApiToken)
        .join(Membership, ApiToken.membership_id == Membership.id)
        .where(
            ApiToken.id == token_id,
            Membership.tenant_slug == slug,
        )
    )
    if token is None:
        return False
    token.revoked_at = datetime.now(UTC)
    db.flush()
    return True


def record_audit(
    db: Session,
    principal: Principal,
    action: str,
    object_type: str,
    object_id: object,
    summary: dict | None = None,
) -> None:
    """Append a value-free audit row. The caller owns the transaction."""
    # The test harness truncates every table, including the migration-seeded
    # default workspace; an audit row must not fail on the FK because of that.
    ensure_tenant(db, principal.tenant)
    db.add(
        AuditLog(
            tenant_slug=principal.tenant,
            actor_user_id=principal.user_id,
            action=action,
            object_type=object_type,
            object_id=str(object_id),
            summary=summary or {},
        )
    )


def list_audit(db: Session, slug: str, limit: int = 100) -> list[AuditLog]:
    return list(
        db.scalars(
            select(AuditLog)
            .where(AuditLog.tenant_slug == slug)
            .options(joinedload(AuditLog.actor))
            .order_by(AuditLog.created_at.desc())
            .limit(min(max(limit, 1), 500))
        )
    )


def member_count(db: Session, slug: str) -> int:
    return int(
        db.scalar(
            select(func.count())
            .select_from(Membership)
            .where(Membership.tenant_slug == slug)
        )
        or 0
    )


def member_user(db: Session, slug: str, user_id: uuid.UUID) -> User | None:
    """A user who belongs to ``slug``; used to validate an assignee."""
    return db.scalar(
        select(User)
        .join(Membership, Membership.user_id == User.id)
        .where(
            Membership.tenant_slug == slug,
            User.id == user_id,
            User.disabled_at.is_(None),
        )
    )


def is_premium(db: Session, slug: str) -> bool:
    """Config override first, then the workspace's own plan."""
    allowed = settings.premium_tenant_set()
    if "*" in allowed or slug in allowed:
        return True
    tenant = db.get(Tenant, slug)
    return tenant is not None and tenant.plan == "premium"
