"""API access control: a workspace principal, API tokens and role gates.

Three postures, in order:

- A **database token** resolves to a membership → user → role. This is the
  hosted/team path; a token belongs to one membership, so it cannot switch
  workspaces.
- A configured **environment key** (``api_keys``) resolves to an admin
  principal for that tenant. It is the break-glass/bootstrap path and preserves
  the old single-key deployment.
- With no key at all, dev/test stays **open** as an admin of the ``default``
  workspace. ``auth_required``, a configured key, a non-dev ENV, or an admin
  who signs in with a password closes that — a sign-in page in front of an API
  that answers anyone anyway would be decorative.

A password sign-in (``app/scans/accounts.py``) mints a ``session`` row in the
same token table, so it resolves through the database path like any token.

Routes take ``TenantId`` for scoping and ``ScanWriteDep``/``AdminDep`` when the
method needs a role. ``require_api_key`` remains as a tenant-only wrapper so
older route modules keep working while they migrate.
"""
from __future__ import annotations

import hashlib
import secrets
import uuid
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Annotated

from fastapi import Depends, Header, HTTPException, Request, status
from sqlalchemy import or_, select
from sqlalchemy.orm import Session, joinedload

from app.core.config import settings
from app.core.db import get_db
from app.domain.permissions import Action, Role, can
from app.models.identity import ApiToken, Membership, User


@dataclass(frozen=True)
class Principal:
    tenant: str
    role: Role
    user_id: uuid.UUID | None = None
    email: str | None = None
    display_name: str | None = None
    token_id: uuid.UUID | None = None
    via: str = "db"


def token_digest(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


def auth_required(db: Session | None = None) -> bool:
    """Whether a request without a key is refused.

    Given a session, a password-holding admin also closes the open posture.
    """
    if (
        settings.auth_required
        or bool(settings.api_key_tenants())
        or settings.env not in {"dev", "test"}
    ):
        return True
    return db is not None and password_admin_exists(db)


def password_admin_exists(db: Session) -> bool:
    return bool(
        db.scalar(
            select(Membership.id)
            .join(User, Membership.user_id == User.id)
            .where(
                Membership.role == Role.admin.value,
                User.password_hash.is_not(None),
                User.status == "active",
                User.disabled_at.is_(None),
            )
            .limit(1)
        )
    )


def _presented(
    x_api_key: str | None, authorization: str | None
) -> str | None:
    if x_api_key is not None:
        return x_api_key
    if authorization:
        scheme, _, token = authorization.partition(" ")
        if scheme.lower() == "bearer" and token:
            return token.strip()
    return None


def _env_principal(token: str) -> Principal | None:
    for key, tenant in settings.api_key_tenants().items():
        if secrets.compare_digest(token, key):
            return Principal(tenant=tenant, role=Role.admin, via="env")
    return None


def _db_principal(db: Session, token: str) -> Principal | None:
    row = db.scalar(
        select(ApiToken)
        .options(joinedload(ApiToken.membership).joinedload(Membership.user))
        .where(
            ApiToken.token_hash == token_digest(token),
            ApiToken.revoked_at.is_(None),
            or_(
                ApiToken.expires_at.is_(None),
                ApiToken.expires_at > datetime.now(UTC),
            ),
        )
    )
    if row is None:
        return None
    membership = row.membership
    user = membership.user
    if user.disabled_at is not None or user.status != "active":
        return None
    try:
        role = Role(membership.role)
    except ValueError:  # a role this version no longer knows
        return None
    return Principal(
        tenant=membership.tenant_slug,
        role=role,
        user_id=user.id,
        email=user.email,
        display_name=user.display_name,
        token_id=row.id,
        via="db",
    )


def require_principal(
    x_api_key: str | None = Header(default=None),
    authorization: str | None = Header(default=None),
    db: Session = Depends(get_db),
) -> Principal:
    presented = _presented(x_api_key, authorization)
    if presented is None:
        if auth_required(db):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="missing or invalid API key",
                headers={"WWW-Authenticate": "Bearer"},
            )
        return Principal(tenant="default", role=Role.admin, via="open")

    env = _env_principal(presented)
    if env is not None:
        return env
    stored = _db_principal(db, presented)
    if stored is not None:
        return stored
    raise HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="missing or invalid API key",
        headers={"WWW-Authenticate": "Bearer"},
    )


def current_tenant(principal: Principal = Depends(require_principal)) -> str:
    return principal.tenant


#: Tenant-only compatibility wrapper for route modules not yet migrated to
#: ``Principal``.
def require_api_key(principal: Principal = Depends(require_principal)) -> str:
    return principal.tenant


def require_action(action: Action):
    """Build a dependency that returns the principal or refuses with 403."""

    def dependency(
        principal: Principal = Depends(require_principal),
    ) -> Principal:
        if not can(principal.role, action):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=(
                    f"role '{principal.role.value}' cannot perform this action"
                ),
            )
        return principal

    return dependency


def require_mutation_role(
    request: Request,
    principal: Principal = Depends(require_principal),
) -> None:
    """Router-level gate: any non-read method needs analyst or admin."""
    if request.method in {"GET", "HEAD", "OPTIONS"}:
        return
    if not can(principal.role, Action.scan_write):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"role '{principal.role.value}' is read-only",
        )


PrincipalDep = Annotated[Principal, Depends(require_principal)]
TenantId = Annotated[str, Depends(current_tenant)]
ScanWriteDep = Annotated[Principal, Depends(require_action(Action.scan_write))]
AdminDep = Annotated[Principal, Depends(require_action(Action.workspace_admin))]
