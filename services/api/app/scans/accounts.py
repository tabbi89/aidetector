"""Password accounts: self-service sign-up, admin approval and sign-in sessions.

A sign-up creates a ``pending`` user with a password and **no membership**, so
it can authenticate to nothing until an admin approves it into the workspace
with a role. Sign-in verifies the password and mints a ``session`` API token
that always expires; every route then resolves it like any other token.

Two rules keep sign-up from being a way into someone else's account:

- An email that already exists is never touched — no password is set, no status
  changes — and the caller gets the same answer as for a new one. Otherwise a
  sign-up could plant a password on a member an admin added by email.
- An unknown email still costs one scrypt verification at sign-in, so timing
  does not reveal which addresses have accounts.
"""
from __future__ import annotations

import secrets
import uuid
from datetime import UTC, datetime, timedelta

from sqlalchemy import select
from sqlalchemy.orm import Session, joinedload

from app.core.auth import token_digest
from app.core.config import settings
from app.core.passwords import (
    dummy_hash,
    hash_password,
    needs_rehash,
    verify_password,
)
from app.domain.permissions import Role
from app.models.identity import ApiToken, Membership, Tenant, User
from app.scans import throttle
from app.scans.workspace import ensure_tenant


class InvalidLogin(Exception):
    """Unknown email, wrong password, or a disabled account — deliberately one
    error, so the answer does not say which."""


class AwaitingApproval(Exception):
    """The password is right but no admin has approved the account yet."""


class NoWorkspace(Exception):
    """The account is active but belongs to no workspace (it was removed)."""


class NotPending(Exception):
    """No pending sign-up with that id."""


def _normal(email: str) -> str:
    return email.strip().lower()


def request_signup(
    db: Session, *, email: str, display_name: str, password: str
) -> None:
    """Record a pending sign-up, or do nothing if the email is taken."""
    email = _normal(email)
    if db.scalar(select(User.id).where(User.email == email)) is not None:
        return
    db.add(
        User(
            email=email,
            display_name=display_name.strip() or email.split("@")[0],
            status="pending",
            password_hash=hash_password(password),
        )
    )
    db.flush()


def authenticate(db: Session, *, email: str, password: str) -> Membership:
    user = db.scalar(select(User).where(User.email == _normal(email)))
    if user is None or user.password_hash is None:
        verify_password(password, dummy_hash())
        raise InvalidLogin()
    if not verify_password(password, user.password_hash):
        raise InvalidLogin()
    if user.disabled_at is not None:
        raise InvalidLogin()
    if user.status == "pending":
        raise AwaitingApproval()
    if needs_rehash(user.password_hash):
        user.password_hash = hash_password(password)
    membership = db.scalar(
        select(Membership)
        .where(Membership.user_id == user.id)
        .options(joinedload(Membership.user))
        .order_by(Membership.created_at)
        .limit(1)
    )
    if membership is None:
        raise NoWorkspace()
    return membership


def start_session(
    db: Session, membership: Membership, *, now: datetime | None = None
) -> tuple[str, ApiToken]:
    """Mint an expiring session token; the plaintext is returned once."""
    raw = secrets.token_urlsafe(32)
    token = ApiToken(
        membership_id=membership.id,
        token_hash=token_digest(raw),
        prefix=raw[:8],
        last4=raw[-4:],
        label="web session",
        kind="session",
        expires_at=(now or datetime.now(UTC))
        + timedelta(hours=settings.session_hours),
    )
    db.add(token)
    db.flush()
    return raw, token


def end_session(db: Session, token_id: uuid.UUID) -> bool:
    """Revoke a session token. An admin-issued API token is left alone:
    signing out of the browser must not break someone's pipeline."""
    token = db.get(ApiToken, token_id)
    if token is None or token.kind != "session" or token.revoked_at is not None:
        return False
    token.revoked_at = datetime.now(UTC)
    db.flush()
    return True


def list_signups(db: Session) -> list[User]:
    return list(
        db.scalars(
            select(User)
            .where(User.status == "pending")
            .order_by(User.created_at, User.id)
        )
    )


def _pending(db: Session, user_id: uuid.UUID) -> User:
    user = db.get(User, user_id, with_for_update=True)
    if user is None or user.status != "pending":
        raise NotPending(str(user_id))
    return user


def approve_signup(
    db: Session, slug: str, user_id: uuid.UUID, role: Role
) -> Membership:
    user = _pending(db, user_id)
    ensure_tenant(db, slug)
    user.status = "active"
    membership = Membership(tenant_slug=slug, user_id=user.id, role=role.value)
    db.add(membership)
    db.flush()
    db.refresh(membership)
    return membership


def reject_signup(db: Session, user_id: uuid.UUID) -> User:
    """Delete the request outright, so the person may ask again later."""
    user = _pending(db, user_id)
    db.delete(user)
    db.flush()
    return user


def bootstrap_admin(
    db: Session,
    *,
    email: str,
    display_name: str,
    password: str,
    tenant: str = "default",
) -> Membership:
    """Create the workspace admin, or reset an existing person's password and
    make them admin. The operator path: it runs from a shell, never over HTTP.
    It also lifts a sign-in lockout on that email, so an attacker who keeps
    the admin's email locked cannot keep the admin out."""
    email = _normal(email)
    throttle.clear(db, throttle.login_email(email))
    db.get(Tenant, ensure_tenant(db, tenant).slug, with_for_update=True)
    user = db.scalar(select(User).where(User.email == email))
    if user is None:
        user = User(email=email, display_name=display_name.strip() or email)
        db.add(user)
    user.status = "active"
    user.disabled_at = None
    user.password_hash = hash_password(password)
    db.flush()
    membership = db.scalar(
        select(Membership).where(
            Membership.tenant_slug == tenant, Membership.user_id == user.id
        )
    )
    if membership is None:
        membership = Membership(
            tenant_slug=tenant, user_id=user.id, role=Role.admin.value
        )
        db.add(membership)
    membership.role = Role.admin.value
    db.flush()
    return membership
