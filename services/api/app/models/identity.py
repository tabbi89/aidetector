"""Workspaces, people, memberships, API tokens and the audit trail.

A tenant (workspace) is a slug; scans and monitors already carry that string, so
this table is the join key rather than a new foreign key on every historical
row. A person belongs to a workspace through a membership that carries the role.
An API token belongs to one membership, which is why a token cannot silently
switch tenants.
"""
from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import (
    BigInteger,
    CheckConstraint,
    DateTime,
    ForeignKey,
    Integer,
    String,
    UniqueConstraint,
)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.models.base import Base, created_at_col, uuid_pk

__all__ = [
    "ApiToken",
    "AuditLog",
    "AuthThrottle",
    "Membership",
    "Tenant",
    "User",
]


class Tenant(Base):
    __tablename__ = "tenants"
    __table_args__ = (
        CheckConstraint("plan IN ('free', 'premium')", name="ck_tenants_plan"),
    )

    slug: Mapped[str] = mapped_column(String(120), primary_key=True)
    name: Mapped[str] = mapped_column(String(200))
    plan: Mapped[str] = mapped_column(
        String(20), default="free", server_default="free", nullable=False
    )
    #: NULL means unlimited. AI spend is micro-USD so sub-cent budgets are exact.
    ai_monthly_micros: Mapped[int | None] = mapped_column(BigInteger, nullable=True)
    ai_per_scan_micros: Mapped[int | None] = mapped_column(BigInteger, nullable=True)
    #: Active means queued + running; the queued cap is separate and can be lower.
    max_concurrent_runs: Mapped[int | None] = mapped_column(Integer, nullable=True)
    max_queued_runs: Mapped[int | None] = mapped_column(Integer, nullable=True)
    scans_per_day: Mapped[int | None] = mapped_column(Integer, nullable=True)
    created_at: Mapped[datetime] = created_at_col()


class User(Base):
    __tablename__ = "users"
    __table_args__ = (
        CheckConstraint(
            "status IN ('active', 'pending')", name="ck_users_status"
        ),
    )

    id: Mapped[uuid.UUID] = uuid_pk()
    # Stored lower-case; the unique index is what makes "add member" idempotent.
    email: Mapped[str] = mapped_column(
        String(320), unique=True, index=True, nullable=False
    )
    display_name: Mapped[str] = mapped_column(String(120))
    created_at: Mapped[datetime] = created_at_col()
    disabled_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    # ``pending`` is a self-service sign-up an admin has not approved yet: it has
    # a password but no membership, so it can authenticate to nothing.
    status: Mapped[str] = mapped_column(
        String(20), default="active", server_default="active", nullable=False
    )
    # ``scrypt$…`` (app/core/passwords.py). NULL means the person signs in with
    # an API token only — every user created before passwords existed.
    password_hash: Mapped[str | None] = mapped_column(String(255), nullable=True)


class Membership(Base):
    __tablename__ = "memberships"
    __table_args__ = (
        UniqueConstraint("tenant_slug", "user_id", name="uq_memberships_tenant_user"),
        CheckConstraint(
            "role IN ('admin', 'analyst', 'viewer')", name="ck_memberships_role"
        ),
    )

    id: Mapped[uuid.UUID] = uuid_pk()
    tenant_slug: Mapped[str] = mapped_column(
        ForeignKey("tenants.slug", ondelete="CASCADE"), index=True
    )
    user_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("users.id", ondelete="CASCADE"), index=True
    )
    role: Mapped[str] = mapped_column(
        String(20), default="viewer", server_default="viewer", nullable=False
    )
    created_at: Mapped[datetime] = created_at_col()

    tenant: Mapped[Tenant] = relationship("Tenant")
    user: Mapped[User] = relationship("User")


class ApiToken(Base):
    __tablename__ = "api_tokens"
    __table_args__ = (
        CheckConstraint("kind IN ('api', 'session')", name="ck_api_tokens_kind"),
    )

    id: Mapped[uuid.UUID] = uuid_pk()
    membership_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("memberships.id", ondelete="CASCADE"), index=True
    )
    # SHA-256 of the presented token. The plaintext is shown once at creation and
    # never stored, echoed by a GET or written to the audit log.
    token_hash: Mapped[str] = mapped_column(
        String(64), unique=True, index=True, nullable=False
    )
    prefix: Mapped[str] = mapped_column(String(12))
    last4: Mapped[str] = mapped_column(String(4))
    label: Mapped[str] = mapped_column(String(120), default="", server_default="")
    # ``session`` is minted by a password sign-in, always expires, and is kept
    # out of the workspace's token list; ``api`` is one an admin issued.
    kind: Mapped[str] = mapped_column(
        String(20), default="api", server_default="api", nullable=False
    )
    created_at: Mapped[datetime] = created_at_col()
    last_used_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    expires_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    revoked_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )

    membership: Mapped[Membership] = relationship("Membership")


class AuditLog(Base):
    __tablename__ = "audit_log"

    id: Mapped[uuid.UUID] = uuid_pk()
    tenant_slug: Mapped[str] = mapped_column(
        ForeignKey("tenants.slug", ondelete="CASCADE"), index=True
    )
    actor_user_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL"), nullable=True, index=True
    )
    action: Mapped[str] = mapped_column(String(80), index=True)
    object_type: Mapped[str] = mapped_column(String(40))
    object_id: Mapped[str] = mapped_column(String(120), default="")
    # Value-free context (names, roles, counts); never evidence or secrets.
    summary: Mapped[dict] = mapped_column(JSONB, default=dict, server_default="{}")
    created_at: Mapped[datetime] = created_at_col()

    actor: Mapped[User | None] = relationship("User")


class RunAdmission(Base):
    """One accepted execution, recorded when the admission gate lets it in.

    The daily allowance counts these, not scans or runs: one scan run three
    times is three executions, a queued execution counts before it has a run
    row, and deleting a scan's history does not refund its allowance (the scan
    link is nulled, the row stays).
    """

    __tablename__ = "run_admissions"

    id: Mapped[uuid.UUID] = uuid_pk()
    tenant_slug: Mapped[str] = mapped_column(
        ForeignKey("tenants.slug", ondelete="CASCADE"), index=True
    )
    scan_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("scans.id", ondelete="SET NULL"), nullable=True, index=True
    )
    # "manual" | "schedule" | "local"
    source: Mapped[str] = mapped_column(String(20))
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), index=True
    )


class AuthThrottle(Base):
    """A fixed-window attempt counter for the unauthenticated auth routes.

    Keyed by an opaque bucket (``login:email:<digest>``, ``login:ip:<addr>``,
    ``signup:ip:<addr>``) rather than a user id, so an email with no account
    is counted exactly like one with an account and a lockout cannot be used
    to discover which addresses are registered. Emails are stored as a digest.
    """

    __tablename__ = "auth_throttle"

    bucket: Mapped[str] = mapped_column(String(120), primary_key=True)
    count: Mapped[int] = mapped_column(Integer, nullable=False)
    window_start: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), index=True, nullable=False
    )
