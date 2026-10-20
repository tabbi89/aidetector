"""Ownership verification for public scan targets.

One row per (workspace, host): the random token the workspace publishes as a
DNS TXT record and serves over HTTP, plus the result of the last explicit
check. The token is not a secret — it is published in DNS by design — but it is
bound to one workspace, so a record another workspace planted proves nothing
for this one. Scan-start gates re-run the proof live rather than trusting
``verified_at``; that column is what the UI shows.
"""
from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import DateTime, ForeignKey, String, UniqueConstraint
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column

from app.models.base import Base, created_at_col, uuid_pk

__all__ = ["DomainVerification"]


class DomainVerification(Base):
    __tablename__ = "domain_verifications"
    __table_args__ = (
        UniqueConstraint("tenant_slug", "host", name="uq_domain_verifications_tenant_host"),
    )

    id: Mapped[uuid.UUID] = uuid_pk()
    tenant_slug: Mapped[str] = mapped_column(
        ForeignKey("tenants.slug", ondelete="CASCADE"), index=True
    )
    #: Exact host (``api.example.com``) or IP literal; never a URL or wildcard.
    host: Mapped[str] = mapped_column(String(255))
    token: Mapped[str] = mapped_column(String(64))
    verified_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    last_checked_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    last_error: Mapped[str | None] = mapped_column(String(1000), nullable=True)
    #: Each proof's outcome from the last explicit check
    #: (``[{"proof": "dns"|"http", "ok": bool, "detail": str | None}]``), so the
    #: UI can say which half is missing. Null before the first check, or when
    #: the egress policy refused the host before either proof ran.
    last_checks: Mapped[list | None] = mapped_column(JSONB, nullable=True)
    created_by_user_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )
    created_at: Mapped[datetime] = created_at_col()
