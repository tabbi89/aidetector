"""Finding work items and comments — the premium team-triage workflow.

A work item is keyed by the finding's fingerprint, which is what survives a
re-run, so an owner, a due date and a discussion follow the finding rather than
its row. Nothing here is derived from finding evidence: a comment is free text a
person wrote, and the same rule that keeps target values out of the findings
table keeps them out of these rows.
"""
from __future__ import annotations

import uuid
from datetime import date, datetime

from sqlalchemy import (
    CheckConstraint,
    Date,
    DateTime,
    ForeignKey,
    String,
    Text,
    UniqueConstraint,
    func,
)
from sqlalchemy.orm import Mapped, mapped_column

from app.models.base import Base, created_at_col, uuid_pk

#: The states a work item may hold. A team-workflow word, not a detection
#: concept, so it lives here rather than in ``app/domain``.
WORK_STATUSES = ("open", "in_progress", "resolved", "accepted_risk")

_STATUS_CHECK = "status IN ('open', 'in_progress', 'resolved', 'accepted_risk')"


class FindingWork(Base):
    __tablename__ = "finding_work"
    __table_args__ = (
        UniqueConstraint("scan_id", "fingerprint", name="uq_finding_work_scan_fingerprint"),
        CheckConstraint(_STATUS_CHECK, name="ck_finding_work_status"),
    )

    id: Mapped[uuid.UUID] = uuid_pk()
    scan_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("scans.id", ondelete="CASCADE"), index=True
    )
    #: The finding's stable identity (``app/engine/fingerprint.py``).
    fingerprint: Mapped[str] = mapped_column(String(64))
    #: Display snapshot of the assignee, kept for rows written before people
    #: existed and so a deleted user still renders on the work item.
    owner: Mapped[str | None] = mapped_column(String(120), nullable=True)
    #: The assignable person, when the owner is a workspace member.
    owner_user_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL"), nullable=True, index=True
    )
    due_date: Mapped[date | None] = mapped_column(Date, nullable=True)
    status: Mapped[str] = mapped_column(String(20), default="open", server_default="open")
    created_at: Mapped[datetime] = created_at_col()
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now()
    )


class FindingComment(Base):
    __tablename__ = "finding_comment"

    id: Mapped[uuid.UUID] = uuid_pk()
    scan_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("scans.id", ondelete="CASCADE"), index=True
    )
    fingerprint: Mapped[str] = mapped_column(String(64), index=True)
    #: The caller's display name at the time of writing (snapshot).
    author: Mapped[str] = mapped_column(String(120))
    #: The person who wrote it; null for a comment written by an operator key.
    author_user_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL"), nullable=True, index=True
    )
    body: Mapped[str] = mapped_column(Text)
    created_at: Mapped[datetime] = created_at_col()
