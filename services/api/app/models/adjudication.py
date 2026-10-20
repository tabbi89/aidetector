"""Durable AI verdict cache, scoped to one scan and finding fingerprint."""
from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import Enum, ForeignKey, String, Text, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.domain.enums import Verdict
from app.models.base import Base, created_at_col, uuid_pk


class AdjudicationCache(Base):
    __tablename__ = "adjudication_cache"
    __table_args__ = (
        UniqueConstraint(
            "scan_id", "fingerprint", "review_key",
            name="uq_adjudication_cache_scan_fingerprint_review",
        ),
    )

    id: Mapped[uuid.UUID] = uuid_pk()
    scan_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("scans.id", ondelete="CASCADE"), index=True
    )
    fingerprint: Mapped[str] = mapped_column(String(64))
    # Evidence-sensitive key used only for AI reuse. ``fingerprint`` remains the
    # stable human triage/diff identity; a changed observation gets a new review
    # key while preserving that identity for the UI.
    review_key: Mapped[str] = mapped_column(String(64), default="", server_default="")
    verdict: Mapped[Verdict] = mapped_column(Enum(Verdict, name="verdict"))
    rationale: Mapped[str] = mapped_column(Text, default="")
    # An evidence-specific fix the adjudicator wrote for a confirmed finding,
    # cached so a re-scan reuses it without re-spending tokens. Empty when the
    # model returned none (the static catalogue remediation then stands).
    remediation: Mapped[str] = mapped_column(Text, default="", server_default="")
    created_at: Mapped[datetime] = created_at_col()

    scan = relationship("Scan", back_populates="adjudication_cache")
