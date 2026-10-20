"""Scan progress events — a lightweight stream the UI polls to show live status."""
from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import BigInteger, ForeignKey, Identity, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.models.base import Base, created_at_col, uuid_pk


class ScanEvent(Base):
    __tablename__ = "scan_events"

    id: Mapped[uuid.UUID] = uuid_pk()
    # Monotonic insertion order. Events written in one transaction share
    # ``created_at`` (server default now()), so a bounded latest-page read must
    # order by this rather than by the timestamp/UUID.
    seq: Mapped[int] = mapped_column(
        BigInteger, Identity(), nullable=False, index=True
    )
    scan_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("scans.id", ondelete="CASCADE"), index=True
    )
    stage: Mapped[str] = mapped_column(String(60))
    pct: Mapped[int] = mapped_column(default=0)
    message: Mapped[str] = mapped_column(Text, default="")
    created_at: Mapped[datetime] = created_at_col()

    scan = relationship("Scan", back_populates="events")
