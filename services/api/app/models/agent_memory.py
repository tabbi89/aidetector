"""Episodic memory for the heavy-lane agent — what worked on a target before.

One row per (tenant, target host, finding fingerprint): the heavy run that found
it writes it, the next heavy run against the same host recalls it. A row keeps
only what a finding already keeps — the fingerprint (free of harvested ids and
values), the check, the grade and a short title — plus a small offline embedding
(``app/agent/memory.py``) for similarity recall. No target value is stored, the
same rule as the findings table it is derived from.
"""
from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import DateTime, Integer, String, UniqueConstraint, func
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column

from app.models.base import Base, uuid_pk


class AgentMemory(Base):
    __tablename__ = "agent_memory"
    __table_args__ = (
        UniqueConstraint("tenant_id", "target_host", "fingerprint", name="uq_agent_memory_key"),
    )

    id: Mapped[uuid.UUID] = uuid_pk()
    tenant_id: Mapped[str] = mapped_column(String(120), default="default", index=True)
    #: scheme://host(:port) — the grouping key (see ``memory.host_of``).
    target_host: Mapped[str] = mapped_column(String(255), index=True)
    #: The finding's stable identity, stamped server-side by ``append_finding``.
    fingerprint: Mapped[str] = mapped_column(String(64))
    check: Mapped[str] = mapped_column(String(100))
    severity: Mapped[str] = mapped_column(String(20))
    confidence: Mapped[str] = mapped_column(String(20))
    title: Mapped[str] = mapped_column(String(255), default="")
    #: Offline token-hash embedding, as a JSON float list (no pgvector needed).
    embedding: Mapped[list] = mapped_column(JSONB(), default=list)
    #: How many heavy runs have seen this weakness on this host.
    hits: Mapped[int] = mapped_column(Integer, default=1)
    first_seen_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )
    last_seen_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now()
    )
