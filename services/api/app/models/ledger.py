"""Token ledger — one row per AI call, so a scan's cost is a fact, not an estimate.

Cost is stored in micro-USD (1e-6 USD) integers to avoid float drift and to keep
sub-cent scans precise.
"""
from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import BigInteger, ForeignKey, String
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.models.base import Base, created_at_col, uuid_pk


class TokenLedger(Base):
    __tablename__ = "token_ledger"

    id: Mapped[uuid.UUID] = uuid_pk()
    # The tenant is recorded on the row itself: spend is an incurred fact that
    # must outlive the scan it happened in. Counting through a join to ``scans``
    # made deleting a scan look like a refund. It is deliberately not a foreign
    # key: deleting a tenant must not erase what was already spent.
    tenant_slug: Mapped[str] = mapped_column(String(120), index=True)
    scan_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("scans.id", ondelete="SET NULL"), index=True, nullable=True
    )
    # "plan" | "execute" | "adjudicate"
    phase: Mapped[str] = mapped_column(String(20))
    model: Mapped[str] = mapped_column(String(60))
    tokens_in: Mapped[int] = mapped_column(default=0)
    tokens_out: Mapped[int] = mapped_column(default=0)
    # Prompt-cache tokens, beside (not inside) tokens_in: the agent planner's
    # turns are mostly cache reads, and pricing them as nothing undercounted it.
    cache_read_tokens: Mapped[int] = mapped_column(
        BigInteger, default=0, server_default="0"
    )
    cache_write_tokens: Mapped[int] = mapped_column(
        BigInteger, default=0, server_default="0"
    )
    cost_micros: Mapped[int] = mapped_column(BigInteger, default=0)
    created_at: Mapped[datetime] = created_at_col()

    scan = relationship("Scan", back_populates="ledger")


class AiBudgetReservation(Base):
    """A paid call's worst-case cost, claimed before the call starts.

    The ledger records what a call *did* cost, which is only knowable after the
    provider answers. Without a pre-call claim two concurrent callers both read
    the same remaining allowance and both spend it. A reservation is committed
    (so the tenant lock is not held across the network call) and released when
    the ledger rows land; a process that dies mid-call leaves one behind, which
    is why :func:`app.ai.budget.reserve` ignores and deletes expired rows.
    """

    __tablename__ = "ai_budget_reservations"

    id: Mapped[uuid.UUID] = uuid_pk()
    tenant_slug: Mapped[str] = mapped_column(
        ForeignKey("tenants.slug", ondelete="CASCADE"), index=True
    )
    scan_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("scans.id", ondelete="CASCADE"), index=True
    )
    phase: Mapped[str] = mapped_column(String(30))
    reserved_micros: Mapped[int] = mapped_column(BigInteger, default=0)
    created_at: Mapped[datetime] = created_at_col()
