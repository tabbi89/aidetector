"""Aggregate AI spend budgets across every phase of a scan.

The ledger is the source of truth: a budget check sums every ``TokenLedger`` row
for the workspace this calendar month, so plan, payload design, adjudication and
Q&A all draw from one pool. ``NULL`` means unlimited; a limit of zero blocks the
phase immediately. Refusals are a skip event, never a failed scan.

A paid call's cost is only knowable after the provider answers, so
:func:`reserve` claims that call's *worst case* first. The claim is a committed
row (:class:`app.models.ledger.AiBudgetReservation`), which is what makes two
concurrent callers — a Q&A request and a scanning worker, say — see each
other's spend instead of both reading the same remaining allowance.
"""
from __future__ import annotations

import uuid
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any

from sqlalchemy import delete, func, select
from sqlalchemy.orm import Session

from app.ai.limits import worst_case_micros
from app.core.config import settings
from app.models.identity import Tenant
from app.models.ledger import AiBudgetReservation, TokenLedger
from app.models.scan import Scan


class BudgetExhausted(Exception):
    """A caller on the request path (Q&A) must stop rather than degrade."""

    def __init__(self, reason: str):
        self.reason = reason
        super().__init__(f"{reason} AI budget reached")


@dataclass(frozen=True)
class Budget:
    monthly_limit_micros: int | None
    scan_limit_micros: int | None
    month_spent_micros: int
    scan_spent_micros: int

    @property
    def monthly_remaining_micros(self) -> int | None:
        if self.monthly_limit_micros is None:
            return None
        return max(0, self.monthly_limit_micros - self.month_spent_micros)

    @property
    def scan_remaining_micros(self) -> int | None:
        if self.scan_limit_micros is None:
            return None
        return max(0, self.scan_limit_micros - self.scan_spent_micros)

    def exhausted(self) -> str | None:
        if (
            self.monthly_limit_micros is not None
            and self.month_spent_micros >= self.monthly_limit_micros
        ):
            return "monthly"
        if (
            self.scan_limit_micros is not None
            and self.scan_spent_micros >= self.scan_limit_micros
        ):
            return "scan"
        return None


@dataclass(frozen=True)
class Reservation:
    """A pre-call allowance. ``id is None`` means nothing needed tracking.

    ``micros`` is the worst case it claimed: what a call that may have reached
    the provider but reported no usage is charged.
    """

    id: uuid.UUID | None = None
    micros: int = 0


def month_start(now: datetime | None = None) -> datetime:
    current = now or datetime.now(UTC)
    return datetime(current.year, current.month, 1, tzinfo=UTC)


def _reservation_cutoff(now: datetime | None = None) -> datetime:
    """Reservations older than this belong to a caller that died mid-call."""
    return (now or datetime.now(UTC)) - timedelta(
        seconds=settings.ai_reservation_ttl_seconds
    )


def spend_micros(
    db: Session, tenant_slug: str, *, since: datetime | None = None
) -> int:
    """Committed spend, from ledger rows. In-flight reservations are excluded.

    Rows carry their tenant, so the figure survives deleting the scan they
    happened in: incurred spend is not undone by cleanup.
    """
    stmt = select(func.coalesce(func.sum(TokenLedger.cost_micros), 0)).where(
        TokenLedger.tenant_slug == tenant_slug
    )
    if since is not None:
        stmt = stmt.where(TokenLedger.created_at >= since)
    return int(db.scalar(stmt) or 0)


def _reserved_micros(
    db: Session,
    tenant_slug: str,
    *,
    scan_id: uuid.UUID | None = None,
) -> int:
    """Every live claim, whatever month it was made in.

    A claim made a second before the month turned is still a call in flight:
    its ledger row will land in the new month, so it counts against the new
    month's allowance until then, and against its scan throughout.
    """
    stmt = (
        select(func.coalesce(func.sum(AiBudgetReservation.reserved_micros), 0))
        .where(
            AiBudgetReservation.tenant_slug == tenant_slug,
            AiBudgetReservation.created_at >= _reservation_cutoff(),
        )
    )
    if scan_id is not None:
        stmt = stmt.where(AiBudgetReservation.scan_id == scan_id)
    return int(db.scalar(stmt) or 0)


def load_budget(db: Session, scan: Scan) -> Budget:
    # The phase unit tests drive a fake session/scan to exercise prompt and
    # parsing behaviour without persistence. They carry no budget; treat that
    # as unlimited rather than making the test construct a database.
    tenant_slug = getattr(scan, "tenant_id", None)
    if not isinstance(db, Session) or tenant_slug is None:
        return Budget(None, None, 0, 0)
    tenant = db.get(Tenant, tenant_slug)
    start = month_start()
    scan_committed = int(
        db.scalar(
            select(func.coalesce(func.sum(TokenLedger.cost_micros), 0)).where(
                TokenLedger.scan_id == scan.id
            )
        )
        or 0
    )
    return Budget(
        monthly_limit_micros=(
            tenant.ai_monthly_micros if tenant is not None else None
        ),
        scan_limit_micros=(
            tenant.ai_per_scan_micros if tenant is not None else None
        ),
        month_spent_micros=spend_micros(db, tenant_slug, since=start)
        + _reserved_micros(db, tenant_slug),
        scan_spent_micros=scan_committed
        + _reserved_micros(db, tenant_slug, scan_id=scan.id),
    )


def _prune_expired(db: Session, tenant_slug: str) -> None:
    db.execute(
        delete(AiBudgetReservation).where(
            AiBudgetReservation.tenant_slug == tenant_slug,
            AiBudgetReservation.created_at < _reservation_cutoff(),
        )
    )


def reserve(
    db: Session,
    scan: Scan,
    phase: str,
    *,
    request: dict[str, Any],
    mode: str | None = None,
) -> Reservation | None:
    """Claim room for one paid call: the runtime call of ``mode`` (default:
    ``phase``) the planner will make with ``request``, priced at the most that
    call is allowed to cost (:mod:`app.ai.limits`).

    Returns ``None`` when the workspace or scan allowance cannot cover the
    call's worst case; otherwise a handle to release once the ledger rows land.
    The tenant row is locked only for the claim, never across the model call.
    """
    tenant_slug = getattr(scan, "tenant_id", None)
    if not isinstance(db, Session) or tenant_slug is None:
        return Reservation()
    # Priced before the lock: nothing that can raise runs while it is held.
    worst = worst_case_micros(mode or phase, request)
    tenant = db.get(Tenant, tenant_slug, with_for_update=True)
    if tenant is None:
        return Reservation()
    _prune_expired(db, tenant_slug)
    budget = load_budget(db, scan)
    if budget.exhausted() is not None:
        db.commit()
        return None
    if (
        budget.monthly_limit_micros is not None
        and budget.month_spent_micros + worst > budget.monthly_limit_micros
    ):
        db.commit()
        return None
    if (
        budget.scan_limit_micros is not None
        and budget.scan_spent_micros + worst > budget.scan_limit_micros
    ):
        db.commit()
        return None
    row = AiBudgetReservation(
        tenant_slug=tenant_slug,
        scan_id=scan.id,
        phase=phase,
        reserved_micros=worst,
    )
    db.add(row)
    # Commit now: holding the tenant row lock across the provider call would
    # serialize every run in the workspace behind one slow completion.
    db.commit()
    return Reservation(row.id, worst)


def release(db: Session | None, reservation: Reservation | None) -> None:
    if (
        db is None
        or reservation is None
        or reservation.id is None
        or not isinstance(db, Session)
    ):
        return
    db.execute(
        delete(AiBudgetReservation).where(
            AiBudgetReservation.id == reservation.id
        )
    )


def require_budget(
    db: Session, scan: Scan, emit, phase: str
) -> Budget | None:
    """Return the budget, or emit ``ai_budget_exhausted`` and return None."""
    budget = load_budget(db, scan)
    reason = budget.exhausted()
    if reason is None:
        return budget
    emit(
        "ai_budget_exhausted",
        scan.progress,
        f"{phase} skipped: {reason} AI budget reached",
    )
    return None
