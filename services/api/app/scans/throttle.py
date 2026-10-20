"""Fixed-window attempt counters for the unauthenticated auth routes.

Sign-in and sign-up are the only writes the API answers without a key, so they
are where password guessing and account spraying happen. Counters live in
Postgres (``auth_throttle``) so every API process shares them, and each hit is
one atomic upsert, so concurrent requests cannot both read a stale count.

Buckets never name a user: a failed sign-in for an unknown email increments a
counter exactly like one for a real account, and a locked bucket refuses a
correct password too. Otherwise the lockout itself would say which addresses
are registered, or let guessing continue past it.
"""
from __future__ import annotations

import hashlib
import math
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta

from sqlalchemy import case, delete
from sqlalchemy.dialects.postgresql import insert
from sqlalchemy.orm import Session

from app.core.config import settings
from app.models.identity import AuthThrottle


@dataclass(frozen=True)
class Limit:
    bucket: str
    max: int
    window: timedelta


def _email_digest(email: str) -> str:
    return hashlib.sha256(email.strip().lower().encode()).hexdigest()[:40]


def login_email(email: str) -> Limit:
    return Limit(
        f"login:email:{_email_digest(email)}",
        settings.auth_login_failures_per_email,
        timedelta(seconds=settings.auth_login_window_seconds),
    )


def login_ip(address: str) -> Limit:
    return Limit(
        f"login:ip:{address}"[:120],
        settings.auth_login_failures_per_ip,
        timedelta(seconds=settings.auth_login_window_seconds),
    )


def signup_ip(address: str) -> Limit:
    return Limit(
        f"signup:ip:{address}"[:120],
        settings.auth_signups_per_ip,
        timedelta(seconds=settings.auth_signup_window_seconds),
    )


def retry_after(
    db: Session, limit: Limit, *, now: datetime | None = None
) -> int | None:
    """Seconds until ``limit`` admits again, or ``None`` if it admits now."""
    now = now or datetime.now(UTC)
    # populate_existing: a row read earlier in this session is stale after hit().
    row = db.get(AuthThrottle, limit.bucket, populate_existing=True)
    if row is None or row.count < limit.max:
        return None
    ends = row.window_start + limit.window
    if ends <= now:
        return None
    return max(1, math.ceil((ends - now).total_seconds()))


def hit(db: Session, limit: Limit, *, now: datetime | None = None) -> int:
    """Count one attempt and return the count in the current window.

    An expired window restarts at one. The caller owns the transaction.
    """
    now = now or datetime.now(UTC)
    expired = AuthThrottle.window_start <= now - limit.window
    stmt = (
        insert(AuthThrottle)
        .values(bucket=limit.bucket, count=1, window_start=now)
        .on_conflict_do_update(
            index_elements=[AuthThrottle.bucket],
            set_={
                "count": case((expired, 1), else_=AuthThrottle.count + 1),
                "window_start": case((expired, now), else_=AuthThrottle.window_start),
            },
        )
        .returning(AuthThrottle.count)
    )
    return int(db.execute(stmt).scalar_one())


def clear(db: Session, limit: Limit) -> None:
    db.execute(delete(AuthThrottle).where(AuthThrottle.bucket == limit.bucket))


def prune(db: Session, *, now: datetime | None = None) -> int:
    """Delete counters whose window has closed under every limit."""
    now = now or datetime.now(UTC)
    longest = max(settings.auth_login_window_seconds, settings.auth_signup_window_seconds)
    result = db.execute(
        delete(AuthThrottle).where(
            AuthThrottle.window_start < now - timedelta(seconds=longest)
        )
    )
    return int(getattr(result, "rowcount", 0) or 0)
