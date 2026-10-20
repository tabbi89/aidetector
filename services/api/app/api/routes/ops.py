"""Deployment-operator diagnostics: queue, slow checks, tools, cleanup.

These are cross-tenant numbers, so they are reserved for an operator key
(``ENV``/open or the break-glass API key), not a workspace admin token.
"""
from __future__ import annotations

from collections import Counter
from datetime import UTC, datetime, timedelta
from statistics import median

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.core.auth import Principal, require_principal
from app.core.db import get_db
from app.models.event import ScanEvent
from app.models.scan import Scan, ScanRun, ScanStatus
from app.scans.capabilities import capabilities

router = APIRouter(prefix="/ops", tags=["operations"])


def require_operator(
    principal: Principal = Depends(require_principal),
) -> Principal:
    if principal.via not in {"env", "open"}:
        raise HTTPException(status_code=403, detail="operator key required")
    return principal


@router.get("/status")
def ops_status(
    principal: Principal = Depends(require_operator),
    db: Session = Depends(get_db),
) -> dict[str, object]:
    """One screen for the questions a slow or stuck deployment raises."""
    by_status: dict[str, int] = {}
    for status, count in db.execute(
        select(Scan.status, func.count()).group_by(Scan.status)
    ).all():
        key = status.value if hasattr(status, "value") else str(status)
        by_status[key] = int(count)
    oldest_queued = db.scalar(
        select(func.min(Scan.queued_at)).where(Scan.status == ScanStatus.queued)
    )
    per_tenant = [
        {"tenant": tenant, "running": int(count)}
        for tenant, count in db.execute(
            select(Scan.tenant_id, func.count())
            .where(Scan.status == ScanStatus.running)
            .group_by(Scan.tenant_id)
        ).all()
    ]
    recent = list(
        db.scalars(
            select(ScanRun)
            .order_by(ScanRun.finished_at.desc().nullslast())
            .limit(50)
        )
    )
    delays = [
        max(0.0, (run.claimed_at - run.queued_at).total_seconds())
        for run in recent
        if run.queued_at is not None and run.claimed_at is not None
    ]
    timings: dict[str, dict[str, int]] = {}
    for run in recent:
        for key, value in (run.check_timings or {}).items():
            if not isinstance(value, dict):
                continue
            entry = timings.setdefault(key, {"ms": 0, "requests": 0, "runs": 0})
            entry["ms"] += int(value.get("ms", 0) or 0)
            entry["requests"] += int(value.get("requests", 0) or 0)
            entry["runs"] += 1
    slow_checks = [
        {"check": key, **value}
        for key, value in sorted(
            timings.items(), key=lambda item: item[1]["ms"], reverse=True
        )[:10]
    ]
    not_run = Counter(
        tool
        for run in recent
        for tool in (run.gaps or {}).get("not_run", [])
    )
    cleanup_failures = [
        failure
        for run in recent
        for failure in (run.gaps or {}).get("cleanup_failed", [])
    ]
    budget_refusals = int(
        db.scalar(
            select(func.count())
            .select_from(ScanEvent)
            .where(
                ScanEvent.stage.in_(
                    ("ai_budget_exhausted", "tenant_run_limit")
                ),
                ScanEvent.created_at >= datetime.now(UTC) - timedelta(days=1),
            )
        )
        or 0
    )
    tools = capabilities()
    unavailable = sorted(
        name for name, cap in tools.items() if not cap.get("available", True)
    )
    return {
        "queue": {
            "by_status": by_status,
            "queued": by_status.get("queued", 0),
            "running": by_status.get("running", 0),
            "oldest_queued_at": (
                oldest_queued.isoformat() if oldest_queued is not None else None
            ),
        },
        "tenants": per_tenant,
        "queue_delay_seconds": {
            "median": median(delays) if delays else None,
            "max": max(delays) if delays else None,
            "samples": len(delays),
        },
        "slow_checks": slow_checks,
        "tools_not_run": [
            {"tool": tool, "runs": count}
            for tool, count in not_run.most_common()
        ],
        "cleanup_failures": cleanup_failures[:20],
        "budget_refusals_24h": budget_refusals,
        "unavailable_tools": unavailable,
        "tools": tools,
        "operator": principal.tenant,
    }
