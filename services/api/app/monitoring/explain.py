"""On-demand AI explanation of one monitoring observation.

An explanation is commentary stored beside the observation. It never changes the
observation's type, confidence, disposition or fingerprint, and a provider that
is disabled or failing records a fixed reason instead of failing anything.
"""

from __future__ import annotations

import json
import time
import uuid
from collections.abc import Mapping
from datetime import UTC, datetime

from fastapi import HTTPException
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.ai.provider import ProviderUnavailable, build_monitoring_provider
from app.core.db import SessionLocal
from app.models.monitoring import EvidenceSource, InfrastructureMonitor, MonitoringRun
from app.monitoring import sources
from app.monitoring.contracts import SourceUnavailable

#: Observation fields a provider may see. Cohorts are HMACs of people and are left out.
SHARED_FIELDS = (
    "type",
    "route_family",
    "method",
    "hours",
    "confidence",
    "severity",
    "current",
    "baseline_days",
    "baseline_requests",
    "remediation",
)
MAX_TEXT = 8000
MAX_STRUCTURED_BYTES = 32_000
MAX_LOG_LINES = 60
LOG_WRITE_INTERVAL = 1.0


def shared_observation(observation: dict) -> dict:
    shared = {key: observation[key] for key in SHARED_FIELDS if key in observation}
    if isinstance(shared.get("current"), dict):
        shared["current"] = {k: v for k, v in shared["current"].items() if k != "cohort"}
    return shared


def day_sampling(run: MonitoringRun) -> dict:
    """How much of the day the WAF evidence saw, against the load balancer's own count.

    A sampled day keeps only the newest events of each UTC hour: the tail of every
    hour, not a random draw. Counts in its leads are counts within that tail, and a
    client missing from it may simply have been active earlier in the hour.
    """
    metrics = run.metrics or {}
    sample = metrics.get("sample")
    if not isinstance(sample, dict):
        return {"method": "every_event"}
    kept = int(sample.get("kept") or metrics.get("event_count") or 0)
    result: dict = {
        "method": sample.get("strategy") or "newest_per_hour",
        "per_hour": sample.get("per_hour"),
        "kept": kept,
    }
    origin = metrics.get("origin")
    total = origin.get("total") if isinstance(origin, dict) else None
    requests = total.get("requests") if isinstance(total, dict) else None
    if isinstance(requests, int | float) and requests > 0:
        result["load_balancer_requests"] = int(requests)
        result["kept_share"] = round(kept / requests, 4)
    return result


def find_observation(run: MonitoringRun, fingerprint: str) -> dict | None:
    return next((o for o in run.observations if o.get("fingerprint") == fingerprint), None)


def _store(run: MonitoringRun, fingerprint: str, value: dict) -> bool:
    if find_observation(run, fingerprint) is None:
        return False
    # Reassign rather than mutate so the JSONB change is detected.
    run.observations = [
        {**o, "ai_explanation": value} if o.get("fingerprint") == fingerprint else o
        for o in run.observations
    ]
    return True


def _now() -> str:
    return datetime.now(UTC).isoformat()


def request(
    db: Session, monitor: InfrastructureMonitor, run_id: uuid.UUID, fingerprint: str
) -> MonitoringRun:
    run = db.scalar(
        select(MonitoringRun)
        .where(MonitoringRun.id == run_id, MonitoringRun.monitor_id == monitor.id)
        .with_for_update()
    )
    if run is None or not _store(run, fingerprint, {"status": "pending", "requested_at": _now()}):
        raise HTTPException(404, "observation not found")
    db.commit()
    return run


def mark_unavailable(db: Session, run: MonitoringRun, fingerprint: str, reason: str) -> None:
    _store(run, fingerprint, {"status": "unavailable", "reason": reason, "finished_at": _now()})
    db.commit()


class AgentLog:
    """Value-free agent progress, saved on the pending explanation as it arrives."""

    def __init__(self, run_id: uuid.UUID, fingerprint: str, requested_at: object) -> None:
        self.run_id, self.fingerprint, self.requested_at = run_id, fingerprint, requested_at
        self.lines: list[dict[str, str]] = []
        self._written = 0.0

    def add(self, text: str, at: str | None = None) -> None:
        text = text.strip()[:300]
        if not text:
            return
        self.lines.append({"at": (at or _now())[:40], "text": text})
        del self.lines[:-MAX_LOG_LINES]
        if time.monotonic() - self._written >= LOG_WRITE_INTERVAL:
            self._written = time.monotonic()
            self._persist()

    def event(self, event: Mapping[str, object]) -> None:
        self.add(str(event.get("text") or ""), str(event.get("t") or "") or None)

    def _persist(self) -> None:
        with SessionLocal() as db:
            run = db.scalar(
                select(MonitoringRun)
                .where(MonitoringRun.id == self.run_id)
                .with_for_update()
                .execution_options(populate_existing=True)
            )
            observation = find_observation(run, self.fingerprint) if run else None
            explanation = (observation or {}).get("ai_explanation") or {}
            # Only the request this log belongs to, and only while it is running.
            if (
                run is None
                or explanation.get("status") != "pending"
                or explanation.get("requested_at") != self.requested_at
            ):
                db.rollback()
                return
            _store(run, self.fingerprint, {**explanation, "log": list(self.lines)})
            db.commit()


def repository_token(db: Session, monitor: InfrastructureMonitor) -> str | None:
    """The monitor's own read-only GitHub token, while its repository binding holds.

    Raises ``SourceUnavailable`` when the monitor names a repository whose source
    was revoked, replaced, or belongs to another tenant.
    """
    if not monitor.context.get("repository"):
        return None
    source_id = monitor.context.get("repository_source_id")
    try:
        source = db.get(EvidenceSource, uuid.UUID(str(source_id))) if source_id else None
    except ValueError:
        source = None
    if (
        source is None
        or source.tenant_id != monitor.tenant_id
        or source.connector != "github"
        or source.status == "revoked"
        or source.revision != monitor.context.get("repository_revision")
    ):
        raise SourceUnavailable("repository_unavailable")
    token = sources.read_credentials(source).get("github_token")
    return str(token) if token else None


def run_explanation(monitor_id: str, run_id: str, fingerprint: str) -> dict:
    with SessionLocal() as db:
        monitor = db.get(InfrastructureMonitor, uuid.UUID(monitor_id))
        run = db.get(MonitoringRun, uuid.UUID(run_id))
        observation = find_observation(run, fingerprint) if run else None
        if monitor is None or run is None or run.monitor_id != monitor.id or observation is None:
            return {"status": "missing"}
        route = observation.get("route_family")
        context = {
            "repository": monitor.context.get("repository"),
            "routes": [r for r in monitor.context.get("routes", []) if r.get("path") == route],
            "sampling": day_sampling(run),
        }
        payload = shared_observation(observation)
        requested_at = (observation.get("ai_explanation") or {}).get("requested_at")
        log = AgentLog(run.id, fingerprint, requested_at)
        token: str | None = None
        blocked: str | None = None
        try:
            token = repository_token(db, monitor)
        except SourceUnavailable as exc:
            blocked = exc.code
        db.commit()  # hold no row lock across a slow provider call
        value: dict
        if blocked:
            value = {"status": "unavailable", "reason": blocked}
        else:
            log.add("Preparing value-free evidence and read-only repository access")
            try:
                response = build_monitoring_provider().explain(
                    payload, context=context, github_token=token, on_event=log.event
                )
                structured = response.structured
                if structured is not None and len(json.dumps(structured)) > MAX_STRUCTURED_BYTES:
                    structured = None
                value = {
                    "status": "complete",
                    "provider": response.provider,
                    "model": response.model,
                    "text": response.text[:MAX_TEXT],
                    "structured": structured,
                    "tokens_in": sum(u.tokens_in for u in response.usages),
                    "tokens_out": sum(u.tokens_out for u in response.usages),
                }
            except ProviderUnavailable as exc:
                value = {"status": "unavailable", "reason": exc.code}
            except Exception:  # noqa: BLE001 — an AI failure never fails monitoring
                value = {"status": "unavailable", "reason": "provider_error"}
        value["finished_at"] = _now()
        value["log"] = log.lines
        locked = db.scalar(
            select(MonitoringRun)
            .where(MonitoringRun.id == run.id)
            .with_for_update()
            .execution_options(populate_existing=True)
        )
        if locked is None or not _store(locked, fingerprint, value):
            db.rollback()
            return {"status": "missing"}
        db.commit()
        return {"status": value["status"]}
