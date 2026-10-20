"""Read-only infrastructure telemetry monitoring API."""

from __future__ import annotations

import uuid
from datetime import UTC, date, datetime, timedelta
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Path, Query, Request, Response
from kombu.exceptions import OperationalError as BrokerUnavailable
from sqlalchemy import delete, select
from sqlalchemy.orm import Session
from starlette.concurrency import run_in_threadpool

from app.api import schemas
from app.core.auth import PrincipalDep, require_api_key, require_mutation_role
from app.core.db import get_db
from app.core.target_guard import TargetNotAllowed
from app.models.monitoring import (
    EvidenceAudit,
    EvidenceSource,
    InfrastructureMonitor,
    MonitoringAlert,
    MonitoringRapidRun,
    MonitoringRun,
)
from app.monitoring import service, sources
from app.monitoring.connectors import MAX_SNAPSHOT_BYTES
from app.scans.policy import require_target_allowed

router = APIRouter(
    prefix="/monitoring",
    tags=["infrastructure monitoring"],
    dependencies=[Depends(require_mutation_role)],
)
TenantId = Annotated[str, Depends(require_api_key)]


def _audit(
    db: Session,
    principal: PrincipalDep,
    action: str,
    object_type: str,
    object_id: object,
    summary: dict | None = None,
) -> None:
    """Append a value-free audit row for a monitoring mutation."""
    from app.scans import workspace

    workspace.record_audit(db, principal, action, object_type, object_id, summary)
    db.commit()


@router.post("/sources", response_model=schemas.EvidenceSourceOut, status_code=201)
def create_source(
    body: schemas.EvidenceSourceCreate,
    tenant_id: TenantId,
    principal: PrincipalDep,
    db: Session = Depends(get_db),
) -> EvidenceSource:
    row = sources.save_source(db, tenant_id, body)
    _audit(db, principal, "monitoring.source_created", "evidence_source", row.id,
           {"connector": row.connector})
    return row


@router.get("/sources", response_model=list[schemas.EvidenceSourceOut])
def list_sources(tenant_id: TenantId, db: Session = Depends(get_db)) -> list[EvidenceSource]:
    return list(
        db.scalars(
            select(EvidenceSource)
            .where(
                EvidenceSource.tenant_id == tenant_id,
            )
            .order_by(EvidenceSource.created_at.desc())
            .limit(100)
        )
    )


@router.post("/sources/{source_id}/revoke", response_model=schemas.EvidenceSourceOut)
def revoke_source(
    source_id: uuid.UUID,
    tenant_id: TenantId,
    principal: PrincipalDep,
    db: Session = Depends(get_db),
) -> EvidenceSource:
    row = sources.revoke_source(db, source_id, tenant_id)
    _audit(db, principal, "monitoring.source_revoked", "evidence_source", row.id)
    return row


@router.delete("/sources/{source_id}", status_code=204)
def delete_source(
    source_id: uuid.UUID,
    tenant_id: TenantId,
    principal: PrincipalDep,
    db: Session = Depends(get_db),
) -> Response:
    sources.delete_source(db, source_id, tenant_id)
    _audit(db, principal, "monitoring.source_deleted", "evidence_source", source_id)
    return Response(status_code=204)


@router.post(
    "/{monitor_id}/sources/{source_id}/snapshot",
    response_model=schemas.MonitoringRunOut,
    openapi_extra={
        "requestBody": {
            "required": True,
            "content": {
                "application/json": {
                    "schema": {
                        "type": "array",
                        "maxItems": 10000,
                        "items": {"type": "object", "additionalProperties": True},
                    }
                },
            },
        }
    },
)
async def upload_snapshot(
    request: Request,
    monitor_id: uuid.UUID,
    source_id: uuid.UUID,
    tenant_id: TenantId,
    observation_date: date,
    revision: int = Query(ge=1),
    db: Session = Depends(get_db),
) -> MonitoringRun:
    """Upload a JSON array representing one complete UTC log day (2 MiB max)."""
    if request.headers.get("content-type", "").split(";")[0].strip() != "application/json":
        raise HTTPException(415, "use application/json")
    payload = bytearray()
    async for chunk in request.stream():
        if len(payload) + len(chunk) > MAX_SNAPSHOT_BYTES:
            raise HTTPException(413, "snapshot exceeds byte limit")
        payload.extend(chunk)
    return await run_in_threadpool(
        sources.ingest_snapshot,
        db,
        monitor_id,
        tenant_id,
        source_id,
        revision,
        observation_date,
        bytes(payload),
    )


def load_monitor(
    monitor_id: uuid.UUID,
    tenant_id: TenantId,
    db: Session = Depends(get_db),
) -> InfrastructureMonitor:
    monitor = service.get_monitor(db, monitor_id, tenant_id)
    if monitor is None:
        raise HTTPException(status_code=404, detail="monitor not found")
    return monitor


@router.post("", response_model=schemas.MonitoringOut, status_code=201)
def create_monitor(
    body: schemas.MonitoringCreate,
    tenant_id: TenantId,
    principal: PrincipalDep,
    db: Session = Depends(get_db),
) -> InfrastructureMonitor:
    try:
        require_target_allowed(body.target_binding)
    except TargetNotAllowed as exc:
        raise HTTPException(status_code=422, detail="target binding is not allowed") from exc
    monitor = service.create_monitor(
        db,
        tenant_id=tenant_id,
        name=body.name,
        target_binding=body.target_binding,
        source_ids=body.source_ids,
        schedule_minutes=body.schedule_minutes,
        minimum_baseline_days=body.minimum_baseline_days,
        schedule_enabled=body.schedule_enabled,
        retention_days=body.retention_days,
    )
    _audit(db, principal, "monitoring.monitor_created", "monitor", monitor.id)
    return monitor


@router.post("/setup", response_model=schemas.MonitoringOut, status_code=201)
def setup_monitor(
    body: schemas.MonitoringSetup,
    tenant_id: TenantId,
    principal: PrincipalDep,
    db: Session = Depends(get_db),
) -> InfrastructureMonitor:
    """Create a monitor from a WAF log-group ARN, an API contract and an optional repository."""
    from app.monitoring import setup

    monitor = setup.setup_monitor(db, tenant_id, body)
    _audit(db, principal, "monitoring.monitor_created", "monitor", monitor.id, {"via": "setup"})
    return monitor


@router.get("/{monitor_id}/setup", response_model=schemas.MonitoringSetupOut)
def get_setup(
    monitor: InfrastructureMonitor = Depends(load_monitor), db: Session = Depends(get_db)
) -> schemas.MonitoringSetupOut:
    from app.monitoring import setup

    return setup.setup_view(db, monitor)


@router.put("/{monitor_id}/setup", response_model=schemas.MonitoringSetupOut)
def edit_setup(
    body: schemas.MonitoringSetupUpdate,
    principal: PrincipalDep,
    monitor: InfrastructureMonitor = Depends(load_monitor),
    db: Session = Depends(get_db),
) -> schemas.MonitoringSetupOut:
    """Edit name, schedule, contract, repository and ALB. Target and WAF log group stay."""
    from app.monitoring import setup

    updated = setup.update_monitor_setup(db, monitor, body)
    _audit(db, principal, "monitoring.setup_updated", "monitor", updated.id)
    return setup.setup_view(db, updated)


@router.post("/example", response_model=schemas.MonitoringOut, status_code=201)
def example_monitor(tenant_id: TenantId, db: Session = Depends(get_db)) -> InfrastructureMonitor:
    """Dev only: a monitor on the bundled target with eight synthetic WAF days."""
    from app.monitoring import setup

    return setup.create_example_monitor(db, tenant_id)


@router.get("", response_model=list[schemas.MonitoringOut])
def list_monitors(
    tenant_id: TenantId, db: Session = Depends(get_db)
) -> list[InfrastructureMonitor]:
    return service.list_monitors(db, tenant_id)


@router.get("/{monitor_id}/runs", response_model=list[schemas.MonitoringRunOut])
def list_runs(
    monitor: InfrastructureMonitor = Depends(load_monitor), db: Session = Depends(get_db)
) -> list[MonitoringRun]:
    return list(
        db.scalars(
            select(MonitoringRun)
            .where(MonitoringRun.monitor_id == monitor.id)
            .order_by(MonitoringRun.observation_date.desc())
            .limit(90)
        )
    )


@router.get("/{monitor_id}/rapid-runs", response_model=list[schemas.MonitoringRapidRunOut])
def rapid_runs(
    monitor: InfrastructureMonitor = Depends(load_monitor), db: Session = Depends(get_db)
) -> list[MonitoringRapidRun]:
    """Recent short-window detections; raw WAF and application events are not stored."""
    return list(db.scalars(select(MonitoringRapidRun).where(
        MonitoringRapidRun.monitor_id == monitor.id
    ).order_by(MonitoringRapidRun.window_end.desc()).limit(100)))


@router.post("/{monitor_id}/rapid-runs", response_model=schemas.MonitoringRapidRunOut)
def ingest_rapid(
    body: schemas.MonitoringRapidIngest,
    monitor: InfrastructureMonitor = Depends(load_monitor),
    db: Session = Depends(get_db),
) -> MonitoringRapidRun:
    """Ingest a complete rolling hour from an authenticated telemetry pipeline."""
    from app.monitoring.rapid_service import ingest as ingest_window

    return ingest_window(db, monitor, body)


@router.post("/{monitor_id}/run", response_model=schemas.MonitoringRunOut, status_code=202)
def queue_run(
    observation_date: date | None = None,
    monitor: InfrastructureMonitor = Depends(load_monitor),
    db: Session = Depends(get_db),
) -> MonitoringRun:
    """Queue the previous complete UTC day's collection slot; an adapter supplies its logs later."""
    from app.workers.tasks import run_monitoring_task

    day = observation_date or datetime.now(UTC).date() - timedelta(days=1)
    if day >= datetime.now(UTC).date() or day < datetime.now(UTC).date() - timedelta(
        days=monitor.retention_days
    ):
        raise HTTPException(422, "select a completed day within retention")
    if monitor.status != "active":
        raise HTTPException(409, "monitor is paused")
    run = service.prepare_daily_run(db, monitor, day)
    if run.status == "collecting":
        return run
    # A retried day starts clean; its previous failure no longer describes it.
    run.status, run.claim, run.error_code = "queued", None, None
    db.commit()
    try:
        run_monitoring_task.delay(str(monitor.id), str(run.id))
    except BrokerUnavailable:
        service.mark_awaiting_evidence(db, run)
        raise HTTPException(status_code=503, detail="monitoring queue unavailable") from None
    return run


@router.post("/{monitor_id}/runs/ingest", response_model=schemas.MonitoringRunOut)
def ingest(
    body: schemas.WafIngestRequest,
    monitor: InfrastructureMonitor = Depends(load_monitor),
    db: Session = Depends(get_db),
) -> MonitoringRun:
    """Ingest one value-redacted-by-processing daily WAF/access-log batch."""
    if monitor.source_ids:
        raise HTTPException(409, "use the bound source snapshot endpoint")
    day = body.observation_date or datetime.now(UTC).date()
    try:
        return service.ingest_waf_records(
            db,
            monitor,
            body.records,
            observation_date=day,
            source_revisions=body.source_revisions,
        )
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc


@router.put("/sources/{source_id}", response_model=schemas.EvidenceSourceOut)
def update_source(
    source_id: uuid.UUID,
    body: schemas.EvidenceSourceCreate,
    tenant_id: TenantId,
    db: Session = Depends(get_db),
) -> EvidenceSource:
    return sources.save_source(db, tenant_id, body, source_id)


@router.get("/sources/{source_id}/audit")
def source_audit(
    source_id: uuid.UUID, tenant_id: TenantId, db: Session = Depends(get_db)
) -> list[dict]:
    source = sources.load_source(db, source_id, tenant_id)
    return [
        {"action": row.action, "outcome": row.outcome, "created_at": row.created_at}
        for row in db.scalars(
            select(EvidenceAudit)
            .where(EvidenceAudit.source_id == source.id)
            .order_by(EvidenceAudit.created_at.desc())
            .limit(100)
        )
    ]


@router.patch("/{monitor_id}", response_model=schemas.MonitoringOut)
def update_monitor(
    body: schemas.MonitoringUpdate,
    principal: PrincipalDep,
    monitor: InfrastructureMonitor = Depends(load_monitor),
    db: Session = Depends(get_db),
) -> InfrastructureMonitor:
    monitor.status, monitor.schedule_enabled, monitor.retention_days = (
        body.status,
        body.schedule_enabled,
        body.retention_days,
    )
    service.expire_evidence(db, monitor)
    _audit(
        db,
        principal,
        "monitoring.monitor_updated",
        "monitor",
        monitor.id,
        {"status": monitor.status},
    )
    return monitor


@router.delete("/{monitor_id}", status_code=204)
def delete_monitor(
    principal: PrincipalDep,
    monitor: InfrastructureMonitor = Depends(load_monitor),
    db: Session = Depends(get_db),
) -> Response:
    db.execute(delete(InfrastructureMonitor).where(InfrastructureMonitor.id == monitor.id))
    _audit(db, principal, "monitoring.monitor_deleted", "monitor", monitor.id)
    return Response(status_code=204)


@router.post("/{monitor_id}/cancel")
def cancel_collection(
    principal: PrincipalDep,
    monitor: InfrastructureMonitor = Depends(load_monitor),
    db: Session = Depends(get_db),
) -> dict:
    from sqlalchemy import update

    db.execute(
        update(MonitoringRun)
        .where(
            MonitoringRun.monitor_id == monitor.id,
            MonitoringRun.status.in_(["queued", "collecting"]),
        )
        .values(
            status="cancelled",
            claim=None,
            state="degraded",
            error_code="cancelled",
            finished_at=datetime.now(UTC),
        )
    )
    db.commit()
    _audit(db, principal, "monitoring.collection_cancelled", "monitor", monitor.id)
    return {"status": "cancelled"}


@router.get("/{monitor_id}/context")
def get_context(
    monitor: InfrastructureMonitor = Depends(load_monitor), db: Session = Depends(get_db)
) -> dict:
    from app.monitoring.context import readable_context

    return readable_context(db, monitor)


@router.put("/{monitor_id}/context")
def attach_context(
    body: schemas.MonitoringContextInput,
    principal: PrincipalDep,
    monitor: InfrastructureMonitor = Depends(load_monitor),
    db: Session = Depends(get_db),
) -> dict:
    from app.monitoring.context import attach_context as attach

    result = attach(
        db, monitor, body.scan_id, body.repository_source_id, body.include_database
    )
    _audit(
        db,
        principal,
        "monitoring.context_attached",
        "monitor",
        monitor.id,
        {
            "scan": body.scan_id is not None,
            "repository": body.repository_source_id is not None,
            "database": bool(body.include_database),
        },
    )
    return result


@router.put("/{monitor_id}/triage")
def triage(
    body: schemas.MonitoringTriageInput,
    principal: PrincipalDep,
    monitor: InfrastructureMonitor = Depends(load_monitor),
    db: Session = Depends(get_db),
) -> dict:
    if body.fingerprint not in monitor.triage and len(monitor.triage) >= 500:
        raise HTTPException(422, "triage limit reached")
    monitor.triage = {**monitor.triage, body.fingerprint: body.disposition}
    service.recompute(db, monitor)
    db.commit()
    _audit(
        db,
        principal,
        "monitoring.observation_triaged",
        "monitor",
        monitor.id,
        {"disposition": str(body.disposition)},
    )
    return monitor.triage


@router.get("/{monitor_id}/alerts", response_model=list[schemas.MonitoringAlertOut])
def alerts(
    monitor: InfrastructureMonitor = Depends(load_monitor), db: Session = Depends(get_db)
) -> list[MonitoringAlert]:
    return list(
        db.scalars(
            select(MonitoringAlert)
            .where(MonitoringAlert.monitor_id == monitor.id)
            .order_by(MonitoringAlert.created_at.desc())
            .limit(100)
        )
    )


@router.post(
    "/{monitor_id}/alerts/{alert_id}/acknowledge", response_model=schemas.MonitoringAlertOut
)
def acknowledge(
    alert_id: uuid.UUID,
    principal: PrincipalDep,
    monitor: InfrastructureMonitor = Depends(load_monitor),
    db: Session = Depends(get_db),
) -> MonitoringAlert:
    alert = db.scalar(
        select(MonitoringAlert).where(
            MonitoringAlert.id == alert_id, MonitoringAlert.monitor_id == monitor.id
        )
    )
    if alert is None:
        raise HTTPException(404, "alert not found")
    alert.acknowledged = True
    db.commit()
    _audit(db, principal, "monitoring.alert_acknowledged", "monitoring_alert", alert.id)
    return alert


@router.get("/{monitor_id}/diff")
def diff(
    from_day: date,
    to_day: date,
    monitor: InfrastructureMonitor = Depends(load_monitor),
    db: Session = Depends(get_db),
) -> dict:
    rows = list(
        db.scalars(
            select(MonitoringRun).where(
                MonitoringRun.monitor_id == monitor.id,
                MonitoringRun.observation_date.in_([from_day, to_day]),
            )
        )
    )
    before = next((r for r in rows if r.observation_date == from_day), None)
    after = next((r for r in rows if r.observation_date == to_day), None)
    if before is None or after is None:
        raise HTTPException(404, "run not found")
    previous = {o["fingerprint"] for o in before.observations}
    current = {o["fingerprint"] for o in after.observations}
    comparable = (
        before.scope_revision == after.scope_revision
        and after.state in {"anomaly", "baseline_ready"}
        and before.state in {"anomaly", "baseline_ready"}
    )
    return {
        "added": sorted(current - previous),
        "unchanged": sorted(current & previous),
        "resolved": sorted(previous - current) if comparable else [],
        "not_retested": sorted(previous - current) if not comparable else [],
        "scope_changed": not comparable,
    }


@router.post(
    "/{monitor_id}/runs/{run_id}/observations/{fingerprint}/explain",
    response_model=schemas.MonitoringRunOut,
    status_code=202,
)
def explain_observation(
    run_id: uuid.UUID,
    fingerprint: str = Path(pattern=r"^[0-9a-f]{64}$"),
    monitor: InfrastructureMonitor = Depends(load_monitor),
    db: Session = Depends(get_db),
) -> MonitoringRun:
    """Ask the optional AI provider to explain one observation; its evidence never changes."""
    from app.monitoring import explain
    from app.workers.tasks import explain_monitoring_observation

    run = explain.request(db, monitor, run_id, fingerprint)
    try:
        explain_monitoring_observation.delay(str(monitor.id), str(run.id), fingerprint)
    except BrokerUnavailable:
        explain.mark_unavailable(db, run, fingerprint, "queue_unavailable")
        raise HTTPException(status_code=503, detail="monitoring queue unavailable") from None
    db.refresh(run)
    return run


@router.get("/{monitor_id}/briefing", response_model=schemas.MonitoringBriefingOut)
def traffic_briefing(monitor: InfrastructureMonitor = Depends(load_monitor)) -> dict:
    """The latest AI briefing on this monitor's bot, AI and client traffic."""
    return {"status": "none", **(monitor.ai_briefing or {})}


@router.post(
    "/{monitor_id}/briefing", response_model=schemas.MonitoringBriefingOut, status_code=202
)
def request_traffic_briefing(
    days: int = Query(default=28, ge=1, le=90),
    monitor: InfrastructureMonitor = Depends(load_monitor),
    db: Session = Depends(get_db),
) -> dict:
    """Ask the optional AI provider what in this traffic matters and how it would alert."""
    from app.monitoring import briefing
    from app.workers.tasks import brief_monitoring_traffic

    monitor = briefing.request(db, monitor, days)
    try:
        brief_monitoring_traffic.delay(str(monitor.id))
    except BrokerUnavailable:
        briefing.mark_unavailable(db, monitor, "queue_unavailable")
        raise HTTPException(status_code=503, detail="monitoring queue unavailable") from None
    db.refresh(monitor)
    return {"status": "none", **(monitor.ai_briefing or {})}


@router.get("/{monitor_id}/bots", response_model=schemas.MonitoringBotsOut)
def bot_traffic(
    days: int = Query(default=28, ge=1, le=90),
    limit: int = Query(default=50, ge=1, le=200),
    monitor: InfrastructureMonitor = Depends(load_monitor),
    db: Session = Depends(get_db),
) -> dict:
    """AI and bot traffic over recent completed days, from AWS WAF Bot Control labels."""
    from app.monitoring import bots

    since = datetime.now(UTC).date() - timedelta(days=days)
    rows = db.scalars(
        select(MonitoringRun)
        .where(
            MonitoringRun.monitor_id == monitor.id,
            MonitoringRun.observation_date >= since,
            MonitoringRun.status == "complete",
        )
        .order_by(MonitoringRun.observation_date.asc())
    )
    return bots.summarize(
        [(row.observation_date, row.metrics.get("bots") or {}) for row in rows], limit=limit
    )


@router.get("/{monitor_id}/routes", response_model=schemas.MonitoringRoutesOut)
def route_traffic(
    days: int = Query(default=28, ge=1, le=90),
    limit: int = Query(default=8, ge=1, le=20),
    monitor: InfrastructureMonitor = Depends(load_monitor),
    db: Session = Depends(get_db),
) -> dict:
    """Daily traffic for the busiest routes, each scored against its own baseline share."""
    from app.monitoring.routes import summarize_routes

    since = datetime.now(UTC).date() - timedelta(days=days)
    rows = db.scalars(
        select(MonitoringRun)
        .where(
            MonitoringRun.monitor_id == monitor.id,
            MonitoringRun.observation_date >= since,
            MonitoringRun.status == "complete",
        )
        .order_by(MonitoringRun.observation_date.asc())
    )
    return summarize_routes(
        [(row.observation_date, row.metrics) for row in rows],
        limit=limit,
        minimum_days=monitor.minimum_baseline_days,
    )


@router.get("/{monitor_id}/clients", response_model=schemas.MonitoringClientsOut)
def client_fingerprints(
    limit: int = Query(default=50, ge=1, le=200),
    monitor: InfrastructureMonitor = Depends(load_monitor),
    db: Session = Depends(get_db),
) -> dict:
    """The latest completed day's JA4 TLS clients, the ones meeting a lead first."""
    from app.monitoring import clients

    row = db.scalar(
        select(MonitoringRun)
        .where(MonitoringRun.monitor_id == monitor.id, MonitoringRun.status == "complete")
        .order_by(MonitoringRun.observation_date.desc())
        .limit(1)
    )
    current = (row.metrics.get("clients") if row else None) or {}
    return {
        "day": row.observation_date if row else None,
        "sampled": bool(row and row.metrics.get("sample")),
        "clients_total": int(current.get("clients_total") or 0),
        "without_fingerprint": int(current.get("without_fingerprint") or 0),
        "clients": clients.with_flags(current, limit=limit),
    }
