"""Tenant and target authorization for telemetry sources and daily ingestion."""

from __future__ import annotations

import hashlib
import json
import uuid
from datetime import UTC, date, datetime

from fastapi import HTTPException
from sqlalchemy import delete, select
from sqlalchemy.orm import Session

from app.core import vault
from app.models.monitoring import (
    EvidenceAudit,
    EvidenceSource,
    InfrastructureMonitor,
    MonitoringAlert,
    MonitoringRun,
)
from app.monitoring import service
from app.monitoring.accumulate import day_metrics
from app.monitoring.connectors import normalize_snapshot
from app.monitoring.contracts import (
    ORIGIN_SOURCE_KEY,
    RouteBinding,
    SourceConfig,
    SourceInput,
    SourceUnavailable,
)


def load_source(db: Session, source_id: uuid.UUID, tenant_id: str) -> EvidenceSource:
    source = db.scalar(
        select(EvidenceSource)
        .where(
            EvidenceSource.id == source_id,
            EvidenceSource.tenant_id == tenant_id,
        )
        .with_for_update()
        .execution_options(populate_existing=True)
    )
    if source is None:
        raise HTTPException(404, "source not found")
    return source


def validate_binding(db: Session, tenant_id: str, target: str, source_ids: list[str]) -> None:
    # A daily snapshot replaces the complete day. Until per-source aggregates
    # exist, accepting multiple feeds would silently overwrite their counts.
    if len(source_ids) > 1:
        raise HTTPException(422, "JSON monitoring supports one source per monitor")
    for value in source_ids:
        try:
            source_id = uuid.UUID(value)
        except ValueError:
            raise HTTPException(422, "invalid source ID") from None
        source = load_source(db, source_id, tenant_id)
        if (
            source.status == "revoked"
            or source.connector == "github"
            or source.target_binding != target
        ):
            raise HTTPException(409, "source is revoked or bound to another target")


def bound_routes(source: EvidenceSource, monitor: InfrastructureMonitor) -> list[RouteBinding]:
    """The route vocabulary a day is mapped with: the source's plus the pinned contract."""
    return [
        RouteBinding.model_validate(r)
        for r in [*source.config.get("routes", []), *monitor.context.get("routes", [])]
    ]


def _lock_binding(
    db: Session,
    monitor_id: uuid.UUID,
    tenant_id: str,
    source_id: uuid.UUID,
    revision: int,
    day: date,
    expected_claim: uuid.UUID | None,
) -> tuple[EvidenceSource, InfrastructureMonitor]:
    if day >= datetime.now(UTC).date():
        raise HTTPException(422, "select a completed UTC day")
    # Lock source before monitor consistently with revocation. Authorization is
    # re-read after the day's data arrived, not trusted from an earlier check.
    source = load_source(db, source_id, tenant_id)
    monitor = db.scalar(
        select(InfrastructureMonitor)
        .where(
            InfrastructureMonitor.id == monitor_id,
            InfrastructureMonitor.tenant_id == tenant_id,
        )
        .with_for_update()
        .execution_options(populate_existing=True)
    )
    if monitor is None:
        raise HTTPException(404, "monitor not found")
    if (
        source.status == "revoked"
        or source.revision != revision
        or source.target_binding != monitor.target_binding
        or monitor.source_ids != [str(source_id)]
        or monitor.status != "active"
    ):
        raise HTTPException(409, "source binding is unavailable or changed")
    # Re-read the locked row: a collecting worker's session still holds the run as it
    # was when the claim was taken, while progress reports and cancels wrote the row
    # through other sessions. Without this the claim check reads that stale copy, and
    # a day that folds to the metrics already in memory is never written over progress.
    slot = db.scalar(
        select(MonitoringRun)
        .where(
            MonitoringRun.monitor_id == monitor.id,
            MonitoringRun.observation_date == day,
        )
        .with_for_update()
        .execution_options(populate_existing=True)
    )
    if expected_claim and (
        slot is None or slot.claim != expected_claim or slot.status != "collecting"
    ):
        raise HTTPException(409, "collection claim changed")
    if not expected_claim and slot is not None and slot.status == "collecting":
        raise HTTPException(409, "collection already running")
    return source, monitor


def ingest_snapshot(
    db: Session,
    monitor_id: uuid.UUID,
    tenant_id: str,
    source_id: uuid.UUID,
    revision: int,
    day: date,
    payload: bytes,
    *,
    expected_claim: uuid.UUID | None = None,
) -> MonitoringRun:
    source, monitor = _lock_binding(
        db, monitor_id, tenant_id, source_id, revision, day, expected_claim
    )
    try:
        events = normalize_snapshot(
            payload,
            observation_date=day,
            salt=service._monitoring_salt(tenant_id),
            routes=bound_routes(source, monitor),
        )
    except ValueError as exc:
        raise HTTPException(422, str(exc)) from None
    # Content-derived revision prevents callers from accidentally reusing a
    # revision label for a different daily snapshot. Raw bytes are never stored.
    return _persist(
        db, source, monitor, day_metrics(events), day, hashlib.sha256(payload).hexdigest()
    )


def ingest_metrics(
    db: Session,
    monitor_id: uuid.UUID,
    tenant_id: str,
    source_id: uuid.UUID,
    revision: int,
    day: date,
    metrics: dict,
    digest: str,
    *,
    expected_claim: uuid.UUID,
    extra_revisions: dict[str, str] | None = None,
) -> MonitoringRun:
    """Persist a day a remote connector already folded into aggregates page by page.

    ``extra_revisions`` records supplementary sources read into the same day. A day is
    re-persisted only when its revisions change, so without them linking a load
    balancer and re-collecting a day would leave that day's origin status unread.
    """
    source, monitor = _lock_binding(
        db, monitor_id, tenant_id, source_id, revision, day, expected_claim
    )
    return _persist(db, source, monitor, metrics, day, digest, extra_revisions)


def _persist(
    db: Session,
    source: EvidenceSource,
    monitor: InfrastructureMonitor,
    metrics: dict,
    day: date,
    digest: str,
    extra_revisions: dict[str, str] | None = None,
) -> MonitoringRun:
    source.status, source.error_code = "ready", None
    source.watermark = max(source.watermark or day, day)
    audit(db, source, "snapshot", "complete")
    return service.ingest_day_metrics(
        db,
        monitor,
        metrics,
        observation_date=day,
        source_revisions={
            str(source.id): f"{source.revision}:{digest}", **(extra_revisions or {})
        },
    )


def revoke_source(db: Session, source_id: uuid.UUID, tenant_id: str) -> EvidenceSource:
    source = load_source(db, source_id, tenant_id)
    if source.status != "revoked":
        source.status = "revoked"
        source.revision += 1
        source.secret_ref = None
    audit(db, source, "revoke", "revoked")
    db.commit()
    db.refresh(source)
    return source


def delete_source(db: Session, source_id: uuid.UUID, tenant_id: str) -> None:
    source = load_source(db, source_id, tenant_id)
    monitors = list(
        db.scalars(
            select(InfrastructureMonitor)
            .where(
                InfrastructureMonitor.tenant_id == tenant_id,
            )
            .with_for_update()
        )
    )
    for monitor in monitors:
        # An origin source only adds load balancer metrics to a WAF day. Removing it detaches it;
        # it must not take the monitor's WAF history and baseline down with it.
        if monitor.context.get(ORIGIN_SOURCE_KEY) == str(source_id):
            monitor.context = {k: v for k, v in monitor.context.items() if k != ORIGIN_SOURCE_KEY}
            continue
        if str(source_id) in monitor.source_ids or monitor.context.get(
            "repository_source_id"
        ) == str(source_id):
            db.execute(delete(MonitoringRun).where(MonitoringRun.monitor_id == monitor.id))
            db.execute(delete(MonitoringAlert).where(MonitoringAlert.monitor_id == monitor.id))
            # Keep the revoked binding so the legacy ingestion endpoint cannot
            # bypass deletion by treating the monitor as an unbound legacy one.
            monitor.status = "paused"
            monitor.context = {}
            monitor.triage = {}
    db.delete(source)
    db.commit()


def audit(db: Session, source: EvidenceSource, action: str, outcome: str) -> None:
    db.add(
        EvidenceAudit(
            tenant_id=source.tenant_id, source_id=source.id, action=action, outcome=outcome
        )
    )


_NOT_ALLOWLISTED = {
    "aws_alb": (
        "This load balancer is not allowlisted on the server. Add its ARN to "
        "MONITORING_AWS_LOAD_BALANCERS in .env and restart the api and worker."
    ),
    "": (
        "This log group is not allowlisted on the server. Add its ARN to "
        "MONITORING_AWS_LOG_GROUPS in .env and restart the api and worker."
    ),
}


def not_allowlisted_message(connector: str) -> str:
    return _NOT_ALLOWLISTED.get(connector, _NOT_ALLOWLISTED[""])


def save_source(
    db: Session,
    tenant_id: str,
    body: SourceInput,
    source_id: uuid.UUID | None = None,
    *,
    commit: bool = True,
    keep_credentials: bool = False,
) -> EvidenceSource:
    """Create or update a source; ``commit=False`` lets a caller own the transaction.

    ``keep_credentials`` keeps an existing source's stored secret when ``body`` carries
    none. Without it an update writes the secret it was given, so editing a GitHub
    source's branch without re-entering the token would silently erase the token.
    """
    from app.monitoring.remote import check_allowlist

    try:
        check_allowlist(body.connector, body.config)
    except SourceUnavailable:
        raise HTTPException(422, not_allowlisted_message(body.connector)) from None
    source = (
        load_source(db, source_id, tenant_id) if source_id else EvidenceSource(tenant_id=tenant_id)
    )
    if source_id:
        if (
            source.status == "revoked"
            or source.target_binding != body.target_binding
            or source.connector != body.connector
        ):
            raise HTTPException(409, "create a new source to change its binding")
        source.revision += 1
    source.name, source.target_binding, source.connector = (
        body.name,
        body.target_binding,
        body.connector,
    )
    source.config = body.config.model_dump(mode="json", exclude_none=True)
    values = (
        {key: value.get_secret_value() for key, value in body.credentials if value is not None}
        if body.credentials
        else {}
    )
    # No stored secret means "use the deployment's credential chain", so an
    # all-empty credentials object must not look like configured credentials.
    if not (keep_credentials and source_id and not values):
        source.secret_ref = vault.encrypt(json.dumps(values)) if values else None
    source.status, source.error_code, source.watermark = "ready", None, None
    db.add(source)
    db.flush()
    audit(db, source, "configure", "ready")
    if commit:
        db.commit()
        db.refresh(source)
    return source


def read_credentials(source: EvidenceSource) -> dict:
    try:
        return json.loads(vault.decrypt(source.secret_ref)) if source.secret_ref else {}
    except (ValueError, vault.VaultKeyError):
        raise SourceUnavailable("credential_unavailable") from None


def bound_config(source: EvidenceSource) -> SourceConfig:
    try:
        return SourceConfig.model_validate(source.config)
    except ValueError:
        raise SourceUnavailable("invalid_configuration") from None
