"""Admin configuration for signed webhooks and Slack notifications."""
from __future__ import annotations

import secrets
import uuid
from urllib.parse import urlsplit

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.api import schemas
from app.core import vault
from app.core.auth import AdminDep
from app.core.db import get_db
from app.core.target_guard import TargetNotAllowed
from app.models.notification import NotificationDelivery, NotificationEndpoint
from app.notifications.dispatch import enqueue_test, require_destination_allowed
from app.notifications.events import KNOWN_EVENTS
from app.scans import workspace

router = APIRouter(prefix="/workspace/notifications", tags=["notifications"])


def _hint(destination: str, kind: str) -> str:
    parts = urlsplit(destination)
    # A Slack incoming-webhook path *is* the bearer secret
    # (/services/T…/B…/secret). Keeping it in a plaintext hint would defeat
    # encrypting the destination, so a Slack hint names only the host.
    path = "" if kind == "slack" else parts.path
    return f"{parts.scheme}://{parts.netloc}{path}"[:512]


def _guard(destination: str) -> None:
    try:
        require_destination_allowed(destination)
    except TargetNotAllowed as exc:
        raise HTTPException(
            status_code=422, detail=f"destination not allowed: {_reason(exc)}"
        ) from exc


def _reason(exc: TargetNotAllowed) -> str:
    """The guard speaks of scan targets; say what it means for a webhook."""
    reason = str(exc)
    if "does not resolve" in reason:
        return "its host does not resolve"
    if "private targets are disabled" in reason:
        return (
            "it is a private address, and private notification destinations "
            "are disabled (NOTIFICATION_ALLOW_PRIVATE)"
        )
    return reason


def _events(raw: list[str]) -> list[str]:
    events = list(dict.fromkeys(raw))
    unknown = sorted(set(events) - KNOWN_EVENTS)
    if unknown:
        raise HTTPException(
            status_code=422,
            detail=f"unknown notification event(s): {', '.join(unknown)}",
        )
    if not events:
        raise HTTPException(
            status_code=422, detail="choose at least one notification event"
        )
    return events


def _out(endpoint: NotificationEndpoint) -> schemas.NotificationEndpointOut:
    return schemas.NotificationEndpointOut(
        id=endpoint.id,
        kind=endpoint.kind,
        destination_hint=endpoint.destination_hint,
        events=list(endpoint.events or []),
        min_severity=endpoint.min_severity,
        active=endpoint.active,
        created_at=endpoint.created_at,
    )


def _owned(
    db: Session, principal: AdminDep, endpoint_id: uuid.UUID
) -> NotificationEndpoint:
    endpoint = db.get(NotificationEndpoint, endpoint_id)
    if endpoint is None or endpoint.tenant_slug != principal.tenant:
        raise HTTPException(status_code=404, detail="notification endpoint not found")
    return endpoint


@router.get("", response_model=list[schemas.NotificationEndpointOut])
def list_endpoints(
    principal: AdminDep, db: Session = Depends(get_db)
) -> list[schemas.NotificationEndpointOut]:
    rows = db.scalars(
        select(NotificationEndpoint)
        .where(NotificationEndpoint.tenant_slug == principal.tenant)
        .order_by(NotificationEndpoint.created_at)
    ).all()
    return [_out(row) for row in rows]


@router.post(
    "", response_model=schemas.NotificationEndpointCreated, status_code=201
)
def create_endpoint(
    body: schemas.NotificationEndpointIn,
    principal: AdminDep,
    db: Session = Depends(get_db),
) -> schemas.NotificationEndpointCreated:
    events = _events(body.events)
    _guard(body.destination)
    workspace.ensure_tenant(db, principal.tenant)
    signing_secret: str | None = None
    signing_ref: str | None = None
    if body.kind == "webhook":
        signing_secret = secrets.token_urlsafe(32)
        signing_ref = vault.encrypt(signing_secret)
    endpoint = NotificationEndpoint(
        tenant_slug=principal.tenant,
        kind=body.kind,
        destination_ref=vault.encrypt(body.destination),
        destination_hint=_hint(body.destination, body.kind),
        signing_secret_ref=signing_ref,
        events=events,
        min_severity=body.min_severity.value,
        active=body.active,
        created_by_user_id=principal.user_id,
    )
    db.add(endpoint)
    db.flush()
    workspace.record_audit(
        db,
        principal,
        "notification.endpoint_created",
        "notification_endpoint",
        endpoint.id,
        {"kind": endpoint.kind, "events": events, "min_severity": endpoint.min_severity},
    )
    db.commit()
    db.refresh(endpoint)
    return schemas.NotificationEndpointCreated(
        **_out(endpoint).model_dump(), signing_secret=signing_secret
    )


@router.patch(
    "/{endpoint_id}", response_model=schemas.NotificationEndpointOut
)
def update_endpoint(
    endpoint_id: uuid.UUID,
    body: schemas.NotificationEndpointUpdate,
    principal: AdminDep,
    db: Session = Depends(get_db),
) -> schemas.NotificationEndpointOut:
    endpoint = _owned(db, principal, endpoint_id)
    changed = body.model_dump(exclude_unset=True)
    if "events" in changed:
        endpoint.events = _events(changed["events"])
    if changed.get("min_severity") is not None:
        endpoint.min_severity = changed["min_severity"].value
    if changed.get("active") is not None:
        endpoint.active = bool(changed["active"])
    workspace.record_audit(
        db,
        principal,
        "notification.endpoint_updated",
        "notification_endpoint",
        endpoint.id,
    )
    db.commit()
    db.refresh(endpoint)
    return _out(endpoint)


@router.delete("/{endpoint_id}")
def delete_endpoint(
    endpoint_id: uuid.UUID,
    principal: AdminDep,
    db: Session = Depends(get_db),
) -> dict[str, str]:
    endpoint = _owned(db, principal, endpoint_id)
    workspace.record_audit(
        db,
        principal,
        "notification.endpoint_deleted",
        "notification_endpoint",
        endpoint.id,
    )
    db.delete(endpoint)
    db.commit()
    return {"status": "deleted"}


@router.post("/{endpoint_id}/test")
def test_endpoint(
    endpoint_id: uuid.UUID,
    principal: AdminDep,
    db: Session = Depends(get_db),
) -> dict[str, str]:
    endpoint = _owned(db, principal, endpoint_id)
    delivery = enqueue_test(db, endpoint)
    workspace.record_audit(
        db,
        principal,
        "notification.test_queued",
        "notification_endpoint",
        endpoint.id,
    )
    db.commit()
    return {"status": "queued", "delivery_id": str(delivery.id)}


@router.get(
    "/deliveries", response_model=list[schemas.NotificationDeliveryOut]
)
def list_deliveries(
    principal: AdminDep,
    limit: int = 100,
    db: Session = Depends(get_db),
) -> list[schemas.NotificationDeliveryOut]:
    rows = db.scalars(
        select(NotificationDelivery)
        .where(NotificationDelivery.tenant_slug == principal.tenant)
        .order_by(NotificationDelivery.created_at.desc())
        .limit(min(max(limit, 1), 500))
    ).all()
    return [
        schemas.NotificationDeliveryOut(
            id=row.id,
            event_type=row.event_type,
            state=row.state,
            attempts=row.attempts,
            last_error=row.last_error,
            created_at=row.created_at,
            delivered_at=row.delivered_at,
        )
        for row in rows
    ]
