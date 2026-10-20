"""Deliver queued notifications: signed webhooks and Slack incoming webhooks.

The destination is decrypted only here, then re-checked through the same egress
guard as a scan target. Redirects are never followed; a 3xx is a configuration
error, not a destination. Retries back off exponentially with jitter and stop
at ``notification_max_attempts``; a permanent 4xx goes straight to ``dead``.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import random
import uuid
from datetime import UTC, datetime, timedelta
from typing import Any

import httpx
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core import vault
from app.core.config import settings
from app.core.target_guard import TargetNotAllowed, check_target_allowed
from app.models.notification import NotificationDelivery, NotificationEndpoint

_RETRYABLE_STATUS = {408, 425, 429}


def require_destination_allowed(destination: str) -> None:
    """Raise :class:`TargetNotAllowed` for a destination out of notification policy.

    Notifications have their own private-range switch and allowlist, separate
    from the scan target's, since a webhook is not attack traffic.
    """
    check_target_allowed(
        destination,
        allow_private=settings.notification_allow_private,
        allowlist=list(settings.notification_allowlist_set()),
    )


def _signature(secret: str, timestamp: int, body: bytes) -> str:
    digest = hmac.new(
        secret.encode(), f"{timestamp}.".encode() + body, hashlib.sha256
    ).hexdigest()
    return f"t={timestamp},v1={digest}"


def _slack_text(payload: dict[str, Any]) -> str:
    event = payload.get("event")
    if event == "finding.new":
        return (
            f"[{str(payload.get('severity', '')).upper()}] "
            f"{payload.get('check') or 'finding'}: {payload.get('title') or ''} "
            f"(scan {payload.get('scan_id')})"
        )
    if event == "work.overdue":
        return (
            f"Work item overdue: {payload.get('fingerprint')} "
            f"(scan {payload.get('scan_id')}, due {payload.get('due_date')})"
        )
    if event == "run.failed":
        return (
            f"Scan failed: {payload.get('scan_id')} — "
            f"{payload.get('failure_reason') or 'no reason recorded'}"
        )
    if event == "run.recovered":
        return f"Scan recovered: {payload.get('scan_id')} (run {payload.get('run_number')})"
    if event == "monitor.alert":
        return (
            f"Monitoring alert: {payload.get('monitor')} is "
            f"{payload.get('state')} on {payload.get('observation_date')}"
        )
    if event == "monitor.recovered":
        return (
            f"Monitoring recovered: {payload.get('monitor')} on "
            f"{payload.get('observation_date')}"
        )
    return str(payload.get("message") or "aidetector notification")


def _retry_delay(attempts: int) -> float:
    base = min(3600.0, 60.0 * (2 ** max(0, attempts - 1)))
    return base * random.uniform(0.8, 1.2)


def _transport(url: str) -> httpx.Client:
    return httpx.Client(
        timeout=httpx.Timeout(settings.notification_timeout_seconds),
        follow_redirects=False,
    )


def _mark(
    delivery: NotificationDelivery,
    state: str,
    *,
    error: str | None = None,
    now: datetime | None = None,
) -> None:
    delivery.state = state
    delivery.last_error = (error or "")[:500] or None
    if state == "delivered":
        delivery.delivered_at = now or datetime.now(UTC)
    elif state == "pending":
        delivery.next_attempt_at = datetime.now(UTC) + timedelta(
            seconds=_retry_delay(delivery.attempts)
        )


def deliver_one(
    db: Session,
    delivery: NotificationDelivery,
    *,
    client: httpx.Client | None = None,
) -> str:
    endpoint = db.get(NotificationEndpoint, delivery.endpoint_id)
    if endpoint is None:
        _mark(delivery, "dead", error="endpoint no longer exists")
        db.commit()
        return "dead"
    # Re-check at delivery, not only at enqueue: disabling an endpoint cancels
    # the backlog it had already queued rather than letting a pending row send.
    if not endpoint.active:
        _mark(delivery, "dead", error="endpoint disabled")
        db.commit()
        return "dead"
    try:
        destination = vault.decrypt(endpoint.destination_ref)
    except Exception:
        _mark(delivery, "dead", error="destination could not be decrypted")
        db.commit()
        return "dead"
    try:
        require_destination_allowed(destination)
    except TargetNotAllowed as exc:
        _mark(delivery, "dead", error=f"destination blocked: {exc}")
        db.commit()
        return "dead"

    if endpoint.kind == "slack":
        body = json.dumps({"text": _slack_text(delivery.payload)}).encode()
        headers = {"Content-Type": "application/json"}
    else:
        body = json.dumps(
            delivery.payload, sort_keys=True, separators=(",", ":")
        ).encode()
        if not endpoint.signing_secret_ref:
            _mark(delivery, "dead", error="webhook has no signing secret")
            db.commit()
            return "dead"
        try:
            secret = vault.decrypt(endpoint.signing_secret_ref)
        except Exception:
            _mark(delivery, "dead", error="signing secret could not be decrypted")
            db.commit()
            return "dead"
        timestamp = int(datetime.now(UTC).timestamp())
        headers = {
            "Content-Type": "application/json",
            "X-Aidetector-Event": delivery.event_type,
            "X-Aidetector-Delivery": str(delivery.id),
            "X-Aidetector-Signature": _signature(secret, timestamp, body),
        }

    owned = client is None
    http = client or _transport(destination)
    try:
        response = http.post(destination, content=body, headers=headers)
    except httpx.HTTPError as exc:
        state = "dead" if delivery.attempts >= settings.notification_max_attempts else "pending"
        _mark(delivery, state, error=f"{type(exc).__name__}: {exc}")
        db.commit()
        return state
    finally:
        if owned:
            http.close()

    if 200 <= response.status_code < 300:
        _mark(delivery, "delivered")
    elif (
        response.status_code in _RETRYABLE_STATUS
        or response.status_code >= 500
    ):
        state = (
            "dead"
            if delivery.attempts >= settings.notification_max_attempts
            else "pending"
        )
        _mark(delivery, state, error=f"HTTP {response.status_code}")
    else:
        _mark(delivery, "dead", error=f"HTTP {response.status_code}")
    db.commit()
    return delivery.state


def dispatch_pending(
    db: Session,
    *,
    client: httpx.Client | None = None,
    now: datetime | None = None,
    limit: int | None = None,
) -> dict[str, int]:
    current = now or datetime.now(UTC)
    batch = limit or settings.notification_batch_size
    rows = list(
        db.scalars(
            select(NotificationDelivery)
            .where(
                NotificationDelivery.state.in_(("pending", "delivering")),
                NotificationDelivery.next_attempt_at <= current,
            )
            .order_by(NotificationDelivery.next_attempt_at)
            .limit(batch)
            .with_for_update(skip_locked=True)
        )
    )
    # The lease must cover the whole sequential batch, not one request: a
    # 20-row batch sending at a 10-second timeout can take 200 seconds, and a
    # 20-second lease would let a second dispatcher claim rows the first still
    # owns. Receiver dedup would hide the duplication, not prevent it.
    lease_seconds = settings.notification_timeout_seconds * (
        2 + batch
    )
    for row in rows:
        row.state = "delivering"
        row.attempts += 1
        row.next_attempt_at = current + timedelta(seconds=lease_seconds)
    db.commit()

    counts = {"delivered": 0, "pending": 0, "dead": 0}
    owned = client is None
    http = client or httpx.Client(
        timeout=httpx.Timeout(settings.notification_timeout_seconds),
        follow_redirects=False,
    )
    try:
        for row in rows:
            state = deliver_one(db, row, client=http)
            counts[state] = counts.get(state, 0) + 1
    finally:
        if owned:
            http.close()
    return {"attempted": len(rows), **counts}


def enqueue_test(db: Session, endpoint: NotificationEndpoint) -> NotificationDelivery:
    delivery = NotificationDelivery(
        tenant_slug=endpoint.tenant_slug,
        endpoint_id=endpoint.id,
        event_type="test",
        dedup_key=f"test:{uuid.uuid4()}",
        payload={
            "event": "test",
            "message": "aidetector test delivery",
            "occurred_at": datetime.now(UTC).isoformat(),
        },
    )
    db.add(delivery)
    db.flush()
    return delivery
