"""Signed webhook/Slack outbox: secrecy, dedup, delivery and quiet states."""
from __future__ import annotations

import hashlib
import hmac
import json
import uuid
from datetime import UTC, date, datetime, timedelta
from unittest.mock import Mock

import httpx
from sqlalchemy import func, select

from app.api.routes.notifications import _hint
from app.core import vault
from app.core.config import settings
from app.models.finding_work import FindingWork
from app.models.notification import NotificationDelivery, NotificationEndpoint
from app.models.scan import ScanRun
from app.notifications import events
from app.notifications.dispatch import dispatch_pending, enqueue_test
from app.scans import workspace


def _endpoint(
    client,
    monkeypatch,
    *,
    kind: str = "webhook",
    events_list: list[str] | None = None,
    min_severity: str = "medium",
    destination: str = "http://127.0.0.1:9/hook",
) -> dict:
    monkeypatch.setattr(settings, "notification_allow_private", True)
    response = client.post(
        "/workspace/notifications",
        json={
            "kind": kind,
            "destination": destination,
            "events": events_list or ["finding.new"],
            "min_severity": min_severity,
            "active": True,
        },
    )
    assert response.status_code == 201, response.text
    return response.json()


def _enqueue(db) -> None:
    events.enqueue(
        db,
        tenant_slug="default",
        event_type="finding.new",
        dedup_key="finding:scan:fp:1",
        payload={
            "event": "finding.new",
            "scan_id": "scan",
            "fingerprint": "fp",
            "severity": "high",
            "check": "bola",
            "title": "BOLA on /accounts/{id}",
        },
        severity="high",
    )


def test_webhook_secret_is_returned_once_and_destination_is_encrypted(
    client, db_session, monkeypatch
):
    body = _endpoint(client, monkeypatch)

    assert body["signing_secret"]
    assert body["destination_hint"] == "http://127.0.0.1:9/hook"
    listed = client.get("/workspace/notifications").json()
    assert listed[0]["id"] == body["id"]
    assert "signing_secret" not in listed[0]

    row = db_session.get(NotificationEndpoint, uuid.UUID(body["id"]))
    assert row is not None
    assert row.destination_ref != body["destination_hint"]
    assert vault.decrypt(row.destination_ref) == "http://127.0.0.1:9/hook"
    assert vault.decrypt(row.signing_secret_ref) == body["signing_secret"]


def test_slack_endpoint_has_no_signing_secret(client, monkeypatch):
    body = _endpoint(
        client, monkeypatch, kind="slack", destination="http://127.0.0.1:9/slack"
    )

    assert body["signing_secret"] is None


def test_unknown_event_and_metadata_destination_are_refused(client, monkeypatch):
    monkeypatch.setattr(settings, "notification_allow_private", True)
    unknown = client.post(
        "/workspace/notifications",
        json={
            "kind": "webhook",
            "destination": "http://127.0.0.1:9/hook",
            "events": ["not-a-real-event"],
        },
    )
    assert unknown.status_code == 422

    metadata = client.post(
        "/workspace/notifications",
        json={
            "kind": "webhook",
            "destination": "http://169.254.169.254/latest/meta-data",
            "events": ["finding.new"],
        },
    )
    assert metadata.status_code == 422


def test_enqueue_deduplicates_and_honours_minimum_severity(
    client, db_session, monkeypatch
):
    _endpoint(client, monkeypatch, min_severity="high")
    common = {
        "tenant_slug": "default",
        "event_type": "finding.new",
        "dedup_key": "same",
        "payload": {"event": "finding.new", "scan_id": "s"},
    }

    assert events.enqueue(db_session, **common, severity="high") == 1
    assert events.enqueue(db_session, **common, severity="high") == 0
    assert events.enqueue(db_session, **common, severity="low") == 0
    db_session.commit()

    count = db_session.scalar(
        select(func.count()).select_from(NotificationDelivery)
    )
    assert count == 1


def test_webhook_delivery_is_signed(client, db_session, monkeypatch):
    body = _endpoint(client, monkeypatch)
    _enqueue(db_session)
    db_session.commit()

    captured: dict[str, object] = {}

    def handler(request: httpx.Request) -> httpx.Response:
        captured["headers"] = dict(request.headers)
        captured["body"] = request.content
        return httpx.Response(200)

    with httpx.Client(transport=httpx.MockTransport(handler)) as http:
        result = dispatch_pending(db_session, client=http, limit=10)

    assert result["delivered"] == 1
    headers = captured["headers"]
    assert isinstance(headers, dict)
    signature = headers["x-aidetector-signature"]
    timestamp_part, digest_part = signature.split(",")
    timestamp = int(timestamp_part.removeprefix("t="))
    expected = hmac.new(
        body["signing_secret"].encode(),
        f"{timestamp}.".encode() + captured["body"],
        hashlib.sha256,
    ).hexdigest()
    assert digest_part == f"v1={expected}"
    assert headers["x-aidetector-event"] == "finding.new"
    assert json.loads(captured["body"])["fingerprint"] == "fp"


def test_slack_delivery_is_text_and_unsigned(client, db_session, monkeypatch):
    _endpoint(
        client, monkeypatch, kind="slack", destination="http://127.0.0.1:9/slack"
    )
    _enqueue(db_session)
    db_session.commit()

    captured: dict[str, object] = {}

    def handler(request: httpx.Request) -> httpx.Response:
        captured["headers"] = dict(request.headers)
        captured["body"] = request.content
        return httpx.Response(200)

    with httpx.Client(transport=httpx.MockTransport(handler)) as http:
        assert dispatch_pending(db_session, client=http)["delivered"] == 1

    headers = captured["headers"]
    assert isinstance(headers, dict)
    assert "x-aidetector-signature" not in headers
    payload = json.loads(captured["body"])
    assert "BOLA" in payload["text"]


def test_a_5xx_is_retried_and_exhaustion_dead_letters(
    client, db_session, monkeypatch
):
    _endpoint(client, monkeypatch)
    _enqueue(db_session)
    db_session.commit()

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(503)

    with httpx.Client(transport=httpx.MockTransport(handler)) as http:
        first = dispatch_pending(db_session, client=http)
    assert first["pending"] == 1

    delivery = db_session.scalar(select(NotificationDelivery))
    assert delivery is not None
    assert delivery.attempts == 1
    assert delivery.last_error == "HTTP 503"

    delivery.attempts = settings.notification_max_attempts - 1
    delivery.next_attempt_at = datetime.now(UTC) - timedelta(seconds=1)
    db_session.commit()

    with httpx.Client(transport=httpx.MockTransport(handler)) as http:
        second = dispatch_pending(db_session, client=http)
    db_session.refresh(delivery)
    assert second["dead"] == 1
    assert delivery.state == "dead"


def test_only_new_fingerprints_are_notified_and_unchanged_runs_are_quiet(
    client, db_session, make_scan, monkeypatch
):
    _endpoint(client, monkeypatch, events_list=["finding.new"])
    scan = make_scan()
    older = ScanRun(
        scan_id=scan.id,
        run_number=1,
        status="completed",
        started_at=datetime(2026, 1, 1, 10, 0, tzinfo=UTC),
        finished_at=datetime(2026, 1, 1, 10, 1, tzinfo=UTC),
        findings_snapshot=[
            {
                "fingerprint": "a",
                "check": "bola",
                "severity": "high",
                "confidence": "verified",
                "title": "A",
            }
        ],
    )
    newer = ScanRun(
        scan_id=scan.id,
        run_number=2,
        status="completed",
        started_at=datetime(2026, 1, 1, 11, 0, tzinfo=UTC),
        finished_at=datetime(2026, 1, 1, 11, 1, tzinfo=UTC),
        findings_snapshot=[
            {
                "fingerprint": "a",
                "check": "bola",
                "severity": "high",
                "confidence": "verified",
                "title": "A",
            },
            {
                "fingerprint": "b",
                "check": "bfla",
                "severity": "high",
                "confidence": "verified",
                "title": "B",
            },
        ],
    )
    db_session.add_all([older, newer])
    db_session.commit()
    scan.runs = [older, newer]

    assert events.completed_run_events(db_session, scan, newer) == 1
    db_session.commit()

    same_again = ScanRun(
        scan_id=scan.id,
        run_number=3,
        status="completed",
        started_at=datetime(2026, 1, 1, 12, 0, tzinfo=UTC),
        finished_at=datetime(2026, 1, 1, 12, 1, tzinfo=UTC),
        findings_snapshot=list(newer.findings_snapshot),
    )
    db_session.add(same_again)
    db_session.commit()
    scan.runs = [older, newer, same_again]

    assert events.completed_run_events(db_session, scan, same_again) == 0


def test_run_failure_and_recovery_are_notified_once(
    client, db_session, make_scan, monkeypatch
):
    _endpoint(client, monkeypatch, events_list=["run.failed", "run.recovered"])
    scan = make_scan()
    scan.failure_reason = "worker stopped"
    failed = ScanRun(
        scan_id=scan.id,
        run_number=1,
        status="failed",
        started_at=datetime(2026, 1, 1, 10, 0, tzinfo=UTC),
        finished_at=datetime(2026, 1, 1, 10, 1, tzinfo=UTC),
        findings_snapshot=[],
    )
    db_session.add(failed)
    db_session.commit()
    scan.runs = [failed]

    assert events.run_failed_event(db_session, scan) == 1
    db_session.commit()
    assert events.run_failed_event(db_session, scan) == 0

    recovered = ScanRun(
        scan_id=scan.id,
        run_number=2,
        status="completed",
        started_at=datetime(2026, 1, 1, 11, 0, tzinfo=UTC),
        finished_at=datetime(2026, 1, 1, 11, 1, tzinfo=UTC),
        findings_snapshot=[],
    )
    db_session.add(recovered)
    db_session.commit()
    scan.runs = [failed, recovered]

    assert events.completed_run_events(db_session, scan, recovered) == 1
    db_session.commit()
    assert events.completed_run_events(db_session, scan, recovered) == 0


def test_overdue_work_notifies_once_per_due_date(
    client, db_session, make_scan, monkeypatch
):
    _endpoint(client, monkeypatch, events_list=["work.overdue"])
    scan = make_scan()
    work = FindingWork(
        scan_id=scan.id,
        fingerprint="fp",
        owner="alice",
        due_date=date(2026, 1, 1),
        status="open",
    )
    db_session.add(work)
    db_session.commit()

    assert events.work_overdue_events(db_session, today=date(2026, 1, 2)) == 1
    db_session.commit()
    assert events.work_overdue_events(db_session, today=date(2026, 1, 2)) == 0


def test_test_delivery_is_queued(client, db_session, monkeypatch):
    body = _endpoint(client, monkeypatch)

    response = client.post(f"/workspace/notifications/{body['id']}/test")

    assert response.status_code == 200, response.text
    delivery = db_session.scalar(select(NotificationDelivery))
    assert delivery is not None
    assert delivery.event_type == "test"


def test_slack_hint_never_keeps_the_bearer_path():
    destination = "https://hooks.slack.com/services/TTEST/BTEST/SYNTHETIC_SECRET"
    hint = _hint(destination, "slack")
    assert hint == "https://hooks.slack.com"
    assert "SYNTHETIC_SECRET" not in hint
    assert _hint("https://example.test/hooks/redacted", "webhook").endswith(
        "/hooks/redacted"
    )


def test_disabled_endpoint_cancels_its_queued_backlog(
    db_session, monkeypatch
):
    monkeypatch.setattr(settings, "notification_allow_private", True)
    workspace.ensure_tenant(db_session, "default")
    endpoint = NotificationEndpoint(
        tenant_slug="default",
        kind="slack",
        active=True,
        destination_ref=vault.encrypt("http://127.0.0.1:9/synthetic"),
        destination_hint="fixture",
        events=["test"],
        min_severity="medium",
    )
    db_session.add(endpoint)
    db_session.commit()
    enqueue_test(db_session, endpoint)
    endpoint.active = False
    db_session.commit()
    handler = Mock(return_value=httpx.Response(200))
    with httpx.Client(transport=httpx.MockTransport(handler)) as client:
        result = dispatch_pending(db_session, client=client)
    assert result["delivered"] == 0
    handler.assert_not_called()


def test_a_refused_notification_destination_is_explained_as_one(client, monkeypatch):
    from app.core import target_guard

    def no_dns(*args, **kwargs):
        raise target_guard.socket.gaierror("synthetic resolver failure")

    monkeypatch.setattr(target_guard.socket, "getaddrinfo", no_dns)
    response = client.post(
        "/workspace/notifications",
        json={
            "kind": "webhook",
            "destination": "https://hooks.unresolvable.test/x",
            "events": ["run.failed"],
            "min_severity": "medium",
        },
    )
    assert response.status_code == 422
    detail = response.json()["detail"]
    assert detail == "destination not allowed: its host does not resolve"
    assert "scan" not in detail
