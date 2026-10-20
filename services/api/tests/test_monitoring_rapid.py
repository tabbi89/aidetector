"""Short-window monitoring uses complete evidence and never stores raw values."""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta

import httpx
import pytest
from sqlalchemy import select

from app.core.config import settings
from app.models.monitoring import (
    InfrastructureMonitor,
    MonitoringAlert,
    MonitoringRapidRun,
    MonitoringRun,
)
from app.monitoring import rapid_service, remote
from app.monitoring.context import contract_context
from app.monitoring.contracts import SourceConfig
from app.scans import operations
from app.scans import service as scans


def _waf(at: datetime, path: str, number: int, *, label: bool = False) -> dict:
    return {
        "timestamp": int(at.timestamp() * 1000),
        "httpRequest": {
            "clientIp": "203.0.113.10", "uri": path, "httpMethod": "GET",
            "requestId": f"req-{number}",
        },
        "action": "ALLOW",
        "labels": ([{"name": "awswaf:managed:aws:core-rule-set:GenericLFI_URIPath"}]
                   if label else []),
    }


def _app(at: datetime, number: int, event: str, **fields: str | int) -> dict:
    return {
        "event": event,
        "occurred_at": at.isoformat(),
        "request_id": f"app-{number}",
        "client_ip": "203.0.113.10",
        "route": "/orders/{id}",
        "response_status": 403 if event == "authz_denied" else 401,
        **fields,
    }


def _monitor(db_session, *, explicit: bool) -> InfrastructureMonitor:
    monitor = InfrastructureMonitor(
        tenant_id="default", name="rapid", target_binding="https://target.test",
        source_ids=[], context={
            "routes": [{"method": "GET", "path": "/orders/{id}"}],
            "openapi_explicit": explicit,
        },
    )
    db_session.add(monitor)
    db_session.commit()
    return monitor


def test_contract_origin_distinguishes_real_spec_from_har(db_session):
    scan = scans.create_scan(db_session, "https://target.test")
    spec = json.dumps({
        "openapi": "3.0.0", "info": {"title": "x", "version": "1"},
        "paths": {"/orders/{id}": {"get": {"responses": {"200": {"description": "ok"}}}}},
    })
    operations.ingest_spec(db_session, scan, spec)
    assert scan.spec_origin == "openapi"
    assert contract_context(db_session, scan)["openapi_explicit"] is True

    har = json.dumps({"log": {"entries": [{
        "request": {"method": "GET", "url": "https://target.test/orders/123"},
        "response": {"status": 200, "content": {"mimeType": "application/json", "text": "{}"}},
    }]}})
    operations.ingest_spec(db_session, scan, har)
    assert scan.spec_origin == "derived"
    assert contract_context(db_session, scan)["openapi_explicit"] is False


def test_rapid_ingest_detects_and_deduplicates(client, db_session):
    monitor = _monitor(db_session, explicit=True)
    end = datetime.now(UTC).replace(microsecond=0) - timedelta(seconds=15)
    start = end - timedelta(hours=1)
    paths = [_waf(end - timedelta(minutes=4), f"/hidden-{i}", i) for i in range(5)]
    injections = [_waf(end - timedelta(minutes=2), "/payload", 20 + i, label=True)
                  for i in range(3)]
    slow = [_waf(end - timedelta(minutes=55 - i * 4), f"/slow-{i}", 40 + i)
            for i in range(12)]
    principal = "a" * 64
    owner = "b" * 64
    denials = [
        _app(end - timedelta(minutes=3), i, "authz_denied", reason="owner_mismatch",
             principal_hash=principal, resource_id_hash=f"{i % 5:064x}")
        for i in range(10)
    ]
    foreign = _app(end - timedelta(minutes=2), 100, "foreign_object_access",
                   principal_hash=principal, owner_hash=owner, response_status=200)
    failures = [
        _app(end - timedelta(minutes=2), 110 + i, "auth_failed",
             account_hash=f"{i % 5 + 20:064x}")
        for i in range(10)
    ]
    body = {
        "window_start": start.isoformat(), "window_end": end.isoformat(),
        "waf_records": paths + injections + slow,
        "application_events": denials + [foreign] + failures,
    }
    url = f"/monitoring/{monitor.id}/rapid-runs"
    response = client.post(url, json=body)
    assert response.status_code == 200, response.text
    data = response.json()
    kinds = {item["type"] for item in data["observations"]}
    assert {"path_discovery", "injection_attempts", "slow_recon_ip",
            "resource_id_enumeration", "foreign_object_access", "credential_stuffing"} <= kinds
    foreign_obs = [o for o in data["observations"] if o["type"] == "foreign_object_access"]
    assert foreign_obs[0]["confidence"] == "verified"
    assert "203.0.113.10" not in response.text
    assert data["waf_count"] == 20
    assert data["application_count"] == 21
    again = client.post(url, json=body)
    assert again.status_code == 200
    assert again.json()["id"] == data["id"]
    assert len(db_session.scalars(select(MonitoringRapidRun)).all()) == 1
    assert len(db_session.scalars(select(MonitoringAlert)).all()) == 1


def test_path_discovery_requires_explicit_spec(client, db_session):
    monitor = _monitor(db_session, explicit=False)
    end = datetime.now(UTC).replace(microsecond=0) - timedelta(seconds=15)
    response = client.post(f"/monitoring/{monitor.id}/rapid-runs", json={
        "window_start": (end - timedelta(hours=1)).isoformat(),
        "window_end": end.isoformat(),
        "waf_records": [_waf(end - timedelta(minutes=1), f"/hidden-{i}", i)
                        for i in range(5)],
    })
    assert response.status_code == 200, response.text
    assert "path_discovery" not in {o["type"] for o in response.json()["observations"]}
    assert response.json()["skipped"]["path_discovery"]


def test_path_discovery_escalates_on_not_found(client, db_session):
    monitor = _monitor(db_session, explicit=True)
    end = datetime.now(UTC).replace(microsecond=0) - timedelta(seconds=15)
    records = [
        {**_waf(end - timedelta(minutes=1), f"/hidden-{i}", i), "status": 404}
        for i in range(3)
    ]
    response = client.post(f"/monitoring/{monitor.id}/rapid-runs", json={
        "window_start": (end - timedelta(hours=1)).isoformat(),
        "window_end": end.isoformat(),
        "waf_records": records,
    })
    assert response.status_code == 200, response.text
    found = [o for o in response.json()["observations"] if o["type"] == "path_discovery"]
    assert found and found[0]["severity"] == "high"
    assert found[0]["current"]["not_found"] == 3


def test_rapid_run_carries_exact_value_free_five_minute_pulse(client, db_session):
    monitor = _monitor(db_session, explicit=True)
    end = datetime.now(UTC).replace(microsecond=0) - timedelta(seconds=15)
    records = [
        _waf(end - timedelta(minutes=20), "/old", 1, label=True),
        _waf(end - timedelta(minutes=4), "/users/1", 2, label=True),
        {**_waf(end - timedelta(minutes=2), "/hidden", 3), "action": "BLOCK"},
    ]
    data = _post(client, monitor, end, records)
    assert data["waf_count"] == 3
    assert data["pulse"] == {
        "minutes": 5,
        "requests": 2,
        "allowed": 1,
        "blocked": 1,
        "challenged": 0,
        "counted": 0,
        "other_actions": 0,
        "attack_requests": 1,
        "attack_allowed": 1,
        "off_spec_requests": 2,
        "distinct_routes": 2,
        "distinct_clients": 1,
        "bot_requests": 0,
        "unverified_bot_requests": 0,
        "application_events": 0,
        "top_attack_labels": [{"label": "core-rule-set:GenericLFI_URIPath", "requests": 1}],
        "top_routes": [
            {"route": "GET /hidden", "requests": 1},
            {"route": "GET /users/{id}", "requests": 1},
        ],
    }
    serialized = json.dumps(data["pulse"])
    assert "source_ip" not in serialized and "request_id" not in serialized


def _broad(end: datetime, prefix: str, first: int) -> list[dict]:
    """One address spreading 12 requests over 12 paths across most of the hour."""
    return [_waf(end - timedelta(minutes=55 - i * 4), f"/{prefix}-{i}", first + i)
            for i in range(12)]


def _baseline(db_session, monitor, end: datetime, families: list[str], days: int = 7) -> None:
    for offset in range(1, days + 1):
        db_session.add(MonitoringRun(
            monitor_id=monitor.id, observation_date=end.date() - timedelta(days=offset),
            status="complete",
            metrics={
                "event_count": 100,
                "routes": {family: {"requests": 1} for family in families},
            },
        ))
    db_session.commit()


def _post(client, monitor, end: datetime, records: list[dict]):
    response = client.post(f"/monitoring/{monitor.id}/rapid-runs", json={
        "window_start": (end - timedelta(hours=1)).isoformat(),
        "window_end": end.isoformat(),
        "waf_records": records,
    })
    assert response.status_code == 200, response.text
    return response.json()


def test_slow_recon_needs_a_contract_or_a_warm_route_baseline(client, db_session):
    monitor = _monitor(db_session, explicit=False)
    end = datetime.now(UTC).replace(microsecond=0) - timedelta(seconds=15)
    data = _post(client, monitor, end, _broad(end, "page", 0))
    assert not {o["type"] for o in data["observations"]} & {"slow_recon_ip", "slow_recon_ja4"}
    assert "daily runs" in data["skipped"]["slow_recon"]


def test_slow_recon_ignores_browsing_the_routes_the_baseline_knows(client, db_session):
    monitor = _monitor(db_session, explicit=False)
    end = datetime.now(UTC).replace(microsecond=0) - timedelta(seconds=15)
    _baseline(db_session, monitor, end, [f"/page-{i}" for i in range(12)])
    quiet = _post(client, monitor, end, _broad(end, "page", 0))
    assert "slow_recon" not in quiet["skipped"]
    assert "slow_recon_ip" not in {o["type"] for o in quiet["observations"]}

    later = end + timedelta(seconds=5)
    loud = _post(client, monitor, later, _broad(later, "probe", 100))
    found = [o for o in loud["observations"] if o["type"] == "slow_recon_ip"]
    assert found and found[0]["current"]["unknown_shapes"] == 12


def test_contract_clear_forgets_explicit_origin():
    from app.monitoring.setup import CONTRACT_KEYS

    assert "openapi_explicit" in CONTRACT_KEYS


# --- scheduled CloudWatch reader -------------------------------------------------

CONFIG = SourceConfig(
    region="us-west-2", account_id="257498453293", log_group="aws-waf-logs-pd_prod"
)


class _Chain:
    def get_frozen_credentials(self):
        return type("Frozen", (), {"access_key": "AKIDCHAIN", "secret_key": "s", "token": None})()


def _cloudwatch(records: list[dict], calls: list[dict], *, error: str | None = None):
    def handler(request: httpx.Request) -> httpx.Response:
        body = json.loads(request.content)
        calls.append(body)
        if error:
            return httpx.Response(400, json={"__type": error})
        rows = [r for r in records if body["startTime"] <= r["timestamp"] <= body["endTime"]]
        return httpx.Response(200, json={"events": [
            {"eventId": r["httpRequest"]["requestId"], "message": json.dumps(r)} for r in rows
        ]})
    return handler


@pytest.fixture
def aws(monkeypatch):
    monkeypatch.setattr(
        settings, "monitoring_aws_log_groups",
        "arn:aws:logs:us-west-2:257498453293:log-group:aws-waf-logs-pd_prod:*",
    )
    monkeypatch.setattr(remote, "ambient_credentials", lambda: _Chain())
    monkeypatch.setattr(remote, "sleep", lambda seconds: None)


def _serve(monkeypatch, handler) -> None:
    monkeypatch.setattr(
        remote, "client_factory", lambda: httpx.Client(transport=httpx.MockTransport(handler))
    )


def _enabled_monitor(client, *, rapid: bool = True) -> str:
    source = client.post("/monitoring/sources", json={
        "name": "waf", "target_binding": "https://target.test",
        "connector": "aws_cloudwatch", "config": CONFIG.model_dump(exclude_none=True),
    })
    assert source.status_code == 201, source.text
    monitor = client.post("/monitoring", json={
        "name": "m", "target_binding": "https://target.test",
        "source_ids": [source.json()["id"]],
    }).json()
    if rapid:
        response = client.put(f"/monitoring/{monitor['id']}/setup", json={"rapid_enabled": True})
        assert response.status_code == 200, response.text
        assert client.get(f"/monitoring/{monitor['id']}/setup").json()["rapid_enabled"] is True
    return monitor["id"]


def test_scheduled_reader_scores_the_newest_complete_hour(client, aws, monkeypatch):
    monitor_id = _enabled_monitor(client)
    now = datetime.now(UTC)
    start, end = rapid_service.current_window(now)
    assert end - start == timedelta(hours=1)
    assert end <= now - timedelta(seconds=settings.monitoring_rapid_lag_seconds)
    records = [_waf(end - timedelta(minutes=2), "/payload", i, label=True) for i in range(3)]
    records.append(_waf(end + timedelta(minutes=1), "/payload", 99, label=True))  # after window
    calls: list[dict] = []
    _serve(monkeypatch, _cloudwatch(records, calls))

    enqueued: list[tuple[str, str]] = []

    def enqueue(monitor: str, window_end: str) -> None:
        enqueued.append((monitor, window_end))

    assert rapid_service.dispatch(enqueue, now)["dispatched"] == [monitor_id]
    assert enqueued == [(monitor_id, end.isoformat())]
    result = rapid_service.collect_recent(monitor_id, end.isoformat(), now)
    assert result["status"] == "complete"
    runs = client.get(f"/monitoring/{monitor_id}/rapid-runs").json()
    assert len(runs) == 1 and runs[0]["waf_count"] == 3
    assert "coverage" not in runs[0]["skipped"]
    assert {o["type"] for o in runs[0]["observations"]} == {"injection_attempts"}
    assert all(c["startTime"] >= start.timestamp() * 1000 for c in calls)
    assert all(c["endTime"] < end.timestamp() * 1000 for c in calls)

    # The window is stored: neither the next tick nor a retry reads AWS again.
    before = len(calls)
    assert rapid_service.collect_recent(monitor_id, end.isoformat(), now)["status"] == "duplicate"
    assert rapid_service.dispatch(enqueue, now)["dispatched"] == []
    # A message that waited in the queue past its window reads nothing.
    later = now + timedelta(seconds=settings.monitoring_rapid_interval_seconds)
    assert rapid_service.collect_recent(monitor_id, end.isoformat(), later)["status"] == "stale"
    assert len(calls) == before


def test_scheduled_reader_is_opt_in(client, aws, monkeypatch):
    monitor_id = _enabled_monitor(client, rapid=False)
    calls: list[dict] = []
    _serve(monkeypatch, _cloudwatch([], calls))
    assert rapid_service.dispatch(lambda *_: None)["dispatched"] == []
    assert rapid_service.collect_recent(monitor_id)["status"] == "disabled"
    assert calls == []


def test_unreadable_window_is_recorded_as_missing_coverage(client, aws, monkeypatch):
    monitor_id = _enabled_monitor(client)
    _serve(monkeypatch, _cloudwatch([], [], error="AccessDeniedException"))
    assert rapid_service.collect_recent(monitor_id)["status"] == "complete"
    run = client.get(f"/monitoring/{monitor_id}/rapid-runs").json()[0]
    assert run["skipped"]["coverage"].startswith("unavailable:")
    assert run["observations"] == []


def test_truncated_window_is_recorded_as_incomplete(client, aws, monkeypatch):
    monitor_id = _enabled_monitor(client)
    now = datetime.now(UTC)
    _, end = rapid_service.current_window(now)
    records = [_waf(end - timedelta(minutes=1), f"/p{i}", i) for i in range(5)]
    monkeypatch.setattr(settings, "monitoring_rapid_max_events", 2)
    calls: list[dict] = []
    _serve(monkeypatch, _cloudwatch(records, calls))
    rapid_service.collect_recent(monitor_id, now=now)
    run = client.get(f"/monitoring/{monitor_id}/rapid-runs").json()[0]
    assert run["skipped"]["coverage"] == "incomplete: row_limit"
    assert run["waf_count"] == 2
    # The cap stops every slice; the read does not page on through the hour.
    assert len(calls) <= remote.RAPID_SLICES


def test_a_paused_monitor_after_the_read_stores_no_window(client, aws, monkeypatch):
    monitor_id = _enabled_monitor(client)

    def pause_then_serve(request: httpx.Request) -> httpx.Response:
        client.put(f"/monitoring/{monitor_id}/setup", json={"rapid_enabled": False})
        return httpx.Response(200, json={"events": []})

    _serve(monkeypatch, pause_then_serve)
    assert rapid_service.collect_recent(monitor_id)["status"] == "binding_changed"
    assert client.get(f"/monitoring/{monitor_id}/rapid-runs").json() == []


def test_rapid_checks_need_a_cloudwatch_source(client, db_session):
    monitor = _monitor(db_session, explicit=False)
    response = client.put(f"/monitoring/{monitor.id}/setup", json={"rapid_enabled": True})
    assert response.status_code == 409
