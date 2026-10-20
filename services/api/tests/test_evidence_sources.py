"""Offline connector boundaries and the tenant-bound snapshot lifecycle."""

import json
from datetime import UTC, date, datetime, timedelta

import pytest

from app.core.config import settings
from app.monitoring.connectors import MAX_SNAPSHOT_BYTES, normalize_snapshot

DAY = date(2026, 1, 1)


def record(**overrides):
    return {
        "timestamp": "2026-01-01T12:00:00Z",
        "uri": "/orders/42?token=secret-value",
        "httpMethod": "GET",
        "requestId": "private-request-id",
        "statusCode": 200,
        **overrides,
    }


def snapshot(records):
    return normalize_snapshot(json.dumps(records).encode(), observation_date=DAY, salt=b"test")


def test_aws_nested_snapshot_and_duplicate_delivery():
    events = snapshot(
        [
            {
                "timestamp": int(datetime(2026, 1, 1, 12, tzinfo=UTC).timestamp() * 1000),
                "action": "ALLOW",
                "httpRequest": {
                    "uri": "/orders/42",
                    "args": "token=secret-value",
                    "httpMethod": "GET",
                    "clientIp": "192.0.2.10",
                    "requestId": "private-request-id",
                },
            }
        ]
        * 2
    )
    assert len(events) == 1
    assert events[0].route_family == "/orders/{id}"
    assert events[0].query_keys == ("token",)
    assert events[0].source_ip_hash
    assert events[0].status_code is None  # ALLOW does not prove an origin 200.
    assert "secret-value" not in repr(events)
    assert "private-request-id" not in repr(events)
    assert "192.0.2.10" not in repr(events)


def test_records_without_request_ids_are_not_deduplicated():
    assert len(snapshot([record(requestId=None)] * 2)) == 2


@pytest.mark.parametrize(
    "records",
    [
        {},
        [None],
        [{}],
        [record(timestamp="2026-01-02T00:00:00Z")],
        [record(timestamp="2026-01-01T00:30:00+02:00")],
        [record(timestamp=10**100)],
        [record()] * 10001,
    ],
)
def test_snapshot_rejects_invalid_or_out_of_window_records(records):
    with pytest.raises(ValueError):
        snapshot(records)


def test_snapshot_byte_limit_and_safe_error():
    with pytest.raises(ValueError, match="byte limit"):
        normalize_snapshot(b" " * (MAX_SNAPSHOT_BYTES + 1), observation_date=DAY, salt=b"test")
    with pytest.raises(ValueError) as exc:
        normalize_snapshot(b"secret-value", observation_date=DAY, salt=b"test")
    assert "secret-value" not in str(exc.value)


def setup_source(client, *, headers=None):
    source = client.post(
        "/monitoring/sources",
        headers=headers,
        json={
            "name": "Access logs",
            "target_binding": "https://target.test",
        },
    )
    assert source.status_code == 201, source.text
    source_id = source.json()["id"]
    monitor = client.post(
        "/monitoring",
        headers=headers,
        json={
            "name": "Daily",
            "target_binding": "https://target.test",
            "source_ids": [source_id],
        },
    )
    assert monitor.status_code == 201, monitor.text
    return source_id, monitor.json()["id"]


def upload(client, source_id, monitor_id, records, *, headers=None, revision=1, day=DAY):
    return client.post(
        f"/monitoring/{monitor_id}/sources/{source_id}/snapshot",
        params={"observation_date": str(day), "revision": revision},
        headers={"Content-Type": "application/json", **(headers or {})},
        content=json.dumps(records),
    )


def test_snapshot_replace_replay_revoke_and_delete(client):
    source_id, monitor_id = setup_source(client)
    first = upload(client, source_id, monitor_id, [record()] * 2)
    assert first.status_code == 200, first.text
    row = first.json()
    assert row["metrics"]["routes"]["/orders/{id}"]["requests"] == 1
    assert "secret-value" not in first.text
    assert upload(client, source_id, monitor_id, [record()] * 2).json()["id"] == row["id"]
    changed = upload(client, source_id, monitor_id, [record(), record(requestId="another")])
    assert changed.json()["id"] == row["id"]
    assert changed.json()["metrics"]["routes"]["/orders/{id}"]["requests"] == 2
    assert upload(client, source_id, monitor_id, [record()], revision=2).status_code == 409
    assert client.post(f"/monitoring/sources/{source_id}/revoke").status_code == 200
    assert upload(client, source_id, monitor_id, [record()]).status_code == 409
    assert (
        client.post(
            f"/monitoring/{monitor_id}/runs/ingest",
            json={
                "records": [record()],
                "observation_date": str(DAY),
            },
        ).status_code
        == 409
    )
    assert client.delete(f"/monitoring/sources/{source_id}").status_code == 204
    assert client.get(f"/monitoring/{monitor_id}/runs").json() == []
    assert upload(client, source_id, monitor_id, [record()]).status_code == 404


def test_source_tenant_and_target_binding(client, monkeypatch):
    monkeypatch.setattr(settings, "api_keys", "alice:a-key,bob:b-key")
    alice, bob = {"X-API-Key": "a-key"}, {"X-API-Key": "b-key"}
    source_id, monitor_id = setup_source(client, headers=alice)
    assert client.get("/monitoring/sources", headers=bob).json() == []
    assert upload(client, source_id, monitor_id, [record()], headers=bob).status_code == 404
    assert client.delete(f"/monitoring/sources/{source_id}", headers=bob).status_code == 404
    for headers, target, expected in [
        (bob, "https://target.test", 404),
        (alice, "https://other.test", 409),
    ]:
        response = client.post(
            "/monitoring",
            headers=headers,
            json={
                "name": "Invalid binding",
                "target_binding": target,
                "source_ids": [source_id],
            },
        )
        assert response.status_code == expected


def test_empty_snapshot_is_missing_and_invalid_upload_does_not_replace_day(client):
    source_id, monitor_id = setup_source(client)
    row = upload(client, source_id, monitor_id, []).json()
    assert row["data_quality"] == "missing"
    response = upload(client, source_id, monitor_id, [record(timestamp="bad-secret-value")])
    assert response.status_code == 422
    assert "bad-secret-value" not in response.text
    assert client.get(f"/monitoring/{monitor_id}/runs").json()[0] == row
    assert (
        upload(client, source_id, monitor_id, [], day=datetime.now(UTC).date()).status_code == 422
    )


def test_stream_limit_is_enforced_before_json_parsing(client):
    source_id, monitor_id = setup_source(client)
    response = client.post(
        f"/monitoring/{monitor_id}/sources/{source_id}/snapshot",
        params={"observation_date": str(DAY), "revision": 1},
        content=b" " * (MAX_SNAPSHOT_BYTES + 1),
        headers={"Content-Type": "application/json"},
    )
    assert response.status_code == 413
    assert client.get(f"/monitoring/{monitor_id}/runs").json() == []


def test_manual_collection_selects_previous_complete_day(client):
    _, monitor_id = setup_source(client)
    response = client.post(f"/monitoring/{monitor_id}/run")
    assert response.status_code == 202, response.text
    assert response.json()["observation_date"] == str(datetime.now(UTC).date() - timedelta(days=1))


def test_empty_days_do_not_warm_baseline(client):
    source_id, monitor_id = setup_source(client)
    for offset in range(1, 8):
        assert (
            upload(client, source_id, monitor_id, [], day=DAY - timedelta(days=offset)).status_code
            == 200
        )
    row = upload(client, source_id, monitor_id, [record()]).json()
    assert row["baseline_days_available"] == 0
    assert row["data_quality"] == "warming_up"


def test_delayed_worker_cannot_erase_complete_snapshot(client, db_session):
    from app.models.monitoring import MonitoringRun
    from app.monitoring.service import mark_awaiting_evidence

    source_id, monitor_id = setup_source(client)
    row = upload(client, source_id, monitor_id, [record()]).json()
    run = db_session.get(MonitoringRun, row["id"])
    assert mark_awaiting_evidence(db_session, run).status == "complete"
