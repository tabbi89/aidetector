"""Changing a scan's target re-derives its operation routes from the spec.

A route depends on the target as well as the spec: a spec served under
``/api/v1`` stores ``/monitors`` for a target that already ends in ``/api/v1``
and ``/api/v1/monitors`` for one that does not. Before this, a target change
kept the routes composed for the old target, and every request went to
``/api/v1/api/v1/monitors``.
"""
from __future__ import annotations

import json

from app.models.scan import Scan

SPEC = json.dumps({
    "openapi": "3.0.0",
    "info": {"title": "monitors", "version": "1"},
    "servers": [{"url": "https://monitors.example.test/api/v1"}],
    "paths": {
        "/monitors": {"get": {"responses": {"200": {"description": "ok"}}},
                      "post": {"responses": {"200": {"description": "ok"}}}},
        "/monitors/{id}": {"get": {
            "parameters": [{"name": "id", "in": "path", "required": True,
                            "schema": {"type": "string"}}],
            "responses": {"200": {"description": "ok"}},
        }},
    },
})

BARE = "http://target:9000"
PREFIXED = "http://target:9000/api/v1"


def _scan(client, target: str) -> str:
    sid = client.post("/scans", json={"target_base_url": target}).json()["id"]
    assert client.post(f"/scans/{sid}/spec", json={"content": SPEC}).status_code == 200
    return sid


def _ops(client, sid: str) -> dict[tuple[str, str], dict]:
    return {(o["method"], o["path"]): o for o in client.get(f"/scans/{sid}").json()["operations"]}


def _retarget(client, sid: str, target: str) -> None:
    r = client.patch(f"/scans/{sid}", json={"target_base_url": target})
    assert r.status_code == 200, r.text


def test_a_target_change_moves_routes_and_keeps_each_operation(client):
    sid = _scan(client, BARE)
    before = _ops(client, sid)
    assert set(before) == {
        ("GET", "/api/v1/monitors"), ("POST", "/api/v1/monitors"),
        ("GET", "/api/v1/monitors/{id}"),
    }
    item = before[("GET", "/api/v1/monitors/{id}")]
    r = client.patch(f"/scans/{sid}/operations",
                     json={"operations": [{"id": item["id"], "enabled": False}]})
    assert r.status_code == 200, r.text

    _retarget(client, sid, PREFIXED)
    after = _ops(client, sid)
    assert set(after) == {("GET", "/monitors"), ("POST", "/monitors"), ("GET", "/monitors/{id}")}
    # The same rows moved: ids and the person's opt-out survive.
    assert {o["id"] for o in after.values()} == {o["id"] for o in before.values()}
    assert after[("GET", "/monitors/{id}")]["id"] == item["id"]
    assert after[("GET", "/monitors/{id}")]["enabled"] is False

    _retarget(client, sid, BARE)
    assert set(_ops(client, sid)) == set(before)

    # The activity log says why the next run's findings will not match old triage.
    messages = [e["message"] for e in client.get(f"/scans/{sid}/events").json()
                if e["stage"] == "operations_retargeted"]
    assert any(m.startswith("3 endpoint route(s) re-derived") for m in messages)


def test_re_saving_the_target_repairs_routes_a_past_change_left_stale(client, db_session):
    sid = _scan(client, BARE)
    # A target changed before routes were re-derived: the row says PREFIXED,
    # the routes are still composed for BARE.
    scan = db_session.get(Scan, sid)
    scan.target_base_url = PREFIXED
    db_session.commit()
    assert ("GET", "/api/v1/monitors") in _ops(client, sid)

    _retarget(client, sid, PREFIXED)
    assert set(_ops(client, sid)) == {
        ("GET", "/monitors"), ("POST", "/monitors"), ("GET", "/monitors/{id}"),
    }


def test_a_target_change_refreshes_the_routing_warning(client):
    sid = _scan(client, PREFIXED)

    def warnings() -> list[str]:
        events = client.get(f"/scans/{sid}/events").json()
        return [e["message"] for e in events if e["stage"] == "spec_warning"]

    assert not any("do not overlap" in w for w in warnings())
    _retarget(client, sid, "http://target:9000/other")
    assert any("do not overlap" in w for w in warnings())
    assert ("GET", "/api/v1/monitors") in _ops(client, sid)
    _retarget(client, sid, PREFIXED)
    assert not any("do not overlap" in w for w in warnings())


def test_a_scan_without_a_spec_just_changes_its_target(client):
    sid = client.post("/scans", json={"target_base_url": BARE}).json()["id"]
    _retarget(client, sid, PREFIXED)
    scan = client.get(f"/scans/{sid}").json()
    assert scan["target_base_url"] == PREFIXED and scan["operations"] == []


def _stale(client, db_session, bare: str, prefixed: str) -> str:
    """A scan whose routes were composed for ``bare`` while its target says
    ``prefixed`` — what a target change on a server without re-derivation left."""
    sid = _scan(client, bare)
    scan = db_session.get(Scan, sid)
    scan.target_base_url = prefixed
    db_session.commit()
    assert ("GET", "/api/v1/monitors") in _ops(client, sid)
    return sid


def test_a_local_claim_repairs_stale_routes_before_handing_them_out(
    client, db_session, monkeypatch
):
    # The target never changes again, so nothing else would ever repair these:
    # every request of every run went to /api/v1/api/v1/monitors and read 404.
    from app.core.config import settings

    monkeypatch.setattr(settings, "local_runner_enabled", True)
    sid = _stale(client, db_session, "http://127.0.0.1", "http://127.0.0.1/api/v1")
    r = client.post(f"/scans/{sid}/local-runs", json={"authorized": True})
    assert r.status_code == 201, r.text
    assert {(o["method"], o["path"]) for o in r.json()["operations"]} == {
        ("GET", "/monitors"), ("POST", "/monitors"), ("GET", "/monitors/{id}"),
    }
    stages = [e["stage"] for e in client.get(f"/scans/{sid}/events").json()]
    # After the claim's event reset, so the run's own log says routes moved.
    assert "operations_retargeted" in stages


def test_a_server_run_repairs_stale_routes_and_says_so(client, db_session, engine_client):
    from app.engine.runner import run_scan

    sid = _stale(client, db_session, "http://127.0.0.1", "http://127.0.0.1/api/v1")
    scan = db_session.get(Scan, sid)
    run_scan(db_session, scan, client=engine_client)
    assert {(op.method, op.path) for op in scan.operations} == {
        ("GET", "/monitors"), ("POST", "/monitors"), ("GET", "/monitors/{id}"),
    }
    messages = [e.message for e in scan.events if e.stage == "operations_retargeted"]
    assert any("re-derived" in m for m in messages)


def test_a_run_with_current_routes_moves_nothing(client, db_session, engine_client):
    from app.engine.runner import run_scan

    sid = _scan(client, "http://127.0.0.1/api/v1")
    scan = db_session.get(Scan, sid)
    before = {(op.id, op.path) for op in scan.operations}
    run_scan(db_session, scan, client=engine_client)
    assert {(op.id, op.path) for op in scan.operations} == before
    assert not [e for e in scan.events if e.stage == "operations_retargeted"]
