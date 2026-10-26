"""``runpentests auth check``: identities checked before a scan, never a scan.

The claim answers consent, the egress guard and the ownership proof, opens no
run and picks a few GET routes; the runner sends those per identity and
anonymously through the same pinned transport and grant minting a scan uses,
and reports verdicts that refuse to call a public 200 a working key.
"""
from __future__ import annotations

import io
import json

import httpx
import pytest

from app.core.config import settings
from app.engine.auth_probe import (
    ACCEPTED,
    INCONCLUSIVE,
    REJECTED,
    UNPROVEN,
    pick_routes,
    verdict,
)
from app.runner import auth_check
from app.runner import main as runner


def test_routes_are_get_only_protected_first_and_bounded():
    ops = [
        {"id": "1", "method": "POST", "path": "/accounts", "auth_scope": "bearer"},
        {"id": "2", "method": "GET", "path": "/public", "auth_scope": None},
        {"id": "3", "method": "GET", "path": "/accounts/{id}", "auth_scope": "bearer"},
        {"id": "4", "method": "GET", "path": "/me", "auth_scope": "bearer"},
        {"id": "5", "method": "GET", "path": "/b", "auth_scope": None},
    ]
    assert [o["id"] for o in pick_routes(ops)] == ["4", "3", "5"]


@pytest.mark.parametrize(
    ("mine", "anon", "state"),
    [
        ([200, 200], [401, 200], ACCEPTED),
        ([401, 403], [401, 401], REJECTED),
        # A public 200 proves nothing about the key.
        ([200], [200], UNPROVEN),
        ([404, 500], [404, 401], INCONCLUSIVE),
        ([None, None], [None, None], INCONCLUSIVE),
    ],
)
def test_verdicts_are_strict(mine, anon, state):
    assert verdict(mine, anon).state == state


@pytest.fixture(autouse=True)
def _enabled(monkeypatch):
    monkeypatch.setattr(settings, "local_runner_enabled", True)


def test_the_claim_needs_consent_and_opens_no_run(client, make_scan):
    scan = make_scan(target_base_url="http://127.0.0.1")
    assert client.post(f"/scans/{scan.id}/auth-checks", json={}).status_code == 403
    r = client.post(f"/scans/{scan.id}/auth-checks", json={"authorized": True})
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["operations"] and all(op["method"] == "GET" for op in body["operations"])
    assert len(body["operations"]) <= 3 and body["max_requests"] <= 40
    assert "token" not in body and "run_id" not in body
    assert all("secret" not in c for c in body["credentials"])
    assert client.get(f"/scans/{scan.id}/runs").json() == []


@pytest.mark.parametrize(
    ("target", "detail"),
    [
        ("http://93.184.216.34", "target not verified"),
        ("http://169.254.169.254", "target not allowed"),
    ],
)
def test_the_claim_answers_the_ownership_gate_and_metadata(client, scan_with_spec, target, detail):
    sid = scan_with_spec(target)
    r = client.post(f"/scans/{sid}/auth-checks", json={"authorized": True})
    assert r.status_code == 422, r.text
    assert detail in r.json()["detail"]


def test_the_claim_is_404_when_local_runs_are_off(client, make_scan, monkeypatch):
    monkeypatch.setattr(settings, "local_runner_enabled", False)
    scan = make_scan(target_base_url="http://127.0.0.1")
    r = client.post(f"/scans/{scan.id}/auth-checks", json={"authorized": True})
    assert r.status_code == 404


@pytest.fixture
def in_process(monkeypatch):
    """The runner's real bridge, bound to the in-process vulnerable app."""
    from app.engine.transport import AsyncHttpClientBridge
    from tests.vulnapp import vulnapp

    def factory(base_url, **kwargs):
        return AsyncHttpClientBridge(
            base_url, **{**kwargs, "requests_per_second": 10000,
                         "transport": httpx.ASGITransport(app=vulnapp)},
        )

    monkeypatch.setattr(auth_check, "AsyncHttpClientBridge", factory)


def _run(cfg):
    out = io.StringIO()
    code = auth_check.main(stdin=io.StringIO(json.dumps(cfg)), stdout=out)
    return code, json.loads(out.getvalue()) if out.getvalue() else None


def test_the_runner_reports_each_identity_without_secrets(client, make_scan, in_process):
    scan = make_scan(target_base_url="http://127.0.0.1")
    check = client.post(f"/scans/{scan.id}/auth-checks", json={"authorized": True}).json()
    code, report = _run({"check": check, "secrets": {"alice": {"secret": "alice-token-XYZ"}}})
    assert code == 0, report
    by_name = {row["name"]: row for row in report["identities"]}
    assert by_name["admin"]["state"] == "missing_secret"
    assert by_name["alice"]["state"] in {ACCEPTED, UNPROVEN, INCONCLUSIVE, REJECTED}
    assert report["requests"] <= check["max_requests"]
    assert "alice-token-XYZ" not in json.dumps(report)


def test_a_rejected_key_is_called_rejected(monkeypatch):
    """Against a target that refuses everything but one real key."""
    from starlette.applications import Starlette
    from starlette.responses import JSONResponse
    from starlette.routing import Route

    from app.engine.transport import AsyncHttpClientBridge

    async def me(request):
        if request.headers.get("authorization") == "Bearer good":
            return JSONResponse({"ok": True})
        return JSONResponse({"detail": "no"}, status_code=401)

    app = Starlette(routes=[Route("/me", me)])
    monkeypatch.setattr(
        auth_check, "AsyncHttpClientBridge",
        lambda base, **kw: AsyncHttpClientBridge(
            base, **{**kw, "transport": httpx.ASGITransport(app=app)}
        ),
    )
    monkeypatch.setattr(runner, "_target_pins", lambda check, target: None)
    shape = {"auth_type": "bearer", "header_name": None, "grant_type": "static"}
    check = {
        "target_base_url": "http://127.0.0.1",
        "operations": [{"id": "1", "method": "GET", "path": "/me", "params": []}],
        "credentials": [
            {"name": "good", "role": "user", **shape},
            {"name": "bad", "role": "user", **shape},
        ],
        "max_requests": 40, "requests_per_second": 1000,
    }
    code, report = _run({"check": check, "secrets": {"good": "good", "bad": "stale"}})
    states = {row["name"]: row["state"] for row in report["identities"]}
    assert states == {"good": ACCEPTED, "bad": REJECTED}
    assert report["anonymous"] == [401]


def test_bad_stdin_is_a_usage_error():
    assert auth_check.main(stdin=io.StringIO("{}"), stdout=io.StringIO()) == 2


def test_identities_past_the_request_cap_are_not_checked_not_inconclusive(monkeypatch):
    from starlette.applications import Starlette
    from starlette.responses import JSONResponse
    from starlette.routing import Route

    from app.engine.transport import AsyncHttpClientBridge

    async def me(request):
        return JSONResponse({"detail": "no"}, status_code=401)

    app = Starlette(routes=[Route("/me", me)])
    monkeypatch.setattr(
        auth_check, "AsyncHttpClientBridge",
        lambda base, **kw: AsyncHttpClientBridge(
            base, **{**kw, "transport": httpx.ASGITransport(app=app)}
        ),
    )
    monkeypatch.setattr(runner, "_target_pins", lambda check, target: None)
    shape = {"role": "user", "auth_type": "bearer", "header_name": None, "grant_type": "static"}
    check = {
        "target_base_url": "http://127.0.0.1",
        "operations": [{"id": "1", "method": "GET", "path": "/me", "params": []}],
        "credentials": [{"name": f"u{i}", **shape} for i in range(4)],
        "max_requests": 3, "requests_per_second": 1000,
    }
    code, report = _run({"check": check, "secrets": {f"u{i}": "k" for i in range(4)}})
    states = [row["state"] for row in report["identities"]]
    # One anonymous request, two identities, then the cap.
    assert states == [REJECTED, REJECTED, "not_checked", "not_checked"]
    assert report["requests"] == 3
