"""Known resource ids: previewed by name, carried to the engine, kept off the server.

A read-only scan of ``GET /merchants/{merchantId}`` with an invented id gets a
404 and tests nothing. The user can name a real fixture instead; the server may
tell them which routes each name fills (names only), and the local runner takes
the ids on stdin — the claim and the archived options never hold them.
"""
from __future__ import annotations

import io

import pytest

from app.core.config import settings
from app.engine.resource_map import preview_bindings
from app.runner import main as runner
from app.runner.main import EXIT_OK, ServerLink, execute
from app.scans.run_options import supplied_resource_ids

OPS = [
    ("GET", "/merchants/{merchantId}"),
    ("GET", "/merchants/{merchant_id}/statements"),
    ("GET", "/projects/{projectId}/items/{itemId}"),
    ("GET", "/monitors/{id}"),
    ("GET", "/orphans/{thing}"),
]


def test_preview_uses_the_engine_s_own_matching():
    out = preview_bindings(OPS, ["merchant", "project", "item", "monitor"])
    routes = {row["name"]: row["routes"] for row in out["names"]}
    assert [r["param"] for r in routes["merchant"]] == ["merchantId", "merchant_id"]
    assert [r["path"] for r in routes["project"]] == ["/projects/{projectId}/items/{itemId}"]
    assert [r["param"] for r in routes["item"]] == ["itemId"]
    # A bare {id} takes the segment before it.
    assert [r["path"] for r in routes["monitor"]] == ["/monitors/{id}"]
    assert out["unbound"] == [{"method": "GET", "path": "/orphans/{thing}", "param": "thing"}]


def test_two_spellings_of_one_resource_are_ambiguous():
    out = preview_bindings(OPS, ["merchant", "merchant_id", "nothing"])
    by_name = {row["name"]: row for row in out["names"]}
    assert by_name["merchant"]["ambiguous_with"] == ["merchant_id"]
    assert by_name["merchant_id"]["ambiguous_with"] == ["merchant"]
    assert by_name["nothing"]["routes"] == []


def test_the_route_takes_names_never_ids(client, scan_with_spec):
    sid = scan_with_spec()
    r = client.post(f"/scans/{sid}/resource-bindings", json={"names": ["account", "nope"]})
    assert r.status_code == 200, r.text
    names = {row["name"]: row for row in r.json()["names"]}
    assert names["account"]["routes"] and names["nope"]["routes"] == []
    # A name that breaks the grammar is refused; the body has nowhere for an id.
    assert client.post(
        f"/scans/{sid}/resource-bindings", json={"names": ["bad/name"]}
    ).status_code == 422


def test_supplied_ids_are_validated_like_the_run_request():
    assert supplied_resource_ids(
        {"merchant": " m_1 ", "bad/name": "x", "item": "a/b", "ok.name": "7", 3: "x"}
    ) == {"merchant": "m_1", "ok.name": "7"}
    assert supplied_resource_ids("nope") == {}


@pytest.fixture
def bridges(monkeypatch):
    import httpx

    from app.engine.transport import AsyncHttpClientBridge
    from tests.vulnapp import vulnapp

    def factory(base_url, **kwargs):
        return AsyncHttpClientBridge(
            base_url,
            **{**kwargs, "requests_per_second": 10000,
               "transport": httpx.ASGITransport(app=vulnapp)},
        )

    monkeypatch.setattr(runner, "AsyncHttpClientBridge", factory)


def test_the_runner_uses_ids_from_stdin_and_the_server_never_stores_the_map(
    client, make_scan, bridges, monkeypatch
):
    monkeypatch.setattr(settings, "local_runner_enabled", True)
    scan = make_scan(target_base_url="http://127.0.0.1")
    claim = client.post(f"/scans/{scan.id}/local-runs", json={"authorized": True}).json()
    assert "predefined_resource_ids" not in claim["options"]

    cfg = {
        "server": "http://testserver", "run": claim, "runner_version": "t1",
        "secrets": {"alice": {"secret": "alice-token"}, "admin": {"secret": "admin-token"}},
        "predefined_resource_ids": {"account": "fixture-account-7731"},
    }
    link = ServerLink("http://testserver", claim["run_id"], claim["token"], client=client)
    out = io.StringIO()
    assert execute(cfg, link, out=out) == EXIT_OK, out.getvalue()

    events = client.get(f"/scans/{scan.id}/events").json()
    assert any("using predefined 'account' resource id" in e["message"] for e in events)
    run = client.get(f"/scans/{scan.id}/runs").json()[0]
    assert "predefined_resource_ids" not in run["options"]
