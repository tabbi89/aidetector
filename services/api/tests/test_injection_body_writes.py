"""Body-sink injection: it runs under mutate, as a writer, and leaves no trace.

Fuzzing a POST/PUT/PATCH body creates and updates real objects. The checks must
send as an identity allowed to write, and the target must end a scan in the
state it started — created objects deleted, updated fields restored.
"""
from __future__ import annotations

from dataclasses import replace

from fastapi import FastAPI, Header
from fastapi.responses import JSONResponse
from fastapi.testclient import TestClient

from app.engine.base import TargetOperation
from app.engine.checks.injection import ReflectedInjectionCheck
from app.engine.checks.signature_injection import SignatureInjectionCheck
from tests import factories

SPEC = {
    "openapi": "3.1.0",
    "info": {"title": "widgets", "version": "1"},
    "paths": {
        "/widgets": {"post": {"requestBody": {"content": {"application/json": {
            "schema": {"$ref": "#/components/schemas/WidgetCreate"}}}},
            "responses": {"201": {"description": "c"}}}},
        "/widgets/{widget_id}": {
            "parameters": [{"name": "widget_id", "in": "path", "required": True,
                            "schema": {"type": "string"}}],
            "get": {"responses": {"200": {"description": "ok"}}},
            "patch": {"requestBody": {"content": {"application/json": {
                "schema": {"$ref": "#/components/schemas/WidgetInput"}}}},
                "responses": {"200": {"description": "ok"}}},
            "delete": {"responses": {"204": {"description": "gone"}}},
        },
    },
    "components": {"schemas": {
        "WidgetInput": {"type": "object", "properties": {
            "name": {"type": "string"},
            # A 3.1 list type — the shape that used to crash point building.
            "ttl": {"type": ["integer", "null"]},
        }},
        "WidgetCreate": {"allOf": [{"$ref": "#/components/schemas/WidgetInput"}],
                         "required": ["name"]},
    }},
}

OPS = [
    TargetOperation(id="post", method="POST", path="/widgets",
                    params=[{"name": "name", "in": "body", "required": True,
                             "schema": {"type": "string"}}]),
    TargetOperation(id="get", method="GET", path="/widgets/{widget_id}",
                    params=[{"name": "widget_id", "in": "path", "required": True}]),
    TargetOperation(id="patch", method="PATCH", path="/widgets/{widget_id}",
                    params=[{"name": "widget_id", "in": "path", "required": True},
                            {"name": "name", "in": "body", "required": False,
                             "schema": {"type": "string"}}]),
    TargetOperation(id="del", method="DELETE", path="/widgets/{widget_id}",
                    params=[{"name": "widget_id", "in": "path", "required": True}]),
]


def _app() -> tuple[FastAPI, dict]:
    app = FastAPI()
    store: dict[str, dict] = {"1": {"id": "1", "name": "original", "ttl": 60}}
    calls = {"next": 2}

    def auth(h: str | None) -> bool:
        return h in ("writer-token", "owner-token")

    @app.post("/widgets")
    def make(body: dict, authorization: str | None = Header(default=None)):
        if authorization != "writer-token":  # a read key may not create
            return JSONResponse({"error": "read only"}, status_code=403)
        if not isinstance(body.get("name"), str):
            return JSONResponse({"error": "name required"}, status_code=400)
        wid = str(calls["next"])
        calls["next"] += 1
        store[wid] = {"id": wid, **body}
        return JSONResponse(store[wid], status_code=201)

    @app.get("/widgets/{wid}")
    def read(wid: str, authorization: str | None = Header(default=None)):
        if not auth(authorization):
            return JSONResponse({}, status_code=401)
        return store.get(wid) or JSONResponse({}, status_code=404)

    @app.patch("/widgets/{wid}")
    def patch(wid: str, body: dict, authorization: str | None = Header(default=None)):
        if authorization != "writer-token":
            return JSONResponse({"error": "read only"}, status_code=403)
        if wid in store:
            store[wid].update({k: v for k, v in body.items() if k in ("name", "ttl")})
        return store.get(wid) or JSONResponse({}, status_code=404)

    @app.delete("/widgets/{wid}")
    def remove(wid: str, authorization: str | None = Header(default=None)):
        if authorization != "writer-token":
            return JSONResponse({}, status_code=403)
        store.pop(wid, None)
        return JSONResponse({}, status_code=204)

    return app, store


def _ctx(client):
    reader = replace(factories.credential("reader", "viewer"), tenant="a")
    writer = replace(factories.credential("writer", "editor"), tenant="a")
    ctx = factories.scan_context(
        OPS, spec=SPEC, allow_mutation=True, credentials=[reader, writer], client=client
    )
    ctx.resource_ids["widget"] = "1"
    return ctx


def test_body_injection_sends_as_a_writer_and_leaves_the_target_as_it_was():
    app, store = _app()
    before = {k: dict(v) for k, v in store.items()}
    ctx = _ctx(TestClient(app))
    ReflectedInjectionCheck().run(ctx)
    SignatureInjectionCheck().run(ctx)

    writes = [m for m in ctx.probe.mutations if m["method"] in ("POST", "PATCH")]
    assert writes, "body sinks should have been fuzzed"
    # Every write went out as the writer, never the read-only key.
    assert all(m["identity"] == "writer" for m in writes)
    # The target is back to its starting state: no leftover objects, field restored.
    assert store == before
    assert ctx.cleanup_failures == []


def test_an_update_with_no_read_back_is_skipped_not_reported_as_a_failed_cleanup():
    """No GET to read the original from means no restore, so nothing is written —
    and a skipped write is not a cleanup failure."""
    app, store = _app()
    ops = [op for op in OPS if op.method != "GET"]
    reader = replace(factories.credential("reader", "viewer"), tenant="a")
    writer = replace(factories.credential("writer", "editor"), tenant="a")
    ctx = factories.scan_context(
        ops, spec=SPEC, allow_mutation=True, credentials=[reader, writer],
        client=TestClient(app),
    )
    ctx.resource_ids["widget"] = "1"
    ReflectedInjectionCheck().run(ctx)
    SignatureInjectionCheck().run(ctx)

    assert not [m for m in ctx.probe.mutations if m["method"] == "PATCH"]
    assert store["1"] == {"id": "1", "name": "original", "ttl": 60}
    assert not [f for f in ctx.cleanup_failures if "no read-back" in f]


def test_body_injection_is_skipped_without_a_writer():
    # Only a read-only identity: nothing may create, so nothing is attempted.
    app, store = _app()
    reader = factories.credential("reader", "viewer")
    ctx = factories.scan_context(
        OPS, spec=SPEC, allow_mutation=True, credentials=[reader], client=TestClient(app)
    )
    # lowest_writer falls back to the only identity; the server refuses its
    # writes (403), so still nothing persists.
    ReflectedInjectionCheck().run(ctx)
    assert store == {"1": {"id": "1", "name": "original", "ttl": 60}}
