"""Create probes send a body the target can accept.

The write-side checks used to send only the field carrying their canary (plus
what the parser flattened as required). A create DTO written as ``allOf`` +
``required`` therefore went out with neither required field, and the target
answered 400 from validation — before the authorization decision the probe
exists to test.
"""
from __future__ import annotations

from dataclasses import replace

from fastapi import FastAPI, Header
from fastapi.responses import JSONResponse
from fastapi.testclient import TestClient

from app.engine.base import TargetOperation
from app.engine.checks.write_oracle import WriteOracleCheck
from app.engine.request_bodies import create_body
from app.engine.resource_map import build_body
from tests import factories

SPEC = {
    "openapi": "3.1.0",
    "info": {"title": "widgets", "version": "1"},
    "paths": {
        "/widgets": {"post": {"requestBody": {"content": {"application/json": {
            "schema": {"$ref": "#/components/schemas/WidgetCreate"}}}},
            "responses": {"201": {"description": "created"}}}},
        "/widgets/{widget_id}": {"get": {
            "parameters": [{"name": "widget_id", "in": "path", "required": True}],
            "responses": {"200": {"description": "ok"}}}},
    },
    "components": {"schemas": {
        "Role": {"type": "string", "enum": ["admin", "member"]},
        "WidgetInput": {"type": "object", "properties": {
            "name": {"type": "string"},
            "url": {"type": "string", "format": "uri"},
            "role": {"$ref": "#/components/schemas/Role"},
            "note": {"type": "string"},
        }},
        "WidgetCreate": {"allOf": [{"$ref": "#/components/schemas/WidgetInput"}],
                         "required": ["name", "url", "role"]},
    }},
}

POST = TargetOperation(
    id="w-post", method="POST", path="/widgets",
    params=[{"name": "name", "in": "body", "required": False, "schema": {"type": "string"}}],
)
GET = TargetOperation(
    id="w-get", method="GET", path="/widgets/{widget_id}",
    params=[{"name": "widget_id", "in": "path", "required": True}],
)


def _ctx(spec=SPEC, **kwargs):
    return factories.scan_context([POST, GET], spec=spec, **kwargs)


def test_every_required_field_is_filled_and_the_canary_rides_in_its_field() -> None:
    body = create_body(_ctx(), POST, "name", "aidxcanary")
    assert body["name"] == "aidxcanary"
    assert body["url"]
    # Optional scalars stay out: the target's default is valid by definition.
    assert "note" not in body


def test_a_required_enum_never_takes_a_privileged_value() -> None:
    # role: [admin, member] — a scanner that grants itself admin while testing
    # someone's API has escalated, not found a bug.
    assert create_body(_ctx(), POST, "name", "aidxcanary")["role"] == "member"


def test_without_a_spec_the_minimal_body_stands() -> None:
    assert create_body(_ctx(spec=None), POST, "name", "x") == build_body(POST, "name", "x")


def test_a_shared_seed_builds_the_same_other_fields() -> None:
    ctx = _ctx()
    first = create_body(ctx, POST, "name", "a", seed="s1")
    again = create_body(ctx, POST, "name", "a", seed="s1")
    assert first == again


def _api() -> FastAPI:
    """Validates like a real create DTO, and reads any widget back to any
    authenticated caller (a BOLA the write oracle should prove)."""
    app = FastAPI()
    widgets: dict[str, dict] = {}

    @app.post("/widgets")
    def make(body: dict, authorization: str | None = Header(default=None)):
        if not authorization:
            return JSONResponse({"error": "sign in"}, status_code=401)
        if not body.get("name") or not body.get("url"):
            return JSONResponse({"error": "name and url are required"}, status_code=400)
        wid = str(len(widgets) + 1)
        widgets[wid] = {"id": wid, **body}
        return JSONResponse(widgets[wid], status_code=201)

    @app.get("/widgets/{widget_id}")
    def read(widget_id: str, authorization: str | None = Header(default=None)):
        if not authorization:
            return JSONResponse({"error": "sign in"}, status_code=401)
        return widgets.get(widget_id) or JSONResponse({}, status_code=404)

    return app


def test_the_write_oracle_create_now_reaches_the_authorization_decision() -> None:
    owner = replace(factories.credential("owner", "editor"), tenant="a")
    other = replace(factories.credential("other", "editor"), tenant="b")
    ctx = _ctx(credentials=[owner, other], allow_mutation=True, client=TestClient(_api()))
    findings = WriteOracleCheck().run(ctx)
    created = [r for r in ctx.probe.mutations if r["method"] == "POST"]
    assert created and all(r["response"]["status"] == 201 for r in created)
    assert any(f.evidence["kind"] == "create" for f in findings)
