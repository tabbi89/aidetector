"""Unit tests for spec-shaped injection value/point helpers — pure, no DB."""
from __future__ import annotations

from app.engine.base import TargetOperation
from app.engine.spec_values import (
    base_value,
    injection_points,
    injection_value,
    prepare,
)


def test_base_value_respects_enum_type_and_format():
    assert base_value({"enum": ["active", "closed"]}) == "active"
    assert base_value({"type": "integer"}) == "1"
    assert base_value({"type": "boolean"}) == "true"
    assert base_value({"type": "string", "format": "email"}) == "probe@example.com"
    assert base_value({"type": "string", "format": "uuid"}).count("-") == 4
    assert base_value(None) == "1"


def test_injection_value_keeps_valid_prefix_for_typed_params():
    marker = "aidx123"
    # enum: prefix with a valid member so an upfront validator is more forgiving
    assert injection_value({"enum": ["active"]}, marker) == f"active{marker}"
    # numeric: prefix with a valid number, marker still travels verbatim
    assert injection_value({"type": "integer"}, marker) == f"1{marker}"
    # formatted string: prefix with a valid value
    assert injection_value({"type": "string", "format": "email"}, marker).endswith(marker)
    # plain string / no schema: payload sent as-is (back-compatible)
    assert injection_value({"type": "string"}, marker) == marker
    assert injection_value(None, marker) == marker


def test_injection_points_scope_by_method():
    get_op = TargetOperation(
        id="g", method="GET", path="/x/{id}",
        params=[
            {"name": "id", "in": "path", "required": True},
            {"name": "q", "in": "query", "required": False},
        ],
    )
    locs = {(p.location, p.name) for p in injection_points(get_op)}
    assert locs == {("path", "id"), ("query", "q")}

    post_op = TargetOperation(
        id="p", method="POST", path="/x",
        params=[{"name": "title", "in": "body", "required": True}],
    )
    # body sinks on a mutating verb are gated behind the mutate opt-in
    assert injection_points(post_op) == []
    assert [
        (p.location, p.name) for p in injection_points(post_op, allow_body_writes=True)
    ] == [("body", "title")]

    # DELETE with only a path param is left untouched (no junk mutating requests)
    del_op = TargetOperation(
        id="d", method="DELETE", path="/x/{id}",
        params=[{"name": "id", "in": "path", "required": True}],
    )
    assert injection_points(del_op) == []


def test_prepare_fills_other_required_params_with_baselines():
    op = TargetOperation(
        id="m", method="GET", path="/merchants",
        params=[
            {"name": "email", "in": "query", "required": False},
            {"name": "limit", "in": "query", "required": True, "schema": {"type": "integer"}},
        ],
    )
    point = next(p for p in injection_points(op) if p.name == "email")
    path, params, json_body = prepare(op, point, "PAYLOAD")
    assert path == "/merchants"
    assert params["email"] == "PAYLOAD"
    assert params["limit"] == "1"  # required sibling filled with a spec-valid baseline
    assert json_body is None


def test_prepare_path_target_substitutes_and_baselines_siblings():
    op = TargetOperation(
        id="i", method="GET", path="/o/{oid}/items/{sid}",
        params=[
            {"name": "oid", "in": "path", "required": True, "schema": {"type": "integer"}},
            {"name": "sid", "in": "path", "required": True},
        ],
    )
    point = next(p for p in injection_points(op) if p.name == "sid")
    path, params, json_body = prepare(op, point, "PWN")
    assert path == "/o/1/items/PWN"  # oid baselined to 1, sid carries the payload
    assert params is None and json_body is None


def test_prepare_reuses_resource_id_for_a_mutating_body_probe():
    op = TargetOperation(
        id="patch", method="PATCH", path="/merchants/{merchant_id}",
        params=[
            {"name": "merchant_id", "in": "path", "required": True},
            {"name": "name", "in": "body", "required": True},
        ],
    )
    point = next(p for p in injection_points(op, allow_body_writes=True) if p.name == "name")

    path, params, json_body = prepare(
        op, point, "PAYLOAD", resource_ids={"merchant": "existing-42"}
    )

    assert path == "/merchants/existing-42"
    assert params is None
    assert json_body == {"name": "PAYLOAD"}
