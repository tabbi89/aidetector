"""Regression cases for methodology, including paired behavioral ground truth."""

import json
from concurrent.futures import ThreadPoolExecutor

import pytest
from fastapi.testclient import TestClient

from app.engine.business_state import run_workflows
from app.engine.independent_injection import confirm_independently
from app.engine.methodology import finish_manifest
from app.engine.request_shapes import points, request
from tests import factories
from tests.methodology_targets import target, workflow_spec


def expression_context(vulnerable=True, mode="compute", budget=500):
    app, _ = target(vulnerable=vulnerable, expression_mode=mode)
    op = factories.operation(
        "GET",
        "/preview",
        params=[
            {"name": "template", "in": "query", "schema": {"type": "string"}},
        ],
    )
    ctx = factories.scan_context([op], client=TestClient(app), max_requests=budget)
    ctx.confirm = True
    return ctx


@pytest.mark.parametrize(
    "vulnerable,mode,expected",
    [
        (True, "compute", 1),
        (False, "compute", 0),
        (True, "static", 0),
        (True, "reject", 0),
    ],
)
def test_confirmation_does_not_need_reflection(vulnerable, mode, expected):
    ctx = expression_context(vulnerable, mode)
    findings = confirm_independently(ctx)
    assert len(findings) == expected
    assert ctx.probe.count <= 5
    if expected:
        assert findings[0].confidence.value == "verified"
        assert not findings[0].evidence["reflected"]
    if mode == "reject":
        assert ctx.probe.test_cases[0]["outcome"] == "blocked"


def test_confirm_remains_opt_in_and_reserves_whole_case():
    ctx = expression_context(budget=4)
    assert not confirm_independently(ctx)
    assert ctx.probe.count == 0
    assert ctx.probe.test_cases[0]["outcome"] == "budget_exhausted"
    ctx.confirm = False
    assert not confirm_independently(ctx)


def workflow_context(vulnerable=True, budget=500):
    app, rows = target(vulnerable=vulnerable)
    operations = [
        factories.operation(method, path)
        for method, path in [
            ("POST", "/drafts"),
            ("GET", "/drafts/{id}"),
            ("DELETE", "/drafts/{id}"),
            ("POST", "/drafts/{id}/approve"),
            ("POST", "/drafts/{id}/settle"),
        ]
    ]
    ctx = factories.scan_context(
        operations,
        client=TestClient(app),
        max_requests=budget,
        allow_mutation=True,
        credentials=[
            factories.credential("owner", "user"),
            factories.credential("peer", "user"),
        ],
    )
    ctx.spec = workflow_spec()
    return ctx, rows


@pytest.mark.parametrize("vulnerable", [True, False])
def test_workflows_compare_fresh_control_skip_replay_and_peer(vulnerable):
    ctx, rows = workflow_context(vulnerable)
    findings = run_workflows(ctx)
    assert len(findings) == (3 if vulnerable else 0)
    assert rows == {}
    assert ctx.probe.cleanup_results == [True] * 6
    assert all(c["baseline_valid"] for c in ctx.probe.test_cases)
    assert all(
        c["outcome"] == ("finding" if vulnerable else "passed") for c in ctx.probe.test_cases
    )


def test_workflow_rejects_out_of_scope_steps_and_insufficient_budget():
    ctx, rows = workflow_context(budget=12)
    assert run_workflows(ctx) == []
    assert ctx.probe.count == 0 and rows == {}
    ctx.spec["x-aidetector-workflows"][0]["transitions"][0]["path"] = "https://elsewhere.invalid"
    assert run_workflows(ctx) == []
    assert ctx.probe.count == 0


def test_reserved_cleanup_survives_competition_and_fairness_limit():
    ctx = expression_context(budget=4)
    probe = ctx.probe
    probe._per_operation_max = 1
    with probe.test_case(4, cleanup=1, label="protected") as case:
        assert case is not None
        assert probe.send("GET", "/preview")
        with ThreadPoolExecutor(1) as pool:
            assert pool.submit(probe.send, "GET", "/preview").result() is None
        assert probe.send("GET", "/preview")
        assert probe.send("GET", "/preview")
        assert probe.send("GET", "/preview") is None
        with probe.cleanup_scope():
            assert probe.send("GET", "/preview")
    assert probe.count == 4 and probe._held == 0


def test_exception_releases_slots_but_deferred_cleanup_stays_reserved():
    ctx = expression_context(budget=3)
    with pytest.raises(RuntimeError), ctx.probe.test_case(3, cleanup=1):
        ctx.probe.defer_cleanup()
        raise RuntimeError("broken test")
    assert ctx.probe._held == 1
    assert ctx.probe.send("GET", "/preview")
    assert ctx.probe.send("GET", "/preview")
    assert ctx.probe.send("GET", "/preview") is None
    with ctx.probe.cleanup_scope():
        assert ctx.probe.send("GET", "/preview")
    assert ctx.probe._held == 0


def body_context(schema, media="application/json"):
    op = factories.operation("POST", "/inputs")
    ctx = factories.scan_context([op], allow_mutation=True)
    ctx.spec = {
        "paths": {
            "/inputs": {
                "post": {
                    "requestBody": {
                        "content": {
                            media: {"schema": schema},
                        }
                    }
                }
            }
        }
    }
    return ctx, op


def test_nested_arrays_and_alternatives_preserve_valid_companions():
    ctx, op = body_context(
        {
            "oneOf": [
                {
                    "type": "object",
                    "required": ["kind", "items"],
                    "properties": {
                        "kind": {"const": "many"},
                        "items": {
                            "type": "array",
                            "items": {
                                "type": "object",
                                "required": ["count", "text"],
                                "properties": {
                                    "count": {"type": "integer"},
                                    "text": {"type": "string"},
                                },
                            },
                        },
                    },
                },
                {
                    "type": "object",
                    "required": ["kind", "message"],
                    "properties": {"kind": {"const": "single"}, "message": {"type": "string"}},
                },
            ]
        }
    )
    candidates = points(ctx, op)
    point = next(p for p in candidates if p.name == "/items/0/text")
    _, kwargs = request(ctx, op, point, "PAYLOAD", {})
    assert kwargs["json"] == {"kind": "many", "items": [{"count": 1, "text": "PAYLOAD"}]}
    other = next(p for p in candidates if p.name == "/message")
    assert other.body == {"kind": "single", "message": "1"}
    ctx.allow_mutation = False
    assert points(ctx, op) == []


@pytest.mark.parametrize(
    "media", ["application/x-www-form-urlencoded", "multipart/form-data", "text/plain"]
)
def test_non_json_wire_encoding(media):
    schema = (
        {"type": "string"}
        if media == "text/plain"
        else {"type": "object", "properties": {"message": {"type": "string"}}}
    )
    ctx, op = body_context(schema, media)
    point = points(ctx, op)[0]
    _, kwargs = request(ctx, op, point, "a&b", {})
    assert "json" not in kwargs
    assert kwargs["headers"]["Content-Type"].startswith(media)
    assert (b"a%26b" if "urlencoded" in media else b"a&b") in kwargs["content"]


def test_header_and_cookie_injection_preserves_authentication():
    op = factories.operation(
        "GET",
        "/preview",
        params=[
            {"name": "X-Filter", "in": "header"},
            {"name": "view", "in": "cookie"},
            {"name": "Authorization", "in": "header"},
            {"name": "Host", "in": "header"},
        ],
    )
    ctx = factories.scan_context([op])
    candidates = points(ctx, op)
    assert len(candidates) == 2
    _, kwargs = request(ctx, op, candidates[1], "a;b", {"Cookie": "session=secret; view=old"})
    assert kwargs["headers"]["Cookie"] == "session=secret; view=a%3Bb"


def test_same_seed_replays_confirmation_requests_and_manifest_metrics():
    a, b = expression_context(), expression_context()
    confirm_independently(a)
    confirm_independently(b)
    assert [r["response"]["body"] for r in a.probe.mutations] == [
        r["response"]["body"] for r in b.probe.mutations
    ]
    metrics = finish_manifest(a.probe)["metrics"]
    assert metrics["valid_request_coverage"] == 1
    assert metrics["completed_cases"] == 1
    assert metrics["cleanup_success_rate"] is None
    assert "owner-token" not in json.dumps(finish_manifest(a.probe))


def test_paired_effectiveness_thresholds():
    from tests.methodology_benchmark import measure

    report = measure()
    assert report["precision"] == 1
    assert report["recall"] == 1
    assert report["valid_request_coverage"] >= 0.9
    assert report["inconclusive_rate"] <= 0.1
    assert report["cleanup_attempts"] == report["cleanup_successes"]
    assert report["cleanup_attempts"] > 0

    names = {case["name"] for case in report["cases"]}
    assert any("nested-ownership" in name for name in names)
    assert any("bulk-approval" in name for name in names)
    assert any("archive-restore" in name for name in names)

    # The aggregate can hide a single missed case, so every paired case is
    # asserted on its own: a vulnerable twin must be found and a secure twin
    # must stay quiet.
    for case in report["cases"]:
        assert case["detected"] == case["expected"], case
        if case["expected"]:
            assert case["outcome"] == "finding", case
        else:
            assert case["outcome"] in {"passed", "blocked"}, case
