"""G1: bounded request generation plus response-contract validation."""
from __future__ import annotations

import json
from types import SimpleNamespace
from typing import Any

import pytest
from fastapi.testclient import TestClient

from app.domain.enums import Confidence
from app.engine.base import HttpProbe, ScanContext, TargetOperation
from app.engine.checks.schema_fuzz import (
    SchemaFuzzCheck,
    _Candidate,
    _case_allocation,
)
from tests import factories
from tests.vulnapp import vulnapp


class ContractClient:
    def __init__(self, responses: dict[str, tuple[int, dict[str, str], bytes]]) -> None:
        self.responses = responses
        self.calls: list[tuple[str, str, dict[str, Any]]] = []

    def request(self, method: str, url: str, **kwargs: Any) -> Any:
        self.calls.append((method, url, kwargs))
        status, headers, content = self.responses[url]
        return SimpleNamespace(
            status_code=status,
            headers=headers,
            content=content,
            text=content.decode("utf-8", "replace"),
        )


def _parameter() -> dict[str, Any]:
    return {
        "name": "q",
        "in": "query",
        "required": True,
        "schema": {"type": "string", "minLength": 2, "maxLength": 4},
    }


def _spec(paths: dict[str, dict[str, Any]]) -> dict[str, Any]:
    return {
        "openapi": "3.0.0",
        "info": {"title": "contract", "version": "1"},
        "paths": paths,
    }


def _operation(path: str, method: str = "GET") -> TargetOperation:
    return TargetOperation(
        id=f"{method.lower()}-{path}", method=method, path=path, params=[_parameter()]
    )


def _response(*, schema: dict[str, Any] | None = None, headers=None) -> dict[str, Any]:
    definition: dict[str, Any] = {"description": "ok"}
    if schema is not None:
        definition["content"] = {"application/json": {"schema": schema}}
    if headers is not None:
        definition["headers"] = headers
    return definition


def test_case_allocation_is_exact_fair_and_uses_both_modes():
    allocation = _case_allocation(3, 8)
    assert allocation == [(2, 1), (1, 2), (1, 1)]
    assert sum(positive + negative for positive, negative in allocation) == 8
    assert max(map(sum, allocation)) - min(map(sum, allocation)) <= 1
    assert _case_allocation(5, 2) == [(1, 0), (0, 1), (0, 0), (0, 0), (0, 0)]


def test_small_allowance_follows_planned_operation_order():
    paths = {
        "/low": {"get": {"parameters": [_parameter()], "responses": {"200": _response()}}},
        "/high": {"get": {"parameters": [_parameter()], "responses": {"200": _response()}}},
    }
    # Planner order is deliberately the reverse of document order.
    operations = [_operation("/high"), _operation("/low")]
    client = ContractClient({"/low": (200, {}, b""), "/high": (200, {}, b"")})
    ctx = factories.scan_context(
        operations,
        credentials=[],
        probe=HttpProbe(client, operations=operations),
        spec=_spec(paths),
        fuzz_cases=1,
    )

    assert SchemaFuzzCheck().run(ctx) == []
    assert [(method, path) for method, path, _ in client.calls] == [("GET", "/high")]


def test_response_contract_rules_find_misses_without_retaining_values(capsys):
    secret = "response-secret-sentinel"
    paths = {
        "/status": {"get": {"parameters": [_parameter()], "responses": {
            "200": _response(),
        }}},
        "/content": {"get": {"parameters": [_parameter()], "responses": {
            "200": _response(schema={}),
        }}},
        "/headers": {"get": {"parameters": [_parameter()], "responses": {
            "200": _response(headers={
                "X-Contract": {"required": True, "schema": {"type": "string"}},
            }),
        }}},
        "/schema": {"get": {"parameters": [_parameter()], "responses": {
            "200": _response(schema={
                "type": "object",
                "required": ["result"],
                "properties": {"result": {"type": "string"}},
                "additionalProperties": False,
            }),
        }}},
    }
    client = ContractClient({
        "/status": (201, {}, b""),
        "/content": (200, {"content-type": "text/plain"}, b"{}"),
        "/headers": (200, {}, b""),
        "/schema": (
            200,
            {"content-type": "application/json"},
            json.dumps({"result": 7, "detail": secret}).encode(),
        ),
    })
    operations = [_operation(path) for path in paths]
    ctx = factories.scan_context(
        operations,
        credentials=[],
        probe=HttpProbe(client, operations=operations),
        spec=_spec(paths),
        fuzz_cases=12,
    )

    findings = SchemaFuzzCheck().run(ctx)

    by_rule = {finding.evidence["rule"]: finding for finding in findings}
    assert {"status", "content_type", "headers", "schema"} <= set(by_rule)
    for rule in ("status", "content_type", "headers", "schema"):
        assert by_rule[rule].confidence == Confidence.heuristic
        assert by_rule[rule].owasp_id is None
    assert by_rule["headers"].evidence["location"] == "response.headers/x-contract"
    assert by_rule["schema"].evidence["location"].startswith("response.body")
    assert secret not in json.dumps([
        {"title": finding.title, "description": finding.description, "evidence": finding.evidence}
        for finding in findings
    ])
    captured = capsys.readouterr()
    assert secret not in captured.out
    assert secret not in captured.err


def test_valid_declared_response_is_not_flagged():
    paths = {
        "/valid": {"get": {"parameters": [_parameter()], "responses": {
            "200": _response(
                schema={
                    "type": "object",
                    "required": ["result"],
                    "properties": {"result": {"type": "string"}},
                    "additionalProperties": False,
                },
                headers={
                    "X-Contract": {"required": True, "schema": {"type": "integer"}},
                },
            ),
        }}},
    }
    operation = _operation("/valid")
    client = ContractClient({
        "/valid": (
            200,
            {"content-type": "application/json", "x-contract": "7"},
            b'{"result":"ok"}',
        )
    })
    ctx = factories.scan_context(
        [operation],
        credentials=[],
        probe=HttpProbe(client, operations=[operation]),
        spec=_spec(paths),
        fuzz_cases=6,
    )

    assert SchemaFuzzCheck().run(ctx) == []
    assert len(client.calls) <= 6


def test_probe_budget_exhaustion_stops_requests_without_failing():
    paths = {
        path: {"get": {"parameters": [_parameter()], "responses": {"200": _response()}}}
        for path in ("/one", "/two", "/three")
    }
    operations = [_operation(path) for path in paths]
    client = ContractClient({path: (200, {}, b"") for path in paths})
    probe = HttpProbe(client, max_requests=2, operations=operations)
    ctx = factories.scan_context(
        operations,
        credentials=[],
        probe=probe,
        spec=_spec(paths),
        fuzz_cases=20,
    )

    assert SchemaFuzzCheck().run(ctx) == []
    assert probe.count == len(client.calls) == 2


def test_mutating_operations_remain_gated():
    paths = {
        "/read": {"get": {"parameters": [_parameter()], "responses": {"200": _response()}}},
        "/write": {"post": {
            "requestBody": {"required": True, "content": {"application/json": {"schema": {
                "type": "object", "properties": {"name": {"type": "string"}},
            }}}},
            "responses": {"200": _response()},
        }},
    }
    operations = [_operation("/read"), _operation("/write", "POST")]
    responses = {"/read": (200, {}, b""), "/write": (200, {}, b"")}

    safe_client = ContractClient(responses)
    safe_ctx = factories.scan_context(
        operations,
        credentials=[],
        probe=HttpProbe(safe_client, operations=operations),
        spec=_spec(paths),
        fuzz_cases=4,
    )
    SchemaFuzzCheck().run(safe_ctx)
    assert {method for method, _, _ in safe_client.calls} == {"GET"}

    mutate_client = ContractClient(responses)
    mutate_ctx = factories.scan_context(
        operations,
        credentials=[],
        probe=HttpProbe(mutate_client, operations=operations),
        spec=_spec(paths),
        fuzz_cases=4,
        allow_mutation=True,
    )
    SchemaFuzzCheck().run(mutate_ctx)
    assert {method for method, _, _ in mutate_client.calls} == {"GET", "POST"}


def test_generation_failure_is_swallowed_without_a_request():
    class BrokenOperation:
        method = "get"
        path = "/broken"

        @staticmethod
        def as_strategy(**_kwargs):
            raise RuntimeError("generator diagnostic with response-secret-sentinel")

    client = ContractClient({})
    ctx = factories.scan_context(
        [], credentials=[], probe=HttpProbe(client), spec={}, fuzz_cases=1
    )
    violations = {}

    SchemaFuzzCheck._generate(
        ctx,
        _Candidate(BrokenOperation(), "GET", None),
        1,
        object(),
        {},
        (),
        object(),
        (AssertionError,),
        violations,
        None,
        None,
        None,
    )

    assert violations == {}
    assert client.calls == []


def test_schema_fuzz_flags_5xx_on_boundary_input():
    from app.engine.checks.schema_fuzz import SchemaFuzzCheck

    param = {"name": "divisor", "in": "query", "required": True,
             "schema": {"type": "integer"}}
    spec = {
        "openapi": "3.0.0",
        "info": {"title": "t", "version": "1"},
        "paths": {"/compute": {"get": {
            "parameters": [param],
            "responses": {"200": {"description": "ok"}},
        }}},
    }
    op = TargetOperation(id="op-compute", method="GET", path="/compute", params=[param])
    ctx = factories.scan_context(
        [op],
        credentials=[],
        probe=HttpProbe(TestClient(vulnapp, raise_server_exceptions=False)),
        spec=spec,
        fuzz_cases=40,
    )
    findings = SchemaFuzzCheck().run(ctx)
    assert findings, "expected a 5xx server-error finding from a generated boundary input"
    f = findings[0]
    assert f.check == "schema_fuzz" and f.owasp_id == "API8:2023"
    assert f.confidence == Confidence.verified
    assert f.evidence["status"] >= 500
    assert "response_sample" not in f.evidence
    assert "params" not in f.evidence
    assert f.operation_id == "op-compute"


def test_schema_fuzz_noop_without_spec_or_cases():
    from app.engine.checks.schema_fuzz import SchemaFuzzCheck

    op = TargetOperation(id="x", method="GET", path="/compute", params=[])
    base = dict(base_url="http://testserver", operations=[op], credentials=[])
    probe = HttpProbe(TestClient(vulnapp))
    # No spec → no-op.
    assert SchemaFuzzCheck().run(ScanContext(**base, probe=probe, fuzz_cases=10)) == []
    # Spec present but fuzz_cases=0 (default, opt-in off) → no-op.
    assert SchemaFuzzCheck().run(
        ScanContext(**base, probe=probe, spec={"openapi": "3.0.0"}, fuzz_cases=0)
    ) == []


# ---- Server path prefixes ---------------------------------------------------
#
# Schemathesis yields the bare ``paths`` key; the parser stores the route with
# the spec's server/basePath joined on. A prod scan whose spec declared
# ``servers: [{url: https://host/api/v1}]`` sent every generated case to the bare
# key, hit the frontend's HTML 404 and reported pure contract-drift noise.

_FRONTEND_404 = (404, {"content-type": "text/html"}, b"<html>not found</html>")


class PrefixedClient(ContractClient):
    """Answers only under ``/api/v1``; anything else is the frontend's HTML 404."""

    def request(self, method: str, url: str, **kwargs: Any) -> Any:
        if url not in self.responses:
            self.calls.append((method, url, kwargs))
            status, headers, content = _FRONTEND_404
            return SimpleNamespace(
                status_code=status, headers=headers, content=content, text=content.decode()
            )
        return super().request(method, url, **kwargs)


def _items_operation() -> dict[str, Any]:
    return {"get": {"parameters": [_parameter()], "responses": {
        "200": _response(schema={"type": "object"}),
    }}}


def _prefixed_specs() -> dict[str, dict[str, Any]]:
    return {
        "oas3 absolute server url": {
            **_spec({"/items": _items_operation()}),
            "servers": [{"url": "https://api.example.test/api/v1"}],
        },
        "oas3 server variable": {
            **_spec({"/items": _items_operation()}),
            "servers": [{
                "url": "https://api.example.test/{base}",
                "variables": {"base": {"default": "api/v1"}},
            }],
        },
        "oas3 operation-level servers": {
            **_spec({"/items": {"get": {
                **_items_operation()["get"],
                "servers": [{"url": "/api/v1"}],
            }}}),
            "servers": [{"url": "/elsewhere"}],
        },
        "oas3 path-item servers": _spec({"/items": {
            **_items_operation(), "servers": [{"url": "/api/v1"}],
        }}),
        "swagger2 basePath": {
            "swagger": "2.0",
            "info": {"title": "contract", "version": "1"},
            "basePath": "/api/v1/",
            "produces": ["application/json"],
            "paths": {"/items": {"get": {
                "parameters": [{"name": "q", "in": "query", "required": True,
                                "type": "string", "minLength": 2, "maxLength": 4}],
                "responses": {"200": {"description": "ok", "schema": {"type": "object"}}},
            }}},
        },
    }


def _parsed_operations(spec: dict[str, Any], base_url: str) -> list[TargetOperation]:
    from app.specs.parser import parse_operations

    return [
        TargetOperation(
            id=f"op-{index}", method=parsed.method, path=parsed.path, params=parsed.params
        )
        for index, parsed in enumerate(parse_operations(spec, target_base_url=base_url))
    ]


@pytest.mark.parametrize("name", sorted(_prefixed_specs()))
def test_prefixed_spec_fuzzes_the_runtime_route(name):
    spec = _prefixed_specs()[name]
    operations = _parsed_operations(spec, factories.BASE_URL)
    assert [op.path for op in operations] == ["/api/v1/items"]
    client = PrefixedClient({
        "/api/v1/items": (200, {"content-type": "application/json"}, b"{}"),
    })
    probe = HttpProbe(client, operations=operations)
    ctx = factories.scan_context(
        operations, credentials=[], probe=probe, spec=spec, fuzz_cases=6
    )

    assert factories.run_check(SchemaFuzzCheck(), ctx) == []
    assert client.calls
    assert {url for _, url, _ in client.calls} == {"/api/v1/items"}
    # Attributed to the parsed operation, so coverage and the trace see it.
    assert probe.coverage.get("op-0", {}).get("schema_fuzz", 0) == len(client.calls)


def test_prefixed_finding_reports_the_runtime_route_and_operation():
    spec = {**_spec({"/items": _items_operation()}), "servers": [{"url": "/api/v1"}]}
    operations = _parsed_operations(spec, factories.BASE_URL)
    # A real drift under the prefix: a status the contract never declared.
    client = PrefixedClient({"/api/v1/items": (201, {}, b"")})
    ctx = factories.scan_context(
        operations,
        credentials=[],
        probe=HttpProbe(client, operations=operations),
        spec=spec,
        fuzz_cases=4,
    )

    findings = factories.run_check(SchemaFuzzCheck(), ctx)

    status = next(f for f in findings if f.evidence["rule"] == "status")
    assert status.evidence["route"] == "/api/v1/items"
    assert status.title.endswith("GET /api/v1/items")
    assert status.operation_id == "op-0"
    assert {url for _, url, _ in client.calls} == {"/api/v1/items"}


def test_target_base_url_that_already_carries_the_prefix_is_not_doubled():
    spec = {**_spec({"/items": _items_operation()}), "servers": [{"url": "/api/v1"}]}
    base_url = "http://testserver/api/v1"
    operations = _parsed_operations(spec, base_url)
    assert [op.path for op in operations] == ["/items"]
    client = PrefixedClient({"/items": (200, {"content-type": "application/json"}, b"{}")})
    probe = HttpProbe(client, operations=operations)
    ctx = factories.scan_context(
        operations, credentials=[], probe=probe, spec=spec, fuzz_cases=4
    )
    ctx.base_url = base_url

    assert factories.run_check(SchemaFuzzCheck(), ctx) == []
    assert {url for _, url, _ in client.calls} == {"/items"}
    assert probe.coverage.get("op-0", {}).get("schema_fuzz", 0) == len(client.calls)


def test_mounted_vulnapp_server_error_is_found_under_the_prefix():
    from starlette.applications import Starlette
    from starlette.responses import HTMLResponse
    from starlette.routing import Mount, Route

    async def frontend_404(_request):
        return HTMLResponse("<html>not found</html>", status_code=404)

    app = Starlette(routes=[
        Mount("/api/v1", app=vulnapp),
        Route("/{rest:path}", frontend_404),
    ])
    param = {"name": "divisor", "in": "query", "required": True,
             "schema": {"type": "integer"}}
    spec = {
        "openapi": "3.0.0",
        "info": {"title": "t", "version": "1"},
        "servers": [{"url": "https://api.example.test/api/v1"}],
        "paths": {"/compute": {"get": {
            "parameters": [param],
            "responses": {"200": {"description": "ok"}},
        }}},
    }
    operations = _parsed_operations(spec, factories.BASE_URL)
    ctx = factories.scan_context(
        operations,
        credentials=[],
        probe=HttpProbe(TestClient(app, raise_server_exceptions=False), operations=operations),
        spec=spec,
        fuzz_cases=40,
    )

    findings = factories.run_check(SchemaFuzzCheck(), ctx)

    server_error = next(f for f in findings if f.evidence["rule"] == "server_error")
    assert server_error.evidence["route"] == "/api/v1/compute"
    assert server_error.operation_id == "op-0"
    # Nothing reached the frontend: no HTML-404 drift on a route that exists.
    assert not [f for f in findings if f.evidence.get("status") == 404]


def test_path_parameters_are_filled_under_the_prefix():
    spec = {
        **_spec({"/items/{item_id}": {"get": {
            "parameters": [{"name": "item_id", "in": "path", "required": True,
                            "schema": {"type": "integer"}}],
            "responses": {"200": _response(schema={"type": "object"})},
        }}}),
        "servers": [{"url": "/api/v1"}],
    }
    operations = _parsed_operations(spec, factories.BASE_URL)
    assert [op.path for op in operations] == ["/api/v1/items/{item_id}"]

    class ItemsClient(PrefixedClient):
        def request(self, method: str, url: str, **kwargs: Any) -> Any:
            if url.startswith("/api/v1/items/"):
                self.responses.setdefault(
                    url, (200, {"content-type": "application/json"}, b"{}")
                )
            return super().request(method, url, **kwargs)

    client = ItemsClient({})
    probe = HttpProbe(client, operations=operations)
    ctx = factories.scan_context(
        operations, credentials=[], probe=probe, spec=spec, fuzz_cases=6
    )

    factories.run_check(SchemaFuzzCheck(), ctx)

    assert client.calls
    assert all(url.startswith("/api/v1/items/") for _, url, _ in client.calls)
    assert probe.coverage.get("op-0", {}).get("schema_fuzz", 0) == len(client.calls)


def test_a_partly_overlapping_target_base_path_is_cut_like_the_parser():
    # Target ``/api`` + server ``/api/v2`` → the parser stores ``/v2/items``.
    spec = {**_spec({"/items": _items_operation()}), "servers": [{"url": "/api/v2"}]}
    base_url = "http://testserver/api"
    operations = _parsed_operations(spec, base_url)
    assert [op.path for op in operations] == ["/v2/items"]
    client = PrefixedClient({"/v2/items": (200, {"content-type": "application/json"}, b"{}")})
    probe = HttpProbe(client, operations=operations)
    ctx = factories.scan_context(
        operations, credentials=[], probe=probe, spec=spec, fuzz_cases=4
    )
    ctx.base_url = base_url

    assert factories.run_check(SchemaFuzzCheck(), ctx) == []
    assert {url for _, url, _ in client.calls} == {"/v2/items"}
