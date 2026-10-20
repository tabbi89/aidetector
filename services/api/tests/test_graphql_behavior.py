"""G6: bounded GraphQL suggestions and controlled alias/batch authorization."""
from __future__ import annotations

from typing import Any

from fastapi import Body, FastAPI, Header
from fastapi.responses import JSONResponse
from fastapi.testclient import TestClient

from app.domain.enums import AuthType
from app.engine.base import ResolvedCredential
from app.engine.checks.graphql_behavior import (
    MAX_BATCH_SIZE,
    MAX_QUERY_BYTES,
    GraphQLBehaviorCheck,
)
from tests import factories

GRAPHQL_OP = factories.operation("POST", "/graphql", id="gql-op")
QUERY = "{ account { id secretMarker } }"
SENTINEL = "response-secret-never-persisted"


def _credential(name: str, role: str, token: str) -> ResolvedCredential:
    return ResolvedCredential(name, role, AuthType.bearer, None, token)


def _spec(query: str = QUERY) -> dict:
    return {
        "openapi": "3.0.0",
        "info": {"title": "gql", "version": "1"},
        "paths": {
            "/graphql": {
                "post": {
                    "requestBody": {
                        "content": {"application/json": {"example": {"query": query}}}
                    },
                    "responses": {"200": {"description": "GraphQL response"}},
                }
            }
        },
    }


def _app(mode: str, seen: list[Any]) -> FastAPI:
    app = FastAPI()

    @app.post("/graphql")
    def graphql(
        payload: Any = Body(default={}),
        authorization: str | None = Header(default=None),
    ):
        seen.append(payload)
        identity = (authorization or "").removeprefix("Bearer ")
        if isinstance(payload, list):
            if mode == "batch_bypass" and identity == "attacker":
                return [{"data": {"account": {"id": "1", "secretMarker": SENTINEL}}}]
            return [{"data": None, "errors": [{"message": "forbidden"}]}]
        query = str(payload.get("query", "")) if isinstance(payload, dict) else ""
        if "usre" in query:
            if mode == "no_suggestions":
                return {"errors": [{"message": "invalid query"}]}
            return {
                "errors": [
                    {"message": 'Cannot query field "usre". Did you mean "user"?'}
                ]
            }
        if "aidxAlias:" in query:
            if mode == "alias_bypass" and identity == "attacker":
                return {
                    "data": {
                        "aidxAlias": {"id": "1", "secretMarker": SENTINEL}
                    }
                }
            return {"data": None, "errors": [{"message": "forbidden"}]}
        if identity == "owner" or mode == "public":
            return {"data": {"account": {"id": "1", "secretMarker": SENTINEL}}}
        if identity in ("", "attacker"):
            return {"data": None, "errors": [{"message": "forbidden"}]}
        return JSONResponse({"detail": "unauthorized"}, status_code=401)

    return app


def _run(mode: str, *, query: str = QUERY, allow_mutation: bool = False):
    seen: list[Any] = []
    credentials = [
        _credential("owner", "admin", "owner"),
        _credential("attacker", "user", "attacker"),
    ]
    ctx = factories.scan_context(
        [GRAPHQL_OP],
        credentials=credentials,
        client=TestClient(_app(mode, seen)),
        premium=True,
        allow_mutation=allow_mutation,
        spec=_spec(query),
    )
    return GraphQLBehaviorCheck().run(ctx), ctx, seen


def test_premium_check_noops_without_premium():
    assert factories.run_one(GraphQLBehaviorCheck(), [GRAPHQL_OP]) == []


def test_anonymous_field_suggestion_is_a_heuristic_lead():
    findings, _, _ = _run("no_bypass")
    finding = next(f for f in findings if f.evidence["issue"] == "field_suggestion")
    assert finding.confidence.value == "heuristic"
    assert finding.severity.value == "low"
    assert finding.evidence["suggested_fields"] == ["user"]


def test_generic_graphql_errors_are_not_field_suggestions():
    findings, _, _ = _run("no_suggestions")
    assert not [f for f in findings if f.evidence["issue"] == "field_suggestion"]


def test_alias_bypass_requires_owner_and_denied_normal_controls():
    findings, _, _ = _run("alias_bypass")
    alias = next(f for f in findings if f.evidence["issue"] == "alias_auth_bypass")
    assert alias.confidence.value == "verified"
    assert alias.evidence["owner_control"] == "success"
    assert alias.evidence["anonymous_control"] == "denied"
    assert alias.evidence["attacker_control"] == "denied"
    assert SENTINEL not in str(alias.evidence)


def test_batch_bypass_requires_equivalent_denied_normal_query():
    findings, _, _ = _run("batch_bypass")
    batch = next(f for f in findings if f.evidence["issue"] == "batch_auth_bypass")
    assert batch.confidence.value == "verified"
    assert batch.evidence["attacker_control"] == "denied"
    assert SENTINEL not in batch.description


def test_alias_and_batch_support_without_differential_access_are_clean():
    findings, _, _ = _run("public")
    assert not [f for f in findings if "auth_bypass" in str(f.evidence.get("issue"))]


def test_requests_queries_aliases_and_batches_are_bounded():
    _, ctx, seen = _run("alias_bypass")
    assert ctx.probe.count <= 8
    for payload in seen:
        if isinstance(payload, list):
            assert len(payload) <= MAX_BATCH_SIZE
            queries = [item["query"] for item in payload]
        else:
            queries = [payload["query"]]
        assert all(len(query.encode()) <= MAX_QUERY_BYTES for query in queries)
        assert all(query.count("aidxAlias:") <= 1 for query in queries)


def test_mutation_examples_are_never_replayed_even_with_mutation_opt_in():
    findings, _, seen = _run(
        "no_bypass",
        query="mutation { updateAccount { id } }",
        allow_mutation=True,
    )
    assert not [f for f in findings if "auth_bypass" in str(f.evidence.get("issue"))]
    assert all("mutation" not in str(payload).lower() for payload in seen)
