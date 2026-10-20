"""GraphQL introspection (premium): is the schema exposed to any caller?"""
from __future__ import annotations

from fastapi import FastAPI, Header
from fastapi.responses import JSONResponse
from fastapi.testclient import TestClient

from app.engine.base import TargetOperation
from app.engine.checks.graphql_introspection import GraphQLIntrospectionCheck
from tests import factories

GRAPHQL_OP = TargetOperation(id="op-gql", method="POST", path="/graphql", params=[])


def test_premium_check_noops_without_premium():
    assert factories.run_one(GraphQLIntrospectionCheck(), [GRAPHQL_OP]) == []


def test_introspection_is_flagged():
    findings = factories.run_one(GraphQLIntrospectionCheck(), [GRAPHQL_OP], premium=True)
    assert findings
    f = findings[0]
    assert f.check == "graphql_introspection"
    assert f.evidence["route"] == "/graphql"
    assert f.confidence.value == "verified"


def test_authenticated_only_introspection_is_not_public_exposure():
    app = FastAPI()

    @app.post("/graphql")
    def graphql(authorization: str | None = Header(default=None)):
        if authorization != "admin-token":
            return JSONResponse({"detail": "unauthorized"}, status_code=401)
        return {"data": {"__schema": {"types": []}}}

    ctx = factories.scan_context(
        [GRAPHQL_OP],
        credentials=[factories.credential("admin", "admin", "admin-token")],
        client=TestClient(app),
        premium=True,
    )

    assert GraphQLIntrospectionCheck().run(ctx) == []
