"""Spec design review (A06, premium): design-level risks visible in the spec.

The check reads the operations/schemas (no target traffic) and flags six static
design signals: a sensitive operation with no declared auth, a secret in a
query/path parameter, a server-owned field in a request body, missing error and
rate-limit contracts, and unbounded collection responses. Premium: no-op (no
findings) unless ``premium: true``.
"""
from __future__ import annotations

from app.engine.base import TargetOperation
from app.engine.checks.design_review import (
    DesignReviewCheck,
    secret_param,
    sensitive,
    server_owned_field,
)
from tests import factories


def _op(method="GET", path="/x", params=None, auth_scope=None) -> TargetOperation:
    return TargetOperation(
        id="op", method=method, path=path, params=params or [], auth_scope=auth_scope
    )


def _spec(
    operation: dict,
    *,
    path: str = "/x",
    method: str = "get",
    security=None,
    components: dict | None = None,
) -> dict:
    document = {
        "openapi": "3.0.0",
        "info": {"title": "test", "version": "1"},
        "paths": {path: {method: operation}},
    }
    if security is not None:
        document["security"] = security
    if components is not None:
        document["components"] = components
    return document


def _signals(findings):
    return {finding.evidence.get("signal") for finding in findings}


# ---- the pure predicates ------------------------------------------------------

def test_secret_param_only_flags_url_params():
    assert secret_param({"name": "api_key", "in": "query"})
    assert secret_param({"name": "access_token", "in": "path"})
    assert not secret_param({"name": "api_key", "in": "header"})
    assert not secret_param({"name": "api_key", "in": "body"})
    assert not secret_param({"name": "username", "in": "query"})


def test_server_owned_field_matches_privilege_names():
    assert server_owned_field("role")
    assert server_owned_field("is_admin")
    assert server_owned_field("owner_id")
    assert not server_owned_field("name")


def test_sensitive_uses_privilege_and_path():
    assert sensitive(_op(path="/admin/users", auth_scope=None))
    assert sensitive(_op(path="/reset-password"))
    assert not sensitive(_op(path="/health"))


# ---- the check ----------------------------------------------------------------

def test_premium_check_noops_without_premium():
    op = _op(path="/admin/users", auth_scope=None)
    assert factories.run_one(DesignReviewCheck(), [op]) == []


def test_no_auth_on_sensitive_is_flagged():
    op = _op(path="/admin/users", auth_scope=None)
    findings = factories.run_one(DesignReviewCheck(), [op], premium=True)
    assert [f.evidence["signal"] for f in findings] == ["no_auth"]


def test_an_authed_sensitive_operation_is_clean():
    op = _op(path="/admin/users", auth_scope="adminAuth")
    assert factories.run_one(DesignReviewCheck(), [op], premium=True) == []


def test_secret_in_url_is_flagged():
    op = _op(path="/search", params=[{"name": "api_key", "in": "query"}])
    findings = factories.run_one(DesignReviewCheck(), [op], premium=True)
    assert any(f.evidence.get("signal") == "secret_in_url" for f in findings)


def test_server_owned_body_field_is_flagged():
    op = _op(method="POST", path="/users", params=[{"name": "role", "in": "body"}])
    findings = factories.run_one(DesignReviewCheck(), [op], premium=True)
    assert any(f.evidence.get("signal") == "server_owned_field" for f in findings)


def test_missing_error_and_rate_limit_contracts_are_distinct_leads():
    from app.engine.fingerprint import fingerprint

    op = _op()
    spec = _spec({"responses": {"200": {"description": "ok"}}})

    findings = factories.run_one(DesignReviewCheck(), [op], premium=True, spec=spec)

    assert _signals(findings) == {
        "missing_error_contract",
        "missing_rate_limit_contract",
    }
    assert len({finding.evidence["issue"] for finding in findings}) == 2
    assert all(finding.severity.value == "low" for finding in findings)
    assert len(
        {
            fingerprint(f.check, f.owasp_id, f.title, f.evidence)
            for f in findings
        }
    ) == 2


def test_error_and_rate_limit_contracts_accept_refs_and_headers():
    op = _op()
    spec = _spec(
        {
            "responses": {
                "200": {
                    "description": "ok",
                    "headers": {
                        "RateLimit-Remaining": {"schema": {"type": "integer"}}
                    },
                },
                "400": {"$ref": "#/components/responses/Error"},
            }
        },
        components={"responses": {"Error": {"description": "bad request"}}},
    )

    findings = factories.run_one(DesignReviewCheck(), [op], premium=True, spec=spec)

    assert "missing_error_contract" not in _signals(findings)
    assert "missing_rate_limit_contract" not in _signals(findings)


def test_explicit_429_documents_both_error_and_rate_limit_behavior():
    op = _op()
    spec = _spec({"responses": {"200": {}, "429": {"description": "slow down"}}})

    findings = factories.run_one(DesignReviewCheck(), [op], premium=True, spec=spec)

    assert "missing_error_contract" not in _signals(findings)
    assert "missing_rate_limit_contract" not in _signals(findings)


def test_unbounded_collection_behind_refs_is_flagged():
    op = _op(path="/widgets")
    spec = _spec(
        {
            "responses": {
                "200": {
                    "content": {
                        "application/json": {
                            "schema": {"$ref": "#/components/schemas/WidgetPage"}
                        }
                    }
                },
                "default": {"description": "error"},
                "429": {"description": "slow down"},
            }
        },
        path="/widgets",
        components={
            "schemas": {
                "WidgetPage": {
                    "type": "object",
                    "properties": {
                        "items": {
                            "type": "array",
                            "items": {"$ref": "#/components/schemas/Widget"},
                        }
                    },
                },
                "Widget": {
                    "type": "object",
                    "properties": {"id": {"type": "string"}},
                },
            }
        },
    )

    findings = factories.run_one(DesignReviewCheck(), [op], premium=True, spec=spec)

    unbounded = [
        finding
        for finding in findings
        if finding.evidence.get("signal") == "unbounded_collection"
    ]
    assert len(unbounded) == 1
    assert unbounded[0].evidence["location"] == "response.items"


def test_bounded_collection_is_clean():
    op = _op(path="/widgets")
    spec = _spec(
        {
            "responses": {
                "200": {
                    "content": {
                        "application/json": {
                            "schema": {
                                "type": "array",
                                "maxItems": 100,
                                "items": {"type": "object"},
                            }
                        }
                    }
                },
                "429": {"description": "slow down"},
            }
        },
        path="/widgets",
    )

    findings = factories.run_one(DesignReviewCheck(), [op], premium=True, spec=spec)

    assert "unbounded_collection" not in _signals(findings)


def test_security_inheritance_and_anonymous_overrides_are_respected():
    operation = {"responses": {"200": {}, "429": {}}}
    inherited = _spec(operation, path="/admin/users", security=[{"bearer": []}])
    op = _op(path="/admin/users", auth_scope="bearer")
    assert "no_auth" not in _signals(
        factories.run_one(DesignReviewCheck(), [op], premium=True, spec=inherited)
    )

    for override in ([], [{}, {"bearer": []}]):
        anonymous = _spec(
            {**operation, "security": override},
            path="/admin/users",
            security=[{"bearer": []}],
        )
        assert "no_auth" in _signals(
            factories.run_one(DesignReviewCheck(), [op], premium=True, spec=anonymous)
        )


def test_intentionally_public_non_sensitive_operation_is_not_an_auth_finding():
    op = _op(path="/health")
    spec = _spec(
        {"security": [], "responses": {"200": {}, "429": {}}}, path="/health"
    )
    findings = factories.run_one(DesignReviewCheck(), [op], premium=True, spec=spec)
    assert "no_auth" not in _signals(findings)


def test_contract_review_adds_no_target_requests():
    op = _op(path="/widgets")
    spec = _spec({"responses": {"200": {}}}, path="/widgets")
    ctx = factories.scan_context([op], premium=True, spec=spec)
    before = ctx.probe.count

    DesignReviewCheck().run(ctx)

    assert ctx.probe.count == before
