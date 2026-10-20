"""Sensitive business flows without anti-automation (API6).

Fires against ``vulnapp``'s ``/checkout`` (every identical replay mints a new
order) and stays quiet against the idempotent ``safeapp`` twin. Off unless
``mutate: true``, and unconcerned with authentication endpoints — those are
``enumeration``'s.
"""
from __future__ import annotations

from fastapi.testclient import TestClient

from app.engine.checks.business_flow import BusinessFlowCheck
from tests import factories, safeapp

CHECKOUT = factories.operation(
    "POST",
    "/checkout",
    id="op-checkout",
    params=[{"name": "item", "in": "body", "required": True,
             "schema": {"type": "string"}}],
)
#: An authentication endpoint — excluded, it belongs to enumeration.
LOGIN = factories.operation(
    "POST", "/login", id="op-login",
    params=[{"name": "u", "in": "body", "required": True, "schema": {"type": "string"}}],
)


def test_noops_without_mutation():
    check = BusinessFlowCheck()
    ctx = factories.scan_context([CHECKOUT])
    assert check.run(ctx) == []
    assert check.inapplicable(ctx) is not None  # explains the skip


def test_unprotected_flow_is_flagged():
    findings = factories.run_one(BusinessFlowCheck(), [CHECKOUT], allow_mutation=True)
    assert findings, "vulnapp /checkout mints a new order per identical replay"
    f = findings[0]
    assert f.check == "business_flow"
    assert f.owasp_id == "API6:2023"
    assert f.evidence["path"] == "/checkout"
    assert f.evidence["distinct_objects"] == f.evidence["requests"]
    assert f.confidence.value == "heuristic"


def test_authentication_endpoint_is_excluded():
    """A /login-shaped flow is enumeration's territory, not this check's."""
    check = BusinessFlowCheck()
    ctx = factories.scan_context([LOGIN], allow_mutation=True)
    assert check.inapplicable(ctx) is not None
    assert check.run(ctx) == []


def test_idempotent_flow_stays_quiet():
    """The safe twin demands an idempotency key, so a replay is de-duplicated."""
    safeapp.reset_state()
    findings = factories.run_one(
        BusinessFlowCheck(),
        [CHECKOUT],
        allow_mutation=True,
        client=TestClient(safeapp.safeapp),
    )
    assert findings == []
