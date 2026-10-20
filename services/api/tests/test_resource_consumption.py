"""Unbounded resource consumption (API4): a client-controlled page size.

Fires against ``vulnapp``'s ``/catalog``, which honours ``limit`` with no cap,
and stays quiet against the capped ``safeapp`` twin. The check is spec-driven,
so a collection with no declared size parameter is skipped, not guessed at.
"""
from __future__ import annotations

from fastapi.testclient import TestClient

from app.engine.checks.resource_consumption import ResourceConsumptionCheck
from tests import factories, safeapp

CATALOG = factories.operation(
    "GET",
    "/catalog",
    id="op-catalog",
    params=[{"name": "limit", "in": "query", "required": False,
             "schema": {"type": "integer"}}],
)
#: A collection with no declared size parameter — the check must not probe it.
NO_SIZE = factories.operation("GET", "/accounts", id="op-accounts", params=[])
#: An item read, not a collection — never a candidate.
ITEM = factories.operation("GET", "/catalog/{item_id}", id="op-item")


def test_unbounded_page_size_is_flagged():
    findings = factories.run_one(ResourceConsumptionCheck(), [CATALOG])
    assert findings, "vulnapp /catalog honours an unbounded limit"
    f = findings[0]
    assert f.check == "resource_consumption"
    assert f.owasp_id == "API4:2023"
    assert f.evidence["param"] == "limit"
    assert f.evidence["path"] == "/catalog"
    # The count tracked the requested size: large probe returned far more.
    assert f.evidence["large_count"] > f.evidence["small_count"]
    # Confidence is a lead, not proof.
    assert f.confidence.value == "heuristic"


def test_no_value_is_ever_recorded():
    """Evidence carries counts and sizes — never a returned record."""
    f = factories.run_one(ResourceConsumptionCheck(), [CATALOG])[0]
    blob = str(f.evidence)
    assert "item-" not in blob  # the generated record names never leak


def test_capped_endpoint_stays_quiet():
    """A server-side cap returns the same count for both probes → no finding."""
    safeapp.reset_state()
    findings = factories.run_one(
        ResourceConsumptionCheck(),
        [CATALOG],
        client=TestClient(safeapp.safeapp),
    )
    assert findings == []


def test_collection_without_a_size_param_is_inapplicable():
    """No declared page-size parameter anywhere → the check explains the skip."""
    check = ResourceConsumptionCheck()
    ctx = factories.scan_context([NO_SIZE, ITEM])
    assert check.inapplicable(ctx) is not None
    assert check.run(ctx) == []


def test_applicable_when_any_collection_declares_a_size_param():
    check = ResourceConsumptionCheck()
    ctx = factories.scan_context([NO_SIZE, CATALOG])
    assert check.inapplicable(ctx) is None
