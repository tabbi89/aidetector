"""Race condition / limit overrun (API6): the one check that fires a burst.

The oracle needs real concurrency, so most of the check is verified against a
live async transport bound to the in-process app: `/orders` has a genuine
check-then-act TOCTOU that interleaves deterministically under `gather`. The
pure decision functions and the safety gates are tested directly.
"""
from __future__ import annotations

import httpx
import pytest

from app.domain.enums import Confidence, Severity
from app.engine.base import HttpProbe, ProbeResult, ScanContext, TargetOperation
from app.engine.checks.race_condition import (
    RaceConditionCheck,
    _rejects_duplicate,
    _unique_field,
    is_overrun,
)
from app.engine.transport import AsyncHttpClientBridge
from tests import factories
from tests.vulnapp import vulnapp

ORDERS_POST = TargetOperation(
    id="op-orders-post",
    method="POST",
    path="/orders",
    params=[{"name": "ref", "in": "body", "required": True, "schema": {"type": "string"}}],
)
ORDERS_GET = TargetOperation(
    id="op-orders-get", method="GET", path="/orders/{order_id}",
    params=[{"name": "order_id", "in": "path", "required": True}],
)
ORDERS_DELETE = TargetOperation(
    id="op-orders-del", method="DELETE", path="/orders/{order_id}",
    params=[{"name": "order_id", "in": "path", "required": True}],
)
OPS = [ORDERS_POST, ORDERS_GET, ORDERS_DELETE]


def _r(status: int) -> ProbeResult:
    return ProbeResult(status=status, headers={}, text="", elapsed_ms=0.0)


# ---- the pure decisions --------------------------------------------------------

def test_overrun_is_more_than_one_success():
    assert is_overrun([_r(201), _r(201), _r(409)])
    assert not is_overrun([_r(201), _r(409), _r(409)])
    assert not is_overrun([_r(409), _r(409)])


def test_rejects_duplicate_reads_status_and_body():
    assert _rejects_duplicate(_r(409))
    assert _rejects_duplicate(ProbeResult(200, {}, "email already exists", 0.0))
    assert not _rejects_duplicate(_r(201))
    assert not _rejects_duplicate(None)


def test_rejects_duplicate_ignores_non_conflict_errors():
    """A 400/401/404/500 is not a uniqueness signal — only conflict-class is."""
    assert not _rejects_duplicate(_r(400))
    assert not _rejects_duplicate(_r(401))
    assert not _rejects_duplicate(_r(404))
    assert not _rejects_duplicate(_r(500))


def test_unique_field_prefers_a_uniqueness_hinting_name():
    op = TargetOperation(
        id="x", method="POST", path="/o",
        params=[
            {"name": "colour", "in": "body", "schema": {"type": "string"}},
            {"name": "email", "in": "body", "schema": {"type": "string"}},
        ],
    )
    assert _unique_field(op) == "email"


def test_unique_field_falls_back_to_the_first_string_field():
    op = TargetOperation(
        id="x", method="POST", path="/o",
        params=[{"name": "colour", "in": "body", "schema": {"type": "string"}}],
    )
    assert _unique_field(op) == "colour"


# ---- safety gates (no burst needed) --------------------------------------------

def test_it_is_opt_in():
    ctx = factories.scan_context(OPS, allow_mutation=False)
    assert RaceConditionCheck().run(ctx) == []
    assert ctx.probe.count == 0


def test_it_noops_when_the_transport_cannot_burst():
    """The sync TestClient path: a serialized burst could never catch a race,
    so the check declines to run rather than pretend."""
    ctx = factories.scan_context(OPS, allow_mutation=True)
    assert not ctx.probe.can_burst()
    assert RaceConditionCheck().run(ctx) == []


# ---- end to end against the live async transport -------------------------------

@pytest.fixture
def bridge():
    b = AsyncHttpClientBridge(
        base_url=factories.BASE_URL,
        transport=httpx.ASGITransport(app=vulnapp),
        requests_per_second=1000.0,
    )
    try:
        yield b
    finally:
        b.close()


def _ctx(bridge, ops=OPS, mutation=True) -> ScanContext:
    probe = HttpProbe(bridge, operations=ops, credentials=factories.two_identities())
    return ScanContext(
        base_url=factories.BASE_URL, operations=ops,
        credentials=factories.two_identities(), probe=probe, allow_mutation=mutation,
    )


def test_a_real_toctou_is_caught_as_verified(bridge):
    findings = factories.run_check(RaceConditionCheck(), _ctx(bridge))
    assert findings, "the /orders check-then-act race should be caught"
    f = findings[0]
    assert f.check == "race_condition"
    assert f.owasp_id == "API6:2023"
    assert f.confidence is Confidence.verified
    assert f.severity is Severity.high
    assert f.evidence["field"] == "ref"
    assert f.evidence["requests_succeeded"] > 1


def test_the_burst_bypasses_the_rate_limiter(bridge):
    """A rate-limited burst would serialize and the race would never fire —
    catching it at all proves the burst went out concurrently."""
    findings = factories.run_check(RaceConditionCheck(), _ctx(bridge))
    assert findings and findings[0].evidence["requests_succeeded"] >= 2


def test_created_objects_are_cleaned_up(bridge):
    from tests.vulnapp import _ORDERS

    factories.run_check(RaceConditionCheck(), _ctx(bridge))
    # Every order the probe created has a DELETE pair, so none should remain.
    assert _ORDERS == {}


def test_an_endpoint_with_no_uniqueness_constraint_is_not_flagged(bridge):
    """No sequential-duplicate rejection → no limit to overrun → no finding."""
    widget_post = TargetOperation(
        id="op-w-post", method="POST", path="/widgets",
        params=[{"name": "name", "in": "body", "required": True, "schema": {"type": "string"}}],
    )
    widget_get = TargetOperation(
        id="op-w-get", method="GET", path="/widgets/{widget_id}",
        params=[{"name": "widget_id", "in": "path", "required": True}],
    )
    findings = factories.run_check(
        RaceConditionCheck(), _ctx(bridge, ops=[widget_post, widget_get])
    )
    assert findings == []
