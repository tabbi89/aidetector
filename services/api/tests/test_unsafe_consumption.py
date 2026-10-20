"""Unsafe consumption of an upstream API (API10) — premium, OOB-confirmed.

Fires against ``vulnapp``'s ``/aggregate`` (fetches an upstream AND relays its
content back) and must NOT fire against ``/fetch`` (fetches but relays nothing —
that is blind SSRF, ``oob_injection``'s finding). No-op without premium or a
collector.
"""
from __future__ import annotations

from app.engine.base import TargetOperation
from app.engine.checks.unsafe_consumption import UnsafeConsumptionCheck
from tests import factories
from tests.fakes import CollectorOob

CREDS = factories.two_identities()

AGGREGATE = TargetOperation(
    id="op-aggregate", method="GET", path="/aggregate",
    params=[{"name": "source", "in": "query", "required": False}],
)
#: Fetches the URL but relays nothing back — a callback with no reflection.
FETCH = TargetOperation(
    id="op-fetch", method="GET", path="/fetch",
    params=[{"name": "url", "in": "query", "required": False}],
)


def _ctx(ops, **kw):
    from tests.vulnapp import OUTBOUND

    return factories.scan_context(
        ops, credentials=CREDS, oob=CollectorOob(OUTBOUND), premium=True, **kw
    )


def test_relayed_upstream_is_confirmed():
    findings = UnsafeConsumptionCheck().run(_ctx([AGGREGATE]))
    assert findings, "expected an OOB-confirmed unsafe consumption"
    f = findings[0]
    assert f.check == "unsafe_consumption"
    assert f.owasp_id == "API10:2023"
    assert f.confidence.value == "verified"
    assert f.evidence["param"] == "source"
    assert f.evidence["location"] == "query"
    assert f.evidence["oob_protocol"] == "http"


def test_callback_without_reflection_is_not_ours():
    """/fetch calls back but relays nothing — that is oob_injection's blind SSRF."""
    findings = UnsafeConsumptionCheck().run(_ctx([FETCH]))
    assert findings == []


def test_noop_without_premium():
    from tests.vulnapp import OUTBOUND

    ctx = factories.scan_context(
        [AGGREGATE], credentials=CREDS, oob=CollectorOob(OUTBOUND)
    )
    assert ctx.premium is False
    assert UnsafeConsumptionCheck().run(ctx) == []
    assert UnsafeConsumptionCheck().inapplicable(ctx) is not None


def test_noop_without_collector():
    """Premium but no OAST server → inactive NullOobClient, nothing to confirm."""
    ctx = factories.scan_context([AGGREGATE], credentials=CREDS, premium=True)
    assert UnsafeConsumptionCheck().run(ctx) == []
    reason = UnsafeConsumptionCheck().inapplicable(ctx)
    assert reason is not None and "collector" in reason


def test_inapplicable_without_a_url_shaped_param():
    from tests.vulnapp import OUTBOUND

    plain = TargetOperation(
        id="op-plain", method="GET", path="/search",
        params=[{"name": "q", "in": "query", "required": False}],
    )
    ctx = factories.scan_context(
        [plain], credentials=CREDS, oob=CollectorOob(OUTBOUND), premium=True
    )
    assert UnsafeConsumptionCheck().inapplicable(ctx) is not None
