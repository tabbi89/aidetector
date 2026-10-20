"""Out-of-band confirmation — the tier where a finding is not a lead.

An interaction means the target really called back to a server we control, so
these are confirmations. Inactive without an OAST server, and a no-op then.
"""
from __future__ import annotations

from app.engine.base import (
    TargetOperation,
)
from tests import factories
from tests.fakes import CollectorOob

OPERATIONS = factories.engine_operations()
CREDS = factories.two_identities()


def test_oob_confirms_blind_ssrf_via_query_and_body():
    from app.engine.checks.oob_injection import OobInjectionCheck
    from tests.vulnapp import OUTBOUND

    ops = [
        TargetOperation(
            id="op-fetch", method="GET", path="/fetch",
            params=[{"name": "url", "in": "query", "required": False}],
        ),
        TargetOperation(
            id="op-webhook", method="POST", path="/webhook",
            params=[{"name": "callback", "in": "body", "required": False}],
        ),
    ]
    ctx = factories.scan_context(
        ops,
        credentials=CREDS,
        oob=CollectorOob(OUTBOUND),
        allow_mutation=True,  # body sinks on POST require the mutate opt-in
    )
    findings = OobInjectionCheck().run(ctx)
    ssrf = [f for f in findings if f.evidence["family"] == "blind_ssrf"]
    assert ssrf, "expected OOB-confirmed blind SSRF"
    locations = {f.evidence["location"] for f in ssrf}
    assert {"query", "body"} <= locations, locations
    assert all(f.severity.value in ("high", "critical") for f in findings)
    assert all(f.evidence["oob_protocol"] == "http" for f in findings)


def test_oob_inactive_client_is_noop():
    from app.engine.checks.oob_injection import OobInjectionCheck

    # No oob passed → the default NullOobClient, i.e. OAST not configured.
    ctx = factories.scan_context(OPERATIONS, credentials=CREDS)
    assert OobInjectionCheck().run(ctx) == []
