"""Full XXE confirmation (premium): out-of-band XML external entities."""
from __future__ import annotations

from app.engine.base import TargetOperation
from app.engine.checks.xxe_confirmation import XxeConfirmationCheck
from tests import factories
from tests.fakes import CollectorOob
from tests.vulnapp import OUTBOUND

XML_OP = TargetOperation(
    id="op-xml", method="POST", path="/xml",
    params=[{"name": "data", "in": "body", "required": False}],
)


def test_premium_check_noops_without_premium():
    ctx = factories.scan_context(
        [XML_OP], allow_mutation=True, oob=CollectorOob(OUTBOUND)
    )
    assert XxeConfirmationCheck().run(ctx) == []


def test_full_xxe_is_confirmed_via_oob():
    ctx = factories.scan_context(
        [XML_OP], allow_mutation=True, oob=CollectorOob(OUTBOUND), premium=True
    )
    findings = XxeConfirmationCheck().run(ctx)
    assert findings
    families = {f.evidence["family"] for f in findings}
    assert {"external_entity", "parameter_entity", "blind_exfil"} <= families
    assert all(f.confidence.value == "verified" for f in findings)
    assert all(f.evidence["oob_protocol"] == "http" for f in findings)
