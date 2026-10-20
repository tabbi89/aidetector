"""Insecure deserialization (premium): gadget payloads confirmed out-of-band."""
from __future__ import annotations

from app.engine.base import TargetOperation
from app.engine.checks.deserialization import DeserializationCheck
from tests import factories
from tests.fakes import CollectorOob
from tests.vulnapp import OUTBOUND

DESER_OP = TargetOperation(
    id="op-deser", method="POST", path="/deserialize",
    params=[{"name": "data", "in": "body", "required": False}],
)


def test_premium_check_noops_without_premium():
    ctx = factories.scan_context(
        [DESER_OP], allow_mutation=True, oob=CollectorOob(OUTBOUND)
    )
    assert DeserializationCheck().run(ctx) == []


def test_deserialization_is_confirmed_via_oob():
    ctx = factories.scan_context(
        [DESER_OP], allow_mutation=True, oob=CollectorOob(OUTBOUND), premium=True
    )
    findings = DeserializationCheck().run(ctx)
    assert findings
    frameworks = {f.evidence["family"] for f in findings}
    assert {"python_pickle", "php_unserialize", "java_ysoserial", "dotnet"} <= frameworks
    assert all(f.confidence.value == "verified" for f in findings)
