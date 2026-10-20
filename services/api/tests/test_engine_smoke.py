"""Whole-registry smoke plus the checks that stand alone.

``test_engine_finds_across_multiple_classes`` walks ALL_CHECKS and is the one
test that fails when a newly registered check explodes on contact.
"""
from __future__ import annotations

from fastapi.testclient import TestClient

from app.engine.base import (
    HttpProbe,
    ScanContext,
    TargetOperation,
)
from tests import factories
from tests.vulnapp import vulnapp

OPERATIONS = factories.engine_operations()
CREDS = factories.two_identities()


def _run_all():
    return factories.run_registry(OPERATIONS, credentials=CREDS)


def test_engine_finds_across_multiple_classes():
    findings = _run_all()
    checks = {f.check for f in findings}
    # Gate: true-positive findings across >= 4 distinct check classes.
    expected = {"bola", "bfla", "broken_auth", "reflected_injection", "security_headers"}
    assert expected.issubset(checks), f"missing: {expected - checks} (got {checks})"


def test_default_run_produces_no_premium_findings():
    """Premium checks are gated: a non-premium run must not emit their findings."""
    from app.engine.base import premium
    from app.engine.checks import ALL_CHECKS

    premium_keys = {c.key for c in ALL_CHECKS if premium(c)}
    assert premium_keys, "expected premium checks to gate"
    findings = _run_all()  # no premium:true
    assert not any(f.check in premium_keys for f in findings)


def test_tls_config_flags_plaintext_http_target():
    from app.engine.checks.tls import TlsConfigCheck

    ctx = ScanContext(
        base_url="http://insecure.test",
        operations=[],
        credentials=CREDS,
        probe=HttpProbe(TestClient(vulnapp)),
    )
    findings = TlsConfigCheck().run(ctx)
    assert len(findings) == 1
    assert findings[0].check == "tls_config"
    assert "plaintext" in findings[0].title.lower()


def test_enumeration_rate_limit_absent():
    from app.engine.checks.enumeration import EnumerationCheck

    op = TargetOperation(id="op-login", method="POST", path="/login", params=[])
    ctx = factories.scan_context([op], credentials=CREDS, allow_mutation=True)
    probe = ctx.probe
    findings = EnumerationCheck().run(ctx)
    assert len(findings) == 1
    f = findings[0]
    assert f.owasp_id == "API4:2023"
    assert f.severity.value == "low"
    assert probe.count == 6
    assert f.evidence["statuses"] == [200] * 6


def test_enumeration_duplicate_create_oracle():
    from app.engine.checks.enumeration import EnumerationCheck

    op = TargetOperation(
        id="op-signup",
        method="POST",
        path="/signup",
        params=[{"name": "email", "in": "body", "required": True}],
    )
    # Without mutate the create oracle never fires (it writes).
    ctx = factories.scan_context([op], credentials=CREDS)
    probe = ctx.probe
    assert EnumerationCheck().run(ctx) == []
    assert probe.count == 0

    ctx2 = factories.scan_context(
        [op],
        credentials=CREDS,
        probe=HttpProbe(TestClient(vulnapp),
        operations=[op]),
        allow_mutation=True,
    )
    findings = EnumerationCheck().run(ctx2)
    assert findings, "duplicate create must surface the enumeration oracle"
    f = findings[0]
    assert f.check == "enumeration"
    assert f.owasp_id == "API2:2023"
    assert f.severity.value == "medium"
    assert f.evidence["first_status"] == 201
    assert f.evidence["second_status"] == 409
