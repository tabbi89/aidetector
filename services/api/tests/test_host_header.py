"""Host-header reflection (premium): the first premium-gated detection.

The check sends a spoofed forwarded-host header carrying a unique canary and
flags when the canary comes back — the target built a link or redirect from the
Host header. It is premium: no-op (no findings, and it costs no probes) unless
``premium: true``.
"""
from __future__ import annotations

from app.engine.base import TargetOperation
from app.engine.checks.host_header import HostHeaderCheck
from tests import factories

RESET_OP = TargetOperation(id="op-reset", method="GET", path="/reset-link", params=[])
HEALTH_OP = TargetOperation(id="op-health", method="GET", path="/health", params=[])


def test_premium_check_noops_without_premium():
    """Without premium:true the check returns nothing and probes nothing."""
    assert factories.run_one(HostHeaderCheck(), [RESET_OP]) == []


def test_host_header_reflection_is_flagged():
    findings = factories.run_one(HostHeaderCheck(), [RESET_OP], premium=True)
    assert findings, "a reflected spoofed host must produce a finding"
    f = findings[0]
    assert f.check == "host_header"
    assert f.evidence["route"] == "/reset-link"
    assert f.confidence.value == "heuristic"
    assert f.owasp_id == "API8:2023"


def test_a_clean_endpoint_is_not_flagged():
    """An endpoint that ignores the forwarded host produces nothing."""
    assert factories.run_one(HostHeaderCheck(), [HEALTH_OP], premium=True) == []
