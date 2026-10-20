"""Advanced rate-limit probe (premium): sustained load beyond the free burst."""
from __future__ import annotations

from types import SimpleNamespace

import pytest

from app.engine.base import HttpProbe, TargetOperation
from app.engine.checks.advanced_rate_limit import AdvancedRateLimitCheck
from app.engine.checks.enumeration import EnumerationCheck
from tests import factories

LOGIN = TargetOperation(id="op-login", method="POST", path="/login", params=[])


def test_premium_check_noops_without_premium():
    """Without premium:true the check returns nothing and probes nothing."""
    assert factories.run_one(AdvancedRateLimitCheck(), [LOGIN]) == []


def test_mutating_rate_probe_needs_mutation_opt_in():
    ctx = factories.scan_context([LOGIN], premium=True, allow_mutation=False)
    assert AdvancedRateLimitCheck().run(ctx) == []
    assert ctx.probe.count == 0


def test_sustained_no_throttle_is_flagged():
    """24 requests served without a 429 → no effective rate limiting."""
    findings = factories.run_one(
        AdvancedRateLimitCheck(), [LOGIN], premium=True, allow_mutation=True
    )
    assert findings
    f = findings[0]
    assert f.check == "advanced_rate_limit"
    assert f.evidence["requests"] == 24
    assert f.evidence["path"] == "/login"
    assert f.owasp_id == "API4:2023"


def test_sustained_probe_is_not_blocked_by_large_spec_fairness():
    operations = [LOGIN] + [
        TargetOperation(id=f"op-{i}", method="GET", path=f"/route-{i}", params=[])
        for i in range(1, 50)
    ]
    ctx = factories.scan_context(
        operations, premium=True, allow_mutation=True, max_requests=500
    )

    findings = AdvancedRateLimitCheck().run(ctx)

    assert findings
    assert ctx.probe.count == 24


@pytest.mark.parametrize(
    ("check", "premium", "requests"),
    [
        (EnumerationCheck(), False, 6),
        (AdvancedRateLimitCheck(), True, 24),
    ],
)
def test_retry_does_not_hide_a_429_from_rate_checks(check, premium, requests):
    class Client:
        def __init__(self):
            self.calls = 0

        def request(self, method, path, **kwargs):
            self.calls += 1
            status = 429 if self.calls % 2 else 200
            return SimpleNamespace(
                status_code=status,
                headers={"content-type": "application/json", "retry-after": "0"},
                text="{}",
                content=b"{}",
            )

    operation = TargetOperation(id="auth", method="GET", path="/auth/status")
    client = Client()
    probe = HttpProbe(client, operations=[operation], max_requests=requests * 2 + 2)
    probe._max_backoff = 0
    ctx = factories.scan_context(
        [operation], probe=probe, premium=premium, max_requests=requests * 2 + 2
    )

    assert check.run(ctx) == []
    assert client.calls == requests * 2
