"""Run-start policy is a decision, not a route: exercise it without HTTP.

The gate used to live inside the scan route handlers, so proving it required a
request fixture and the two callers (manual run, schedule) could drift. These
tests pin the decision itself and the layering that keeps it reusable.
"""
from __future__ import annotations

from pathlib import Path

import pytest

from app.core.config import settings
from app.scans import policy
from app.scans.run_options import RunOptions


def _authorize(
    *,
    authorized: bool = True,
    options: RunOptions | None = None,
    tenant: str = "acme",
) -> None:
    policy.authorize_run(
        authorized=authorized,
        options=options or RunOptions(),
        tenant_id=tenant,
    )


def test_an_active_scan_requires_explicit_authorization() -> None:
    with pytest.raises(policy.RunNotAuthorized):
        _authorize(authorized=False)


def test_a_premium_pass_requires_an_entitled_tenant(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(settings, "premium_tenants", "")
    with pytest.raises(policy.PremiumRequired):
        _authorize(options=RunOptions(premium=True))


def test_an_entitled_tenant_may_run_a_premium_pass(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(settings, "premium_tenants", "acme")
    _authorize(options=RunOptions(premium=True))


def test_resource_refinement_requires_the_flags_it_depends_on(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(settings, "premium_tenants", "acme")
    with pytest.raises(policy.RunOptionConflict, match="premium"):
        _authorize(options=RunOptions(resource_refine=True))
    with pytest.raises(policy.RunOptionConflict, match="requires writes"):
        _authorize(options=RunOptions(resource_refine=True, premium=True))
    _authorize(options=RunOptions(resource_refine=True, premium=True, mutate=True))


def test_a_credential_grant_url_is_egress() -> None:
    with pytest.raises(policy.CredentialUrlBlocked, match="token_url"):
        policy.guard_credential_urls(
            token_url="http://169.254.169.254/latest/meta-data/",
            refresh_url=None,
        )


@pytest.mark.parametrize("module", ["service.py", "policy.py", "views.py"])
def test_the_scan_layer_does_not_depend_on_the_http_layer(module: str) -> None:
    """A service that imports ``app.api`` makes the HTTP adapter its contract."""
    source = Path(__file__).resolve().parents[1] / "app" / "scans" / module
    offenders = [
        line.strip()
        for line in source.read_text().splitlines()
        if line.strip().startswith(
            ("from app.api", "import app.api", "from fastapi", "import fastapi")
        )
    ]
    assert not offenders, f"{module} depends on the HTTP layer: {offenders}"
