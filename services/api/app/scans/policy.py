"""Run-start policy: authorization, entitlement, option conflicts and egress.

These decisions are not HTTP. A schedule is a standing run request, so a manual
run and a scheduled one must answer the same gate; keeping the policy here means
that gate can be unit-tested and reused without a request object.

The route layer owns the translation to status codes. This module raises the
domain errors below and imports neither FastAPI nor ``app.api.schemas``.
"""
from __future__ import annotations

from app.core.config import settings
from app.core.target_guard import TargetNotAllowed, check_target_allowed
from app.scans.run_options import RunOptions


class RunNotAuthorized(Exception):
    """The caller did not confirm they may test the target."""


class PremiumRequired(Exception):
    """The run asked for a pass the tenant is not entitled to."""


class RunOptionConflict(Exception):
    """Two run flags contradict each other."""


class CredentialUrlBlocked(Exception):
    """A credential grant/refresh URL points outside egress policy."""

    def __init__(self, label: str, reason: object) -> None:
        self.label = label
        self.reason = reason
        super().__init__(f"credential {label} not allowed: {reason}")


def authorize_run(
    *,
    authorized: bool,
    options: RunOptions,
    tenant_id: str,
    premium: bool | None = None,
) -> None:
    """Answer the gates every path that starts scans must pass.

    Active scanning fires real payloads at a live host, so ``authorized`` is
    mandatory. The premium passes are re-checked here rather than trusted from
    the request, and the refinement flags must not contradict each other.

    ``premium`` is the caller's workspace-plan answer; when omitted (unit tests,
    legacy callers) the configuration entitlement is used.
    """
    if not authorized:
        raise RunNotAuthorized("Authorization required: confirm you may test this target.")
    entitled = (
        settings.tenant_is_premium(tenant_id) if premium is None else premium
    )
    premium_feature = options.premium or options.adaptive or options.resource_refine
    if premium_feature and not entitled:
        raise PremiumRequired("premium tier required for this run")
    if options.resource_refine and not options.premium:
        raise RunOptionConflict("resource refinement requires premium:true")
    if options.resource_refine and not options.mutate:
        raise RunOptionConflict("resource refinement requires writes")


def require_target_allowed(
    target_base_url: str, *, allow_private: bool | None = None
) -> None:
    """SSRF/egress guard, answered before anything is queued.

    Cloud-metadata and non-http schemes are always refused; private ranges per
    ``target_allow_private``, unless a caller passes ``allow_private`` to
    override it. The local-runner claim passes ``True``: the hosted server
    never dials a local run's target — the CLI machine does — so a private
    target there is the tenant reaching their own network, not egress from the
    server. The worker re-checks immediately before it opens a socket, since
    DNS and the scan may both change while a job waits.
    """
    check_target_allowed(
        target_base_url,
        allow_private=(
            settings.target_allow_private if allow_private is None else allow_private
        ),
        allowlist=settings.allowlist_set(),
    )


def guard_credential_urls(*, token_url: str | None, refresh_url: str | None) -> None:
    """Reject grant/refresh URLs that point out of egress policy.

    ``token_url`` and ``refresh_url`` are fetched by the worker (mint/refresh),
    so they are egress exactly like the scan target and must pass the same
    guard. The target is re-checked at run time; these are checked here at
    write time and again by the runner before any request fires.
    """
    for label, url in (("token_url", token_url), ("refresh_url", refresh_url)):
        if not url:
            continue
        try:
            require_target_allowed(url)
        except TargetNotAllowed as exc:
            raise CredentialUrlBlocked(label, exc) from exc
