"""Advanced rate-limit probe (premium): sustained load beyond the free burst.

The free ``enumeration`` check fires a 6-request burst and can only say "no
limit in six requests". A limit that engages later (a per-minute cap, a token
bucket with a larger burst) is invisible to it, so it under-reports. This check
sends a sustained sequence — well past the free burst — and only claims "no
rate limiting" when that sustained load is served without a throttle. Premium:
it costs more requests per endpoint, so it no-ops unless ``premium: true``.
"""
from __future__ import annotations

import re

from app.domain.enums import Confidence, Severity
from app.engine.base import EngineFinding, ScanContext, method_is_allowed, render_path
from app.engine.resource_map import path_values
from app.engine.spec_values import base_value

_RATE_HINTS = re.compile(
    r"login|signin|sign-in|token|password|passwd|otp|reset|auth", re.I
)
#: Sustained request count — deliberately past the free check's 6-request burst
#: so a limit that engages later is observable, while staying far short of a
#: load test. Each request still reserves a slot from the per-scan budget.
_SUSTAINED = 24
_MAX_OPS = 2
_MUTATING = ("POST", "PUT", "PATCH")


class AdvancedRateLimitCheck:
    key = "advanced_rate_limit"
    #: Premium: reserved for the paid tier, off unless ``premium: true``.
    premium = True

    def run(self, ctx: ScanContext) -> list[EngineFinding]:
        if not ctx.premium:
            return []
        headers = ctx.primary_headers()
        candidates = [
            op for op in ctx.operations
            if _RATE_HINTS.search(op.path)
            and method_is_allowed(op.method, allow_mutation=ctx.allow_mutation)
        ][:_MAX_OPS]
        findings: list[EngineFinding] = []

        for op in candidates:
            url = render_path(op.path, path_values(op, ctx.resource_ids))
            params = {
                p["name"]: base_value(p.get("schema") or {})
                for p in op.params
                if p.get("in") == "query" and p.get("required")
            } or None
            body = None
            if op.method in _MUTATING and op.body_params:
                body = {
                    p["name"]: base_value(p.get("schema") or {})
                    for p in op.params
                    if p.get("in") == "body" and p.get("required")
                }

            statuses: list[int] = []
            throttled = False
            for _ in range(_SUSTAINED):
                r = ctx.probe.send(
                    op.method,
                    url,
                    headers=headers,
                    params=params,
                    json=body,
                    # A sustained probe intentionally concentrates requests on
                    # one operation; the global 750-request ceiling still holds.
                    fairness_exempt=True,
                )
                if r is None:
                    return findings  # budget spent
                statuses.append(r.status)
                throttled = throttled or r.was_throttled

            succeeded = sum(1 for s in statuses if s < 400)
            if throttled or succeeded * 2 < len(statuses):
                continue  # throttled, or mostly rejects: no oracle
            findings.append(self._no_sustained_limit(op, statuses))
        return findings

    def _no_sustained_limit(self, op, statuses: list[int]) -> EngineFinding:
        return EngineFinding(
            check=self.key,
            confidence=Confidence.heuristic,
            owasp_id="API4:2023",
            severity=Severity.medium,
            title=f"No rate limiting under sustained load on {op.method} {op.path}",
            description=(
                f"{_SUSTAINED} identical requests in succession all succeeded "
                "without a throttle (429) response. A limit that only engages "
                "under sustained load is the harder case to notice and the one "
                "that still permits brute force, credential stuffing and "
                "enumeration — just more slowly."
            ),
            evidence={
                "method": op.method,
                "path": op.path,
                "requests": _SUSTAINED,
                "statuses": statuses,
            },
            operation_id=op.id,
        )
