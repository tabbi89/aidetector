"""Host-header reflection (premium): does the target build output from a spoofed Host?

Some apps trust the ``Host`` header — or a forwarded-host header a reverse proxy
sets — to build absolute URLs: password-reset links, redirect targets, canonical
links, cache keys. An attacker who can control that value poisons those links
(password-reset poisoning) or a shared cache (web-cache poisoning). The check
sends a spoofed host carrying a unique canary and flags when the canary comes
back in the response body or ``Location`` header — proof the application read the
header and built output from it.

Heuristic, not verified: reflection proves the header is *used*, not that the
path is exploitable — the target may only echo it in a header of its own.
Premium: it fires a spoofed-host request per endpoint, which the free engine
deliberately leaves out, so it no-ops unless ``premium: true``.
"""
from __future__ import annotations

import uuid
from typing import Any

from app.domain.enums import Confidence, Severity
from app.engine.base import EngineFinding, ScanContext, TargetOperation

#: Header names a reverse proxy commonly forwards that an app may trust as Host.
#: ``Host`` itself is deliberately omitted: httpx ties it to the request URL, and
#: the forwarded-host variants are the ones a misconfigured proxy leaves
#: attacker-controllable anyway.
_FORWARDED_HOST_HEADERS = ("X-Forwarded-Host", "X-Forwarded-Server", "X-Host")

#: Cap on endpoints probed, like the header sweep's own cap.
_MAX_ENDPOINTS = 40


def _safe_endpoints(ctx: ScanContext) -> list[TargetOperation]:
    """GET/HEAD endpoints the check may probe (read-only, bounded)."""
    ops = [o for o in ctx.operations if o.method in ("GET", "HEAD")]
    return ops[:_MAX_ENDPOINTS]


def _reflected(marker: str, result: Any) -> bool:
    """Whether the canary came back in the response body or a redirect target.

    Case-insensitive: a target that normalises host case before echoing has
    still built output from the spoofed header.
    """
    if result is None:
        return False
    if marker.lower() in (result.text or "").lower():
        return True
    return marker.lower() in (result.headers.get("location", "") or "").lower()


class HostHeaderCheck:
    key = "host_header"
    #: Premium: reserved for the paid tier, off unless ``premium: true``.
    premium = True

    def run(self, ctx: ScanContext) -> list[EngineFinding]:
        if not ctx.premium:
            return []
        findings: list[EngineFinding] = []
        for op in _safe_endpoints(ctx):
            # A canary only the target could echo if it read the forwarded-host
            # header and built output (a link, redirect or cache key) from it.
            marker = "aidx" + uuid.uuid4().hex[:16]
            headers = {h: f"{marker}.invalid" for h in _FORWARDED_HOST_HEADERS}
            resp = ctx.probe.send(op.method, op.path, headers=headers)
            if _reflected(marker, resp):
                findings.append(
                    EngineFinding(
                        check=self.key,
                        owasp_id="API8:2023",
                        severity=Severity.medium,
                        confidence=Confidence.heuristic,
                        title=f"Host-header reflection on {op.method} {op.path}"[:255],
                        description=(
                            f"{op.method} {op.path} echoed a spoofed host header "
                            f"back in its response. The application builds output "
                            "(links, redirects or cache keys) from the Host header, "
                            "which is the prerequisite for password-reset poisoning "
                            "and web-cache poisoning."
                        ),
                        evidence={
                            "method": op.method,
                            "route": op.path,
                            "canary_marker": marker,
                        },
                        operation_id=op.id,
                    )
                )
        return findings
