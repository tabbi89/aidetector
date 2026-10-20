"""Unsafe consumption of an upstream API (API10) — premium, OOB-confirmed.

API10 is the mirror of API7. SSRF asks whether the server can be *made to reach*
an attacker-chosen host; unsafe consumption asks whether the server *trusts and
relays* what an upstream returns without validating it. The two share a sink — a
URL-shaped parameter the server dereferences — but a different oracle.

A callback alone is blind SSRF, and ``oob_injection`` already owns that. This
check fires only on the **conjunction**: the target both

1. reached our OAST collector (an interaction — the fetch happened), *and*
2. surfaced the upstream-correlated marker in its **own response** (the token
   the callback URL carried comes back in the body — the endpoint relayed
   content tied to the upstream it fetched).

Together, the endpoint consumed an upstream it did not validate and exposed the
result downstream to its caller. Reflection without a callback is
``reflected_injection``'s; a callback without reflection is ``oob_injection``'s;
only the pair is unsafe consumption, so the three do not overlap.

Premium and off by default; a no-op without a live collector, exactly like the
other confirmation-tier checks.
"""
from __future__ import annotations

import uuid

from app.domain.enums import Confidence, Severity
from app.engine.base import EngineFinding, ScanContext, render_path
from app.engine.param_hints import SSRF_PARAM_HINTS
from app.engine.resource_map import path_values

#: URL/endpoint-shaped parameter names that mean "an upstream the server calls".
#: The SSRF vocabulary plus the API-consumption words that name a downstream
#: service specifically (kept local so the SSRF/OOB sink list is untouched).
_UPSTREAM_HINTS = SSRF_PARAM_HINTS | {
    "source", "upstream", "endpoint", "api", "service", "provider", "proxy",
    "origin", "remote", "backend",
}

_MUTATING = ("POST", "PUT", "PATCH")


def _is_upstream(name: str) -> bool:
    n = name.lower()
    return n in _UPSTREAM_HINTS or n.endswith("url") or n.endswith("uri")


class UnsafeConsumptionCheck:
    key = "unsafe_consumption"
    #: Reserved for the premium tier, off unless ``premium: true``.
    premium = True

    def _sinks(self, ctx: ScanContext) -> list[tuple]:
        """(op, location, param) for every url-shaped sink this run may reach."""
        sinks: list[tuple] = []
        for op in ctx.operations:
            if op.method == "GET":
                sinks += [(op, "query", p) for p in op.query_params if _is_upstream(p)]
            if ctx.allow_mutation and op.method in _MUTATING:
                sinks += [(op, "body", p) for p in op.body_params if _is_upstream(p)]
        return sinks

    def inapplicable(self, ctx: ScanContext) -> str | None:
        if not ctx.premium:
            return "premium detection is off (enable 'premium' to run it)"
        if not getattr(ctx.oob, "active", False):
            return (
                "no out-of-band collector configured (set OAST_SERVER) — proving "
                "the target consumed a downstream needs a callback"
            )
        if not self._sinks(ctx):
            return "no URL/upstream-shaped parameter for the server to consume"
        return None

    def run(self, ctx: ScanContext) -> list[EngineFinding]:
        if not ctx.premium or not getattr(ctx.oob, "active", False):
            return []
        headers = ctx.primary_headers()
        # token -> (op, location, param, response_text)
        pending: dict[str, tuple] = {}

        for op, location, param in self._sinks(ctx):
            path = render_path(op.path, path_values(op, ctx.resource_ids))
            token = "a" + uuid.uuid4().hex[:16]  # DNS-label safe
            url = ctx.oob.payload_url(token)
            if not url:
                return self._collect(ctx, pending)  # collector went inactive
            if location == "query":
                r = ctx.probe.send(op.method, path, headers=headers, params={param: url})
            else:
                r = ctx.probe.send(op.method, path, headers=headers, json={param: url})
            if r is None:
                return self._collect(ctx, pending)  # budget spent
            pending[token] = (op, location, param, r.text or "")

        return self._collect(ctx, pending)

    def _collect(self, ctx: ScanContext, pending: dict[str, tuple]) -> list[EngineFinding]:
        findings: list[EngineFinding] = []
        for interaction in ctx.oob.poll():
            meta = pending.get(interaction.token)
            if meta is None:
                continue
            op, location, param, response_text = meta
            # The conjunction: the callback fired (the fetch happened) AND the
            # upstream-correlated token came back in the target's own response.
            if interaction.token not in response_text:
                continue  # callback only → plain blind SSRF, oob_injection's finding
            findings.append(
                EngineFinding(
                    check=self.key,
                    confidence=Confidence.verified,
                    owasp_id="API10:2023",
                    severity=Severity.high,
                    title=f"Unsafe upstream consumption via '{param}' on {op.method} {op.path}",
                    description=(
                        f"The target fetched an attacker-controlled upstream (an "
                        f"out-of-band {interaction.protocol.upper()} callback proved "
                        f"the request left the server) and then relayed upstream-"
                        f"correlated content back in its own response to the '{param}' "
                        f"{location} value. The endpoint consumes a downstream it does "
                        "not validate and exposes the result to its caller — a "
                        "confirmed unsafe consumption, distinct from blind SSRF because "
                        "the downstream content, not just the request, reached the "
                        "client."
                    ),
                    evidence={
                        "method": op.method,
                        "path": op.path,
                        "param": param,
                        "location": location,
                        "oob_protocol": interaction.protocol,
                        "oob_source_ip": interaction.source_ip,
                        "oob_token": interaction.token,
                    },
                    operation_id=op.id,
                )
            )
        return findings
