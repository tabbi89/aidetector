"""Out-of-band confirmation for blind classes: SSRF, RFI, RCE, ESI (and XXE).

Unlike the reflection checks, these vulnerabilities produce **no** response
signal — the only evidence is the target calling back to a server we control.
Each injection point gets a unique token embedded in a callback URL/host; after
the active pass we poll the OAST client and raise a finding for every token that
produced an interaction. An interaction is strong evidence, so findings here are
high/critical, not "reflection leads".

Scope, kept honest:

- Runs **only** when an OAST server is configured (``ctx.oob.active``);
  otherwise it is a zero-cost no-op.
- Injects into GET **query** params and JSON **body** fields (the two sinks the
  probe can reach). Headers, cookies and path params are still never fuzzed.
- True XXE needs an XML-content-type body, which the probe does not construct;
  the XXE payload here only fires if a JSON string value is concatenated into a
  parser downstream. Treat XXE coverage as partial.
"""
from __future__ import annotations

import uuid

from app.domain.enums import Confidence, Severity
from app.engine.base import EngineFinding, ScanContext, render_path
from app.engine.param_hints import is_fetchable
from app.engine.resource_map import path_values

# family -> (label, severity). Payload string is built per-token by _payload_for.
_FAMILIES: list[tuple[str, str, Severity]] = [
    ("blind_ssrf", "Blind SSRF", Severity.high),
    ("rfi", "Remote File Inclusion", Severity.high),
    ("rce_oob", "Command execution (OOB)", Severity.critical),
    ("esi", "Edge-Side Includes", Severity.high),
    ("xxe", "XXE (partial)", Severity.high),
]


def _payload_for(family: str, url: str) -> str:
    """Build the callback-carrying payload for a family, given its token URL."""
    if family == "rce_oob":
        return f";curl {url};"
    if family == "esi":
        return f'<esi:include src="{url}"/>'
    if family == "xxe":
        return (
            f'<?xml version="1.0"?><!DOCTYPE x '
            f'[<!ENTITY e SYSTEM "{url}">]><x>&e;</x>'
        )
    return url  # blind_ssrf, rfi -> bare callback URL


class OobInjectionCheck:
    key = "oob_injection"

    @staticmethod
    def inapplicable(ctx: ScanContext) -> str | None:
        """Needs a live out-of-band collector to hear a callback."""
        if not getattr(ctx.oob, "active", False):
            return (
                "no out-of-band collector configured (set OAST_SERVER) — blind "
                "injection is only provable by a callback"
            )
        return None

    def run(self, ctx: ScanContext) -> list[EngineFinding]:
        if not getattr(ctx.oob, "active", False):
            return []

        headers = ctx.primary_headers()
        # token -> (op, location, param, family, label, severity, payload)
        pending: dict[str, tuple] = {}

        for op in ctx.operations:
            path = render_path(op.path, path_values(op, ctx.resource_ids))
            # Query-param sinks: SSRF/RFI-named params get every family; others
            # get the URL-valued families only (cheaper, still catches echoes).
            if op.method == "GET":
                for qp in op.query_params:
                    named = is_fetchable(qp)
                    if self._inject(ctx, op, path, "query", qp, headers, pending, named) is None:
                        return self._collect(ctx, pending)  # budget spent
            # JSON body sinks (POST/PUT/PATCH with body fields) — gated behind the
            # mutate opt-in, since sending a body to a mutating verb changes state.
            if ctx.allow_mutation and op.method in ("POST", "PUT", "PATCH"):
                for bp in op.body_params:
                    if self._inject(ctx, op, path, "body", bp, headers, pending, True) is None:
                        return self._collect(ctx, pending)

        return self._collect(ctx, pending)

    def _inject(self, ctx, op, path, location, param, headers, pending, all_families):
        # A fresh token per (param, family) keeps every callback attributable to
        # the exact injection point that produced it.
        for family, label, severity in _FAMILIES:
            if not all_families and family != "blind_ssrf":
                continue
            token = "a" + uuid.uuid4().hex[:16]  # lowercase, DNS-label safe
            url = ctx.oob.payload_url(token)
            host = ctx.oob.payload_domain(token)
            if not url or not host:
                return None
            payload = _payload_for(family, url)
            if location == "query":
                r = ctx.probe.send(op.method, path, headers=headers, params={param: payload})
            else:
                r = ctx.probe.send(op.method, path, headers=headers, json={param: payload})
            if r is None:
                return None  # request budget exhausted
            pending[token] = (op, location, param, family, label, severity, payload)
        return True

    def _collect(self, ctx, pending) -> list[EngineFinding]:
        findings: list[EngineFinding] = []
        for interaction in ctx.oob.poll():
            meta = pending.get(interaction.token)
            if meta is None:
                continue
            op, location, param, family, label, severity, payload = meta
            findings.append(
                EngineFinding(
                    check=self.key,
                    confidence=Confidence.verified,
                    owasp_id="API7:2023" if family == "blind_ssrf" else "CWE-74",
                    severity=severity,
                    title=f"{label} confirmed via '{param}' on {op.method} {op.path}",
                    description=(
                        f"An out-of-band {interaction.protocol.upper()} callback proved "
                        f"the target fetched an attacker-controlled host after the "
                        f"'{param}' {location} value was injected. This is a confirmed "
                        f"{label} — the server reached our OAST server, not a reflection."
                    ),
                    evidence={
                        "param": param,
                        "location": location,
                        "family": family,
                        "payload": payload,
                        "oob_protocol": interaction.protocol,
                        "oob_source_ip": interaction.source_ip,
                        "oob_token": interaction.token,
                    },
                    operation_id=op.id,
                )
            )
        return findings
