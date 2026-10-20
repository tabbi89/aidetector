"""Broken Authentication (API2) — a protected op accepts a forged credential.

Rebuilt to be baseline-gated. The old check flagged any endpoint that returned
< 400 for a garbage token, which false-positives on genuinely *public*
endpoints. This version first proves the endpoint actually enforces auth (an
anonymous request is rejected), and only then tries to bypass it:

1. **Baseline** — send with no credentials. If that is not rejected
   (401/403/redirect-to-login), the endpoint is public; there is nothing to
   bypass, so we skip it. This removes the dominant false-positive class.
2. **Forgeries** — a random never-issued token, plus, when a credential carries a
   JWT, a targeted forgery suite (``alg=none``, stripped/tampered signature,
   elevated claims — see ``app/engine/jwt_forge.py``). The first forged
   credential that is accepted names the concrete bypass class in the finding.
"""
from __future__ import annotations

import uuid
from dataclasses import dataclass

from app.domain.enums import AuthType, Confidence, Severity
from app.engine.base import (
    EngineFinding,
    ResolvedCredential,
    ScanContext,
    TargetOperation,
    method_is_allowed,
    render_path,
)
from app.engine.jwt_forge import forge_from_token
from app.engine.jwt_hmac import hmac_probe_suite
from app.engine.resource_map import path_values

# Path fragments that mark an operation as almost certainly protected.
_PROTECTED_HINTS = ("/admin", "/account", "/user", "/me", "/order", "/profile", "/wallet")

# Anonymous status codes that count as "auth is enforced here".
_REJECTED = {401, 403}


@dataclass(frozen=True)
class _Variant:
    label: str
    description: str
    headers: dict[str, str]
    valid_control: dict[str, str] | None = None
    rejected_control: dict[str, str] | None = None


def _looks_protected(op: TargetOperation) -> bool:
    if op.auth_scope:
        return True
    if op.path_params:
        return True
    p = op.path.lower()
    return any(h in p for h in _PROTECTED_HINTS)


def _headers_for(cred: ResolvedCredential, token: str) -> dict[str, str]:
    """Put a forged value on the credential's actual authentication channel.

    API keys and JWTs carried in custom headers must stay there; switching based
    on token shape only tests an unrelated, ignored Authorization header.
    """
    channel = ResolvedCredential(
        name=cred.name,
        role=cred.role,
        auth_type=cred.auth_type,
        header_name=cred.header_name,
        secret=token,
    )
    return channel.headers()


def _forged_variants(ctx: ScanContext) -> list[_Variant]:
    """Bounded forged credentials; duplicate supplied tokens are processed once."""
    variants: list[_Variant] = []
    seen_channels: set[tuple[AuthType, tuple[str, ...]]] = set()
    for cred in ctx.credentials:
        headers = _headers_for(cred, f"aidetector-forged-{uuid.uuid4().hex[:8]}")
        channel = (cred.auth_type, tuple(sorted(name.lower() for name in headers)))
        if headers and channel not in seen_channels:
            seen_channels.add(channel)
            variants.append(
                _Variant(
                    "random_token",
                    "a random, never-issued token was accepted",
                    headers,
                )
            )
    if not variants:
        variants.append(
            _Variant(
                "random_token",
                "a random, never-issued token was accepted",
                {"Authorization": f"aidetector-forged-{uuid.uuid4().hex[:8]}"},
            )
        )
    seen_tokens: set[str] = set()
    for cred in ctx.credentials:
        if cred.secret in seen_tokens:
            continue
        seen_tokens.add(cred.secret)
        for forged in forge_from_token(cred.secret):
            variants.append(
                _Variant(
                    forged.label,
                    forged.description,
                    _headers_for(cred, forged.token),
                )
            )
        suite = hmac_probe_suite(cred.secret)
        if suite is None:
            continue
        valid_control = _headers_for(cred, suite.valid_control)
        rejected_control = _headers_for(cred, suite.rejected_control)
        for forged in suite.probes:
            variants.append(
                _Variant(
                    forged.label,
                    forged.description,
                    _headers_for(cred, forged.token),
                    valid_control,
                    rejected_control,
                )
            )
    return variants


class BrokenAuthCheck:
    key = "broken_auth"
    # Its findings need the scan's identities; a run that left one out could
    # not have re-found them, so the diff must not call them fixed.
    needs_identities = True

    @staticmethod
    def inapplicable(ctx: ScanContext) -> str | None:
        if not any(
            _looks_protected(op)
            and method_is_allowed(op.method, allow_mutation=ctx.allow_mutation)
            for op in ctx.operations
        ):
            return (
                "no protected-looking operation is safely probeable with the current "
                "mutation setting"
            )
        return None

    def run(self, ctx: ScanContext) -> list[EngineFinding]:
        variants = _forged_variants(ctx)
        findings: list[EngineFinding] = []

        for op in ctx.operations:
            if not _looks_protected(op):
                continue
            if not method_is_allowed(op.method, allow_mutation=ctx.allow_mutation):
                continue
            path = render_path(op.path, path_values(op, ctx.resource_ids))

            # Baseline: is auth actually enforced here? An unauthenticated request
            # must be rejected, or there is no authentication to bypass.
            anon = ctx.probe.send(op.method, path, headers={})
            if anon is None:
                continue
            if anon.status not in _REJECTED:
                continue  # public endpoint — not a broken-auth candidate

            findings.extend(self._try_forgeries(ctx, op, path, anon.status, variants))
        return findings

    def _try_forgeries(
        self, ctx, op, path, anon_status, variants: list[_Variant]
    ) -> list[EngineFinding]:
        findings: list[EngineFinding] = []
        controls: dict[
            tuple[tuple[str, str], ...], tuple[int, int] | None
        ] = {}
        for variant in variants:
            control_statuses: tuple[int, int] | None = None
            if variant.valid_control is not None and variant.rejected_control is not None:
                control_key = tuple(sorted(variant.valid_control.items()))
                if control_key not in controls:
                    valid = ctx.probe.send(op.method, path, headers=variant.valid_control)
                    rejected = ctx.probe.send(
                        op.method, path, headers=variant.rejected_control
                    )
                    if valid is None or rejected is None:
                        return findings
                    controls[control_key] = (valid.status, rejected.status)
                control_statuses = controls[control_key]
                if control_statuses is None:
                    continue
                valid_status, rejected_status = control_statuses
                if valid_status >= 400 or rejected_status not in _REJECTED:
                    continue

            r = ctx.probe.send(op.method, path, headers=variant.headers)
            if r is None:
                return findings
            if r.status < 400:
                evidence = {
                    "method": op.method,
                    "route": op.path,
                    "path": path,
                    "bypass_class": variant.label,
                    "anon_status": anon_status,
                    "forged_status": r.status,
                    "response_sample": r.text[:400],
                }
                control_copy = ""
                if control_statuses is not None:
                    evidence["valid_control_status"] = control_statuses[0]
                    evidence["rejected_control_status"] = control_statuses[1]
                    control_copy = (
                        f" The unchanged valid token succeeded ({control_statuses[0]}) "
                        f"and the bad-signature control was rejected "
                        f"({control_statuses[1]})."
                    )
                findings.append(
                    EngineFinding(
                        check=self.key,
                        confidence=Confidence.verified,
                        owasp_id="API2:2023",
                        severity=Severity.high,
                        title=(
                            f"Auth bypass ({variant.label}) on {op.method} {op.path}"
                        ),
                        description=(
                            f"{op.method} {op.path} rejects an anonymous request "
                            f"({anon_status}) but {variant.description} ({r.status})."
                            f"{control_copy} Authentication is enforced but can be "
                            "bypassed."
                        ),
                        evidence=evidence,
                        operation_id=op.id,
                    )
                )
                # An invalid-signature bypass makes weaker-key/time-claim probes
                # non-isolating; report the broad flaw and stop this endpoint.
                if control_statuses is None:
                    return findings
        return findings
