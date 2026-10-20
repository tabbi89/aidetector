"""Budget-counted, observable teardown. Failure must not hide a finding."""
from __future__ import annotations

from typing import Any

from app.engine.base import ScanContext, TargetOperation


def cleanup_request(
    ctx: ScanContext, op: TargetOperation, path: str, **kwargs: Any
) -> bool:
    try:
        with ctx.probe.cleanup_scope():
            response = ctx.probe.send(op.method, path, **kwargs)
        if response is not None and (
            200 <= response.status < 300 or (op.method == 'DELETE' and response.status == 404)
        ):
            ctx.probe.cleanup_results.append(True)
            return True
        reason = 'request budget exhausted' if response is None else f'HTTP {response.status}'
    except Exception:  # noqa: BLE001 — cleanup must not mask the original result
        reason = 'transport failed; target state unknown'
    # Only the spec template, never resource values, credentials or exception text.
    ctx.probe.cleanup_results.append(False)
    ctx.cleanup_failures.append(f'{op.method} {op.path}: {reason}')
    return False


def cleanup_as(
    ctx: ScanContext,
    op: TargetOperation,
    path: str,
    identities: list[Any],
    **kwargs: Any,
) -> bool:
    """Clean up as each identity in turn; record a failure only if all fail.

    The creator goes first. Across tenants the owner cannot see the attacker's
    object, so the owner's DELETE answers 404 — which ``cleanup_request`` reads
    as "already gone" — and the object stayed on the target unreported. The
    creator's own 404 does mean gone. Later identities cover a creator that may
    create but not delete.
    """
    seen: set[int] = set()
    reasons: list[str] = []
    for identity in identities:
        if identity is None or id(identity) in seen:
            continue
        seen.add(id(identity))
        try:
            with ctx.probe.cleanup_scope():
                response = ctx.probe.send(op.method, path, headers=identity.headers(), **kwargs)
        except Exception:  # noqa: BLE001 — cleanup must not mask the original result
            reasons.append("transport failed; target state unknown")
            continue
        if response is None:
            reasons.append("request budget exhausted")
            break
        if 200 <= response.status < 300 or (op.method == "DELETE" and response.status == 404):
            ctx.probe.cleanup_results.append(True)
            return True
        reasons.append(f"HTTP {response.status}")
    ctx.probe.cleanup_results.append(False)
    ctx.cleanup_failures.append(f"{op.method} {op.path}: {', '.join(reasons) or 'not attempted'}")
    return False


def creation_request(
    ctx: ScanContext, op: TargetOperation, path: str, **kwargs: Any
):
    """A lost create response can mean an orphan with no discoverable identifier."""
    try:
        return ctx.probe.send(op.method, path, **kwargs)
    except Exception:
        ctx.cleanup_failures.append(
            f'{op.method} {op.path}: create response lost; target state unknown'
        )
        raise
