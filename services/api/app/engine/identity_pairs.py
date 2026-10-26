"""Which authorization boundaries a set of identities can test — before a run.

The engine pairs identities at run time (``ScanContext.identity_pair`` for
object-level checks, ``privilege_pair`` for function-level ones). This asks the
same methods about identity *shapes* — name, role, rank, tenant; never a
secret — so setup can say "these two test cross-tenant BOLA, nothing tests
BFLA" without a run. Using the engine's own methods is the point: a second
copy of the rules in a client would drift.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any, cast

from app.domain.enums import AuthType
from app.engine.context import ScanContext
from app.engine.credentials import ResolvedCredential


@dataclass(frozen=True)
class IdentityShape:
    name: str
    role: str
    privilege: int | None = None
    tenant: str | None = None


def _context(shapes: list[IdentityShape]) -> ScanContext:
    creds = [
        ResolvedCredential(
            name=s.name, role=s.role, auth_type=AuthType.bearer, header_name=None,
            secret="", privilege=s.privilege, tenant=s.tenant or None,
        )
        for s in shapes
    ]
    # No probe: nothing here sends a request.
    return ScanContext(base_url="", operations=[], credentials=creds, probe=cast(Any, None))


def describe_pairs(shapes: list[IdentityShape]) -> dict[str, Any]:
    """The object- and function-level pairs a run would use, and what is missing."""
    ctx = _context(shapes)
    tenants = ctx.tenants_declared()
    obj = ctx.identity_pair()
    fn = ctx.privilege_pair()
    out: dict[str, Any] = {
        "tenants_declared": tenants,
        "object_level": None,
        "object_level_gap": None,
        "function_level": None,
        "function_level_gap": None,
        # With tenants declared, an identity without one sits out the pairing.
        "left_out": [s.name for s in shapes if tenants and not s.tenant],
    }
    if obj is not None:
        out["object_level"] = {"owner": obj.owner.name, "attacker": obj.attacker.name}
    elif len(shapes) < 2:
        out["object_level_gap"] = "object-level checks (BOLA) need two identities"
    else:
        out["object_level_gap"] = ctx.pair_gap()
    if fn is not None and ctx.privilege_rank(fn.owner) > ctx.privilege_rank(fn.attacker):
        out["function_level"] = {"privileged": fn.owner.name, "lower": fn.attacker.name}
    elif len(shapes) < 2:
        out["function_level_gap"] = (
            "function-level checks (BFLA) need two identities of different privilege"
        )
    elif fn is None:
        out["function_level_gap"] = (
            "no tenant has two identities — add a lower-privileged identity to one tenant "
            "to test function-level access (BFLA)"
        )
    else:
        out["function_level_gap"] = (
            f"'{fn.owner.name}' and '{fn.attacker.name}' share one privilege rank — give one "
            "a lower rank (or a lower role) to test function-level access (BFLA)"
        )
    return out
