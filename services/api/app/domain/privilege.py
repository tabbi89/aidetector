"""Is this operation privileged? One rule, because it decides a finding's severity.

Two copies of this used to exist and had diverged: the authorization checks
matched six scope tokens, while the write oracle matched only ``admin``. The
value is not cosmetic — in ``write_oracle`` it selects the finding's
``owasp_id`` (API5 vs API1) and ``severity`` (critical vs high), so an endpoint
scoped ``staff:write`` was reported by ``bfla`` as a privileged-function bug and
by ``write_authz`` as an ordinary object-level bug one tier lower. Two findings
in one report, disagreeing about one endpoint.

The union of the two definitions is the correct one: a scope naming staff,
internal or superuser access is privileged wherever it is observed, not only
where a particular check happens to look.

Pure — no I/O, no engine state.
"""
from __future__ import annotations

#: Scope/label tokens that mark an operation as privileged. Matched as
#: substrings of the declared security scope, so ``manage`` catches
#: ``manage:users`` and ``admin`` catches ``admin:write``.
PRIVILEGE_TOKENS = ("admin", "superuser", "root", "manage", "staff", "internal")


def is_privileged(path: str, auth_scope: str | None) -> bool:
    """True when the path or its declared security scope names privileged access.

    The path test is deliberately narrow and slash-anchored (``/admin``): a path
    segment is not a security decision the way a declared scope is, and matching
    the other tokens loosely there would flag ``/manage-account`` or
    ``/internal-notes`` on wording alone.
    """
    scope = (auth_scope or "").lower()
    segments = {segment.lower() for segment in path.split("/") if segment}
    return "admin" in segments or any(tok in scope for tok in PRIVILEGE_TOKENS)


#: Privilege implied by a role *name*, for identities that did not set an
#: explicit rank. Higher is more privileged. Anything unlisted is an ordinary
#: account (1): guessing it is privileged would invent a boundary, and a BFLA
#: finding built on an invented boundary is noise.
ROLE_RANKS: dict[str, int] = {
    "guest": 0, "anonymous": 0, "viewer": 0, "readonly": 0, "read_only": 0,
    "read-only": 0, "reader": 0,
    "user": 1, "member": 1, "customer": 1,
    "editor": 2, "manager": 2, "staff": 2, "support": 2, "moderator": 2,
    "operator": 2,
    "admin": 3, "administrator": 3, "superuser": 3, "root": 3, "superadmin": 3,
}

#: The rank an unrecognised role name gets.
DEFAULT_RANK = 1

#: The top of the scale. An explicit rank uses the same 0..3 scale as the role
#: names, so a scan that mixes explicit and inferred ranks still orders sanely —
#: an "editor" ranked 50 next to an inferred admin (3) would invert BFLA.
MAX_PRIVILEGE = 3


#: Role names that say the identity may read but not write. A check that must
#: *create* something (mass assignment, race) learns nothing from a caller the
#: API refuses every write to — it gets a 403 and tests no field or limit.
READ_ONLY_ROLES = frozenset(
    {"guest", "anonymous", "viewer", "readonly", "read_only", "read-only", "reader"}
)


def is_read_only_role(role: str) -> bool:
    return role.strip().lower() in READ_ONLY_ROLES


def privilege_rank(role: str, privilege: int | None = None) -> int:
    """An identity's privilege: the explicit rank when set, else by role name."""
    if privilege is not None:
        return privilege
    return ROLE_RANKS.get(role.strip().lower(), DEFAULT_RANK)
