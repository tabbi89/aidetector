"""The one rule for "is this operation privileged".

Two implementations used to exist and had diverged — ``authz.py`` matched six
scope tokens, ``write_oracle.py`` matched only ``admin`` — so an endpoint scoped
``staff:write`` was a privileged-function bug to BFLA and an ordinary
object-level bug, one severity tier lower, to the write oracle. The matrix below
is the union, which is the correct reading: a scope naming staff, internal or
superuser access is privileged wherever it is observed.

Grown from ``test_char_privilege.py``, which recorded the two implementations
disagreeing. The disagreement rows below flipped from ``(True, False)`` to
``True`` when they were unified — that diff is the record of what changed in
what the scanner reports.
"""
from __future__ import annotations

import pytest

from app.domain.privilege import PRIVILEGE_TOKENS, is_privileged
from app.engine.checks.authz import BflaCheck
from app.engine.checks.write_oracle import WriteOracleCheck

#: (path, auth_scope, privileged?) — one rule, one answer.
MATRIX: list[tuple[str, str | None, bool]] = [
    # --- the path names /admin -------------------------------------------
    ("/admin/users/{id}", None, True),
    ("/admin/users/{id}", "admin:write", True),
    ("/ADMIN/users", None, True),
    # --- the scope names privileged access -------------------------------
    ("/users/{id}", "admin", True),
    # These five were True for the authz checks and False for the write
    # oracle before the rules were unified. They are the reason this file
    # exists.
    ("/users/{id}", "superuser", True),
    ("/users/{id}", "root", True),
    ("/users/{id}", "manage:users", True),
    ("/users/{id}", "staff:write", True),
    ("/users/{id}", "internal", True),
    # --- nothing privileged ----------------------------------------------
    ("/users/{id}", "user:read", False),
    ("/users/{id}", None, False),
    ("/users/{id}", "", False),
    # A privileged-*looking* path with no scope is not privileged: only
    # "/admin" is matched in the path. A path segment is not a security
    # decision the way a declared scope is, so the other tokens are not
    # matched there — "/manage-account" and "/internal-notes" would be
    # flagged on wording alone.
    ("/internal/jobs", None, False),
    ("/staff/reports", None, False),
    # The "/admin" path test is slash-anchored, so this is not a match even
    # though "badminton" contains the substring "admin".
    ("/badminton/courts", None, False),
    ("/administrative-area", None, False),
    ("/administer", None, False),
]


@pytest.mark.parametrize(("path", "scope", "expected"), MATRIX)
def test_is_privileged(path: str, scope: str | None, expected: bool) -> None:
    assert is_privileged(path, scope) is expected


@pytest.mark.parametrize("token", PRIVILEGE_TOKENS)
def test_every_declared_token_is_honoured(token: str) -> None:
    """A token in the tuple that the function ignores is a silent coverage hole."""
    assert is_privileged("/things/{id}", f"{token}:write") is True


def test_both_checks_now_share_one_rule() -> None:
    """The regression guard: one definition, not two that drift again.

    Asserted structurally rather than behaviourally — a second module-level
    ``_is_privileged`` would not fail any other test until its answers diverged,
    which is exactly how the original defect survived.
    """
    import app.engine.checks.authz as authz
    import app.engine.checks.write_oracle as write_oracle

    for module in (authz, write_oracle):
        assert module.is_privileged is is_privileged
        assert not hasattr(module, "_is_privileged"), (
            f"{module.__name__} declares a private privilege rule again — that is "
            "how the two definitions diverged the first time."
        )
    # The checks that consume it are still wired up.
    assert BflaCheck().key == "bfla"
    assert WriteOracleCheck().key == "write_authz"
