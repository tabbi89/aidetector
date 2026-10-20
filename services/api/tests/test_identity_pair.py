"""Which checks run for which credential sets.

Four cross-identity checks used to decide independently what a usable pair of
identities was, and they disagreed: the authz checks treated identities as
distinct by ``name`` while ``write_oracle`` and ``seeded_bola`` required distinct
``role`` values and returned ``[]`` otherwise.

``highest_priv``/``lowest_priv`` are ``max``/``min`` over a role-score dict that
scores unknown roles alike, so two credentials sharing a role collapse to the
*same* object — and those two checks then silently produced nothing on a normal
shape for a multi-tenant API with no role hierarchy, which is precisely where
cross-tenant BOLA lives.

Every cross-identity check now calls one ``ScanContext.identity_pair()``, so the
``two_same_role`` row matches the distinct-roles row: two credentials with
different names are two identities whatever they are labelled, and a scan that
opted into ``mutate`` exercises them.

Grown from ``test_char_identity_pair.py``, which recorded the four divergent
rules. The ``two_same_role`` row flipping from 0 to 1 for ``write_authz`` and
``seeded_bola`` is the record of what changed.
"""
from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from app.engine.base import HttpProbe, ResolvedCredential, ScanContext, TargetOperation
from app.engine.checks.authz import BflaCheck, BolaCheck
from app.engine.checks.mass_assignment import MassAssignmentCheck
from app.engine.checks.seeded_bola import SeededBolaCheck
from app.engine.checks.write_oracle import WriteOracleCheck
from tests import factories
from tests.factories import credential
from tests.vulnapp import vulnapp

#: Credential shapes a real scan can be given. ``two_same_role`` is the one that
#: exposes the divergence: two distinct identities, one role label.
CREDENTIAL_SETS: dict[str, list[ResolvedCredential]] = {
    "none": [],
    "one": [credential("alice", "user")],
    "two_distinct_roles": [credential("admin", "admin"), credential("alice", "user")],
    "two_same_role": [credential("alice", "user"), credential("bob", "user")],
    "three": [credential("admin", "admin"), credential("alice", "user"), credential("bob", "user")],
}


def _path(name: str) -> list[dict]:
    return [{"name": name, "in": "path", "required": True}]


def _body(name: str) -> list[dict]:
    return [{"name": name, "in": "body", "required": False, "schema": {"type": "string"}}]


def _op(op_id: str, method: str, path: str, params: list[dict] | None = None):
    return TargetOperation(id=op_id, method=method, path=path, params=params or [])


#: The minimal operation set each check needs to reach a finding on vulnapp.
OPERATIONS: dict[str, list[TargetOperation]] = {
    "bola": [
        _op("a-get", "GET", "/accounts/{account_id}", _path("account_id")),
        _op("a-list", "GET", "/accounts"),
    ],
    "bfla": [_op("promote", "POST", "/admin/users/{user_id}/promote", _path("user_id"))],
    "write_authz": [
        _op("w-get", "GET", "/widgets/{widget_id}", _path("widget_id")),
        _op("w-put", "PUT", "/widgets/{widget_id}", _path("widget_id") + _body("name")),
    ],
    "seeded_bola": [
        _op("r-post", "POST", "/records", _body("body")),
        _op("r-get", "GET", "/records/{record_id}", _path("record_id")),
        _op("r-del", "DELETE", "/records/{record_id}", _path("record_id")),
    ],
    "mass_assignment": [
        _op("w-get", "GET", "/widgets/{widget_id}", _path("widget_id")),
        _op("w-put", "PUT", "/widgets/{widget_id}", _path("widget_id") + _body("name")),
    ],
}

CHECKS = {
    "bola": BolaCheck,
    "bfla": BflaCheck,
    "write_authz": WriteOracleCheck,
    "seeded_bola": SeededBolaCheck,
    "mass_assignment": MassAssignmentCheck,
}

#: Column order for the rows below.
COLUMNS = ("bola", "bfla", "write_authz", "seeded_bola", "mass_assignment")

#: Findings each check produces today, per credential set, with mutate:true on.
#:
#: ``two_same_role`` matches ``two_distinct_roles`` — that equality is the fix.
#: ``mass_assignment`` never differed: it takes one identity, not a pair.
_ROWS: dict[str, tuple[int, int, int, int, int]] = {
    #                      bola  bfla  write  seeded  mass
    "none":               (   0,    0,     0,      0,    0),
    "one":                (   1,    0,     0,      0,    2),
    "two_distinct_roles": (   1,    1,     1,      1,    2),
    "two_same_role":      (   1,    0,     1,      1,    2),
    "three":              (   1,    1,     1,      1,    2),
}

#: credential set -> check key -> expected finding count.
MATRIX: dict[str, dict[str, int]] = {
    label: dict(zip(COLUMNS, counts, strict=True)) for label, counts in _ROWS.items()
}

#: The checks that need a distinct pair, including BFLA's function-boundary oracle.
PAIR_DEPENDENT = ("write_authz", "seeded_bola")


def test_bfla_requires_a_real_privilege_boundary() -> None:
    assert _run("bfla", CREDENTIAL_SETS["two_distinct_roles"]) == 1
    assert _run("bfla", CREDENTIAL_SETS["two_same_role"]) == 0


def _run(check_key: str, creds: list[ResolvedCredential]) -> int:
    ops = OPERATIONS[check_key]
    ctx = factories.scan_context(
        ops,
        credentials=creds,
        probe=HttpProbe(TestClient(vulnapp), operations=ops),
        allow_mutation=True,
    )
    return len(CHECKS[check_key]().run(ctx))


@pytest.mark.parametrize("creds_label", sorted(CREDENTIAL_SETS))
@pytest.mark.parametrize("check_key", sorted(CHECKS))
def test_identity_matrix(check_key: str, creds_label: str) -> None:
    expected = MATRIX[creds_label][check_key]
    assert _run(check_key, CREDENTIAL_SETS[creds_label]) == expected


@pytest.mark.parametrize("check_key", PAIR_DEPENDENT)
def test_same_role_credentials_are_still_two_identities(check_key: str) -> None:
    """The regression guard for the defect this file grew out of.

    Two credentials with different names are two identities however they are
    labelled. Requiring distinct *roles* disabled these checks entirely on APIs
    with no role hierarchy — and did it silently, sending no request at all.
    """
    assert _run(check_key, CREDENTIAL_SETS["two_distinct_roles"]) == 1
    assert _run(check_key, CREDENTIAL_SETS["two_same_role"]) == 1


@pytest.mark.parametrize("check_key", PAIR_DEPENDENT)
def test_a_single_identity_still_no_ops(check_key: str) -> None:
    """One credential genuinely cannot support a cross-identity oracle.

    It must no-op rather than compare an identity with itself — and the runner
    emits ``identities_unavailable`` so the report says why (see
    ``test_char_stage_order.py``).
    """
    ops = OPERATIONS[check_key]
    ctx = factories.scan_context(
        ops,
        credentials=CREDENTIAL_SETS["one"],
        probe=HttpProbe(TestClient(vulnapp), operations=ops),
        allow_mutation=True,
    )
    before = ctx.probe.count
    assert CHECKS[check_key]().run(ctx) == []
    assert ctx.probe.count == before   # no requests spent on an impossible check


def test_privilege_ranking_collapses_for_equal_roles() -> None:
    """The mechanism behind the matrix, pinned directly.

    ``highest_priv`` and ``lowest_priv`` return the *same* credential when roles
    tie, which is what the ``role ==`` guards then reject.
    """
    ctx = ScanContext(
        base_url="http://t",
        operations=[],
        credentials=CREDENTIAL_SETS["two_same_role"],
        probe=HttpProbe(TestClient(vulnapp)),
    )
    assert ctx.highest_priv() is ctx.lowest_priv()
    assert ctx.highest_priv().name == "alice"
    # ...whereas distinct roles rank apart, which is why that row still works.
    ranked = ScanContext(
        base_url="http://t",
        operations=[],
        credentials=CREDENTIAL_SETS["two_distinct_roles"],
        probe=HttpProbe(TestClient(vulnapp)),
    )
    assert ranked.highest_priv().role == "admin"
    assert ranked.lowest_priv().role == "user"
