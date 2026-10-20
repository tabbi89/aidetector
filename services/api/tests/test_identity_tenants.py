"""Identities can say which tenant (workspace) they belong to.

Without it, BOLA paired identities by privilege alone: a workspace's editor
and viewer reading the same monitor — the API working as designed — was
reported as a verified cross-identity read. With tenants declared, object-level
checks pair across tenants and function-level checks pair within one.
"""
from __future__ import annotations

from dataclasses import replace

from app.engine.base import TargetOperation
from app.engine.checks.authz import BflaCheck, BolaCheck
from tests import factories


def _cred(name: str, role: str, tenant: str | None):
    return replace(factories.credential(name, role), tenant=tenant)


A_READ = _cred("workspace-a-read", "viewer", "a")
A_WRITE = _cred("workspace-a-write", "editor", "a")
B_WRITE = _cred("workspace-b-write", "editor", "b")


def _ctx(creds):
    return factories.scan_context(factories.engine_operations(), credentials=creds)


def test_object_level_pairs_across_tenants_and_function_level_within_one() -> None:
    ctx = _ctx([A_READ, A_WRITE, B_WRITE])
    pair = ctx.identity_pair()
    assert pair is not None
    # The attacker is the other tenant's most privileged key: the pair differs
    # by tenant, not by role, and a write oracle's attacker can write.
    assert (pair.owner.name, pair.attacker.name) == ("workspace-a-write", "workspace-b-write")
    bfla = ctx.privilege_pair()
    assert bfla is not None
    assert (bfla.owner.name, bfla.attacker.name) == ("workspace-a-write", "workspace-a-read")
    assert [c.name for c in ctx.lower_privileged(A_WRITE)] == ["workspace-a-read"]


def test_one_tenant_has_no_cross_tenant_pair_and_says_what_to_add() -> None:
    ctx = _ctx([A_READ, A_WRITE])
    assert ctx.identity_pair() is None
    assert "add one from another tenant" in ctx.pair_gap()
    assert ctx.privilege_pair() is not None


def test_undeclared_tenants_keep_privilege_pairing() -> None:
    ctx = _ctx([_cred("alice", "user", None), _cred("admin", "admin", None)])
    pair = ctx.identity_pair()
    assert pair is not None and (pair.owner.name, pair.attacker.name) == ("admin", "alice")
    assert ctx.privilege_pair() == pair


def test_identities_without_a_tenant_sit_out_tenant_pairing() -> None:
    ctx = _ctx([A_WRITE, _cred("stray", "editor", None)])
    assert ctx.identity_pair() is None


def test_two_keys_of_one_workspace_reading_its_object_is_not_bola() -> None:
    # vulnapp serves /accounts/{id} to any authenticated caller, so alice and
    # admin reading the same account is BOLA between tenants — and the API
    # working when both are one tenant's keys.
    op = TargetOperation(
        id="op-account", method="GET", path="/accounts/{account_id}",
        params=[{"name": "account_id", "in": "path", "required": True}],
    )
    alice, admin = factories.two_identities()
    across = factories.run_one(
        BolaCheck(), [op],
        credentials=[replace(alice, tenant="a"), replace(admin, tenant="b")],
    )
    assert any(f.severity == "high" for f in across if f.check == "bola")
    within = factories.run_one(
        BolaCheck(), [op],
        credentials=[replace(alice, tenant="a"), replace(admin, tenant="a")],
    )
    assert not any(f.severity == "high" for f in within if f.check == "bola")


def test_bfla_explains_itself_when_no_tenant_has_two_identities() -> None:
    ctx = _ctx([A_WRITE, B_WRITE])
    reason = BflaCheck.inapplicable(ctx)
    assert reason is not None and "same tenant" in reason


def test_tenant_round_trips_through_the_api_and_the_local_claim(
    client, scan_with_spec, monkeypatch
) -> None:
    from app.core.config import settings

    monkeypatch.setattr(settings, "local_runner_enabled", True)
    sid = scan_with_spec("http://127.0.0.1")
    r = client.post(f"/scans/{sid}/credentials", json={
        "name": "workspace-b-write", "role": "editor", "auth_type": "bearer",
        "tenant": "b", "local_only": True,
    })
    assert r.status_code in (200, 201), r.text
    creds = client.get(f"/scans/{sid}").json()["credential_profiles"]
    assert [c["tenant"] for c in creds] == ["b"]
    claim = client.post(f"/scans/{sid}/local-runs", json={"authorized": True}).json()
    assert [c["tenant"] for c in claim["credentials"]] == ["b"]


def test_bfla_names_the_real_reason_it_did_not_run() -> None:
    plain = [TargetOperation(id="m", method="PATCH", path="/monitors/{id}",
                             params=[{"name": "id", "in": "path", "required": True}])]
    ctx = factories.scan_context(plain, credentials=[A_READ, A_WRITE], allow_mutation=True)
    reason = BflaCheck.inapplicable(ctx)
    assert reason is not None and "admin-only" in reason and "write_authz" in reason
    admin_write = [TargetOperation(id="a", method="POST", path="/admin/users", params=[])]
    ctx = factories.scan_context(admin_write, credentials=[A_READ, A_WRITE], allow_mutation=False)
    reason = BflaCheck.inapplicable(ctx)
    assert reason is not None and "writes to the target are off" in reason


def test_create_probes_use_the_lowest_identity_that_may_write() -> None:
    # mass_assignment and race_condition must create to test anything; a
    # read-only key answers every create with 403.
    ctx = _ctx([A_READ, A_WRITE, B_WRITE])
    writer = ctx.lowest_writer()
    assert writer is not None and writer.name == "workspace-a-write"
    only_readers = _ctx([A_READ, _cred("guest", "guest", "a")])
    assert only_readers.lowest_writer() is not None  # falls back rather than none
