"""Local-only identities: the shape lives on the server, the secret never does.

A CLI run (every one is local) supplies every secret to its own runner container, so
the server needs an identity's name, role and auth shape, but not its secret.
These tests pin the three halves of that promise: the API refuses a secret on a
local-only identity (accepting and discarding it would still have carried it
over the wire), an edit cannot quietly add one, and a server-side run leaves the
identity out by name instead of failing or sending an empty credential.
"""
from __future__ import annotations

from types import SimpleNamespace

from app.domain.enums import AuthType, GrantType
from app.engine import runner


def _local(name: str = "alice", role: str = "user") -> dict:
    return {"name": name, "role": role, "auth_type": "bearer", "local_only": True}


def test_a_local_only_identity_is_created_without_a_secret(client, new_scan):
    scan_id = new_scan()
    r = client.post(f"/scans/{scan_id}/credentials", json=_local())
    assert r.status_code == 201, r.text
    assert r.json()["local_only"] is True
    shown = client.get(f"/scans/{scan_id}").json()["credential_profiles"]
    assert [(c["name"], c["local_only"]) for c in shown] == [("alice", True)]


def test_a_local_only_identity_refuses_a_secret(client, new_scan):
    scan_id = new_scan()
    r = client.post(f"/scans/{scan_id}/credentials", json={**_local(), "secret": "tok"})
    assert r.status_code == 422
    r = client.post(
        f"/scans/{scan_id}/credentials", json={**_local(), "refresh_secret": "rt"}
    )
    assert r.status_code == 422
    assert client.get(f"/scans/{scan_id}").json()["credential_profiles"] == []


def test_an_ordinary_identity_still_needs_a_secret(client, new_scan):
    scan_id = new_scan()
    body = {"name": "bob", "role": "user", "auth_type": "bearer"}
    assert client.post(f"/scans/{scan_id}/credentials", json=body).status_code == 422
    r = client.post(f"/scans/{scan_id}/credentials", json={**body, "secret": "tok"})
    assert r.status_code == 201
    assert r.json()["local_only"] is False


def test_an_edit_cannot_put_a_secret_on_a_local_only_identity(client, new_scan, db_session):
    from app.models.credential import CredentialProfile

    scan_id = new_scan()
    cred = client.post(f"/scans/{scan_id}/credentials", json=_local()).json()
    shape = {"name": "alice", "role": "admin", "auth_type": "bearer"}
    r = client.patch(f"/scans/{scan_id}/credentials/{cred['id']}", json={**shape, "secret": "tok"})
    assert r.status_code == 409
    assert "local-only" in r.json()["detail"]

    # A shape-only edit is still allowed, and the identity stays secretless.
    r = client.patch(f"/scans/{scan_id}/credentials/{cred['id']}", json=shape)
    assert r.status_code == 200, r.text
    row = db_session.get(CredentialProfile, cred["id"])
    assert row.local_only is True
    assert row.secret_ref == ""
    assert row.role == "admin"


def test_a_server_run_leaves_a_local_only_identity_out():
    stored = SimpleNamespace(
        name="admin", role="admin", auth_type=AuthType.bearer, header_name=None,
        secret_ref="", refresh_url=None, refresh_secret_ref=None,
        refresh_token_field="refresh_token", access_token_field="access_token",
        grant_type=GrantType.static, token_url=None, grant_params={}, local_only=True,
    )
    resolved, unreadable = runner._resolve_credentials(
        SimpleNamespace(credential_profiles=[stored])
    )
    # Neither resolved with an empty secret nor misreported as a vault problem.
    assert resolved == []
    assert unreadable == []


def test_a_server_run_names_the_identity_it_left_out(db_session, make_scan, engine_client):
    from app.engine.runner import run_scan

    scan = make_scan()
    admin = next(c for c in scan.credential_profiles if c.role == "admin")
    admin.local_only, admin.secret_ref = True, ""
    db_session.commit()

    run_scan(db_session, scan, client=engine_client)

    assert scan.status.value == "completed"
    left_out = [e for e in scan.events if e.stage == "credential_local_only"]
    assert len(left_out) == 1
    assert f"'{admin.name}' is local-only" in left_out[0].message


def test_a_run_that_left_identities_out_does_not_call_their_findings_fixed(
    db_session, make_scan, engine_client
):
    """A server run without the identities cannot have re-tested BOLA."""
    from app.engine.runner import run_scan
    from app.scans.run_options import unperformed

    scan = make_scan()
    for c in scan.credential_profiles:
        c.local_only, c.secret_ref = True, ""
    db_session.commit()

    run_scan(db_session, scan, client=engine_client)

    gaps = scan.runs[-1].gaps
    assert sorted(gaps["identities_missing"]) == sorted(c.name for c in scan.credential_profiles)
    for check in ("bola", "bfla", "broken_auth", "seeded_bola", "write_authz"):
        assert unperformed(check, gaps), check
    # A check that needs no identity still counts as re-tested.
    assert not unperformed("security_headers", gaps)
    message = next(e.message for e in scan.events if e.stage == "identities_unavailable")
    assert "a CLI run (`runpentests run`)" in message


def test_the_local_only_flag_is_in_the_audit_trail(client, new_scan):
    scan_id = new_scan()
    client.post(f"/scans/{scan_id}/credentials", json=_local())
    rows = client.get("/workspace/audit").json()
    added = [r for r in rows if r["action"] == "credential.added"]
    assert added and added[0]["summary"]["local_only"] is True
