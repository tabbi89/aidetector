"""Credential names are unique within a scan.

Local-run secrets and finding evidence both address an identity by name, so a
duplicate name would make one of the two unreachable.
"""
from __future__ import annotations


def _add(client, scan_id, name: str):
    return client.post(
        f"/scans/{scan_id}/credentials",
        json={
            "name": name,
            "role": "user",
            "auth_type": "bearer",
            "secret": f"{name}-token",
        },
    )


def test_duplicate_credential_name_is_rejected(client, scan_with_spec):
    sid = scan_with_spec()
    assert _add(client, sid, "alice").status_code == 201

    response = _add(client, sid, "alice")
    assert response.status_code == 409
    assert "alice" in response.json()["detail"]


def test_renaming_onto_an_existing_name_is_rejected(client, scan_with_spec):
    sid = scan_with_spec()
    alice = _add(client, sid, "alice").json()
    bob = _add(client, sid, "bob").json()

    response = client.patch(
        f"/scans/{sid}/credentials/{bob['id']}",
        json={"name": "alice", "role": "user", "auth_type": "bearer"},
    )
    assert response.status_code == 409
    assert "alice" in response.json()["detail"]

    profiles = {
        row["id"]: row["name"]
        for row in client.get(f"/scans/{sid}").json()["credential_profiles"]
    }
    assert profiles[alice["id"]] == "alice"
    assert profiles[bob["id"]] == "bob"
