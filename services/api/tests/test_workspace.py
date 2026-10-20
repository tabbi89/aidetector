"""Workspace membership, roles, tokens, audit and person attribution."""
from __future__ import annotations

import uuid

from app.core.config import settings
from app.domain.enums import Severity
from app.models.finding import Finding


def _member(client, email: str, role: str = "analyst") -> dict:
    response = client.post(
        "/workspace/members",
        json={
            "email": email,
            "display_name": email.split("@")[0],
            "role": role,
        },
    )
    assert response.status_code == 201, response.text
    return response.json()


def _token(client, user_id: str, label: str = "test") -> dict:
    response = client.post(
        "/workspace/tokens",
        json={"user_id": user_id, "label": label},
    )
    assert response.status_code == 201, response.text
    return response.json()


def _auth(token: str) -> dict[str, str]:
    return {"X-API-Key": token}


def _live_finding(db_session, scan, fingerprint: str = "fp-bola"):
    db_session.add(
        Finding(
            scan_id=scan.id,
            check="bola",
            severity=Severity.high,
            title="Fixture finding",
            fingerprint=fingerprint,
        )
    )
    db_session.commit()


def test_open_workspace_is_the_default_admin(client):
    body = client.get("/workspace").json()

    assert body["tenant"] == "default"
    assert body["role"] == "admin"
    assert body["members"] == 0
    assert body["user"] is None


def test_members_are_assignable_and_roles_change(client):
    alice = _member(client, "alice@example.com", "analyst")
    assert _member(client, "bob@example.com", "viewer")["role"] == "viewer"

    duplicate = client.post(
        "/workspace/members",
        json={
            "email": "ALICE@example.com",
            "display_name": "Alice again",
            "role": "viewer",
        },
    )
    assert duplicate.status_code == 409

    changed = client.patch(
        f"/workspace/members/{alice['user_id']}",
        json={"role": "admin"},
    )
    assert changed.status_code == 200, changed.text
    assert changed.json()["role"] == "admin"

    members = client.get("/workspace/members").json()
    assert {m["email"] for m in members} == {"alice@example.com", "bob@example.com"}


def test_the_last_admin_cannot_be_removed(client):
    admin = _member(client, "only@example.com", "admin")

    response = client.delete(f"/workspace/members/{admin['user_id']}")

    assert response.status_code == 409
    assert "at least one admin" in response.json()["detail"]


def test_tokens_carry_roles_and_viewers_are_read_only(client):
    viewer = _member(client, "viewer@example.com", "viewer")
    viewer_token = _token(client, viewer["user_id"])

    status = client.get(
        "/auth/status", headers=_auth(viewer_token["token"])
    ).json()
    assert status["role"] == "viewer"
    assert status["user"]["email"] == "viewer@example.com"
    assert client.get("/scans", headers=_auth(viewer_token["token"])).status_code == 200
    assert (
        client.post(
            "/scans",
            json={"target_base_url": "http://127.0.0.1"},
            headers=_auth(viewer_token["token"]),
        ).status_code
        == 403
    )

    analyst = _member(client, "analyst@example.com", "analyst")
    analyst_token = _token(client, analyst["user_id"])
    created = client.post(
        "/scans",
        json={"target_base_url": "http://127.0.0.1"},
        headers=_auth(analyst_token["token"]),
    )
    assert created.status_code == 201, created.text
    scan_id = created.json()["id"]
    assert (
        client.delete(
            f"/scans/{scan_id}", headers=_auth(analyst_token["token"])
        ).status_code
        == 403
    )

    admin = _member(client, "admin@example.com", "admin")
    admin_token = _token(client, admin["user_id"])
    assert (
        client.delete(
            f"/scans/{scan_id}", headers=_auth(admin_token["token"])
        ).status_code
        == 200
    )


def test_a_revoked_token_is_refused(client):
    member = _member(client, "revoked@example.com")
    token = _token(client, member["user_id"])
    assert (
        client.get("/auth/status", headers=_auth(token["token"])).status_code == 200
    )

    assert client.delete(f"/workspace/tokens/{token['id']}").status_code == 200
    assert (
        client.get("/auth/status", headers=_auth(token["token"])).status_code == 401
    )


def test_audit_records_members_and_tokens_without_secrets(client):
    member = _member(client, "audit@example.com", "analyst")
    token = _token(client, member["user_id"])

    rows = client.get("/workspace/audit").json()
    actions = {row["action"] for row in rows}
    assert {"member.added", "token.created"} <= actions
    assert any(
        row["summary"].get("email") == "audit@example.com" for row in rows
    )
    assert token["token"] not in str(rows)


def test_tokens_and_scans_are_tenant_scoped(client, monkeypatch):
    monkeypatch.setattr(settings, "api_keys", "acme:key-a,beta:key-b")

    created = client.post(
        "/scans",
        json={"target_base_url": "http://127.0.0.1"},
        headers=_auth("key-a"),
    )
    assert created.status_code == 201, created.text
    scan_id = created.json()["id"]

    assert [
        row["id"]
        for row in client.get("/scans", headers=_auth("key-a")).json()
    ] == [scan_id]
    assert client.get("/scans", headers=_auth("key-b")).json() == []


def test_work_owner_must_be_a_workspace_member(client, make_scan, db_session):
    member = _member(client, "owner@example.com", "analyst")
    scan = make_scan()
    _live_finding(db_session, scan)

    response = client.put(
        f"/scans/{scan.id}/findings/fp-bola/work",
        json={"owner_user_id": member["user_id"]},
    )
    assert response.status_code == 200, response.text
    assert response.json()["owner_user_id"] == member["user_id"]
    assert response.json()["owner"] == "owner"

    stranger = client.put(
        f"/scans/{scan.id}/findings/fp-bola/work",
        json={"owner_user_id": str(uuid.uuid4())},
    )
    assert stranger.status_code == 422


def test_comments_are_attributed_to_the_person(client, make_scan, db_session):
    member = _member(client, "commenter@example.com", "analyst")
    token = _token(client, member["user_id"])
    scan = make_scan()
    _live_finding(db_session, scan)

    response = client.post(
        f"/scans/{scan.id}/findings/fp-bola/comments",
        json={"body": "Please confirm this one."},
        headers=_auth(token["token"]),
    )

    assert response.status_code == 201, response.text
    assert response.json()["author"] == "commenter"
    assert response.json()["author_user_id"] == member["user_id"]
