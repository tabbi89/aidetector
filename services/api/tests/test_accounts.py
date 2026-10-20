"""Password sign-in, self-service sign-up and the admin approval queue."""
from __future__ import annotations

from datetime import UTC, datetime, timedelta

from sqlalchemy import select

from app.core import passwords
from app.core.config import settings
from app.manage import main as manage
from app.models.identity import ApiToken, AuditLog, AuthThrottle, Membership, User
from app.scans import accounts, throttle

ADMIN = "admin@example.com"
ADMIN_PW = "correct horse battery"
PW = "a long enough secret"


def _admin(db_session) -> None:
    accounts.bootstrap_admin(
        db_session, email=ADMIN, display_name="Admin", password=ADMIN_PW
    )
    db_session.commit()


def _login(client, email: str = ADMIN, password: str = ADMIN_PW):
    return client.post("/auth/login", json={"email": email, "password": password})


def _session(client, email: str = ADMIN, password: str = ADMIN_PW) -> dict:
    response = _login(client, email, password)
    assert response.status_code == 200, response.text
    return {"X-API-Key": response.json()["token"]}


def _signup(client, email: str, password: str = PW):
    return client.post(
        "/auth/signup",
        json={"email": email, "display_name": email.split("@")[0], "password": password},
    )


# ---- hashing --------------------------------------------------------------------

def test_password_hash_round_trips_and_rejects_garbage():
    stored = passwords.hash_password("hunter2hunter2")

    assert stored.startswith("scrypt$")
    assert "hunter2" not in stored
    assert passwords.verify_password("hunter2hunter2", stored)
    assert not passwords.verify_password("hunter2hunter3", stored)
    assert not passwords.verify_password("x", "scrypt$broken")
    assert not passwords.verify_password("x", None)
    assert not passwords.needs_rehash(stored)


# ---- the admin and the open posture -------------------------------------------

def test_admin_signs_in_and_the_open_api_closes(client, db_session):
    assert client.get("/auth/status").status_code == 200  # open dev posture

    _admin(db_session)

    # A password admin exists: an anonymous caller is no longer an admin.
    anonymous = client.get("/auth/status")
    assert anonymous.status_code == 401
    assert client.get("/workspace").status_code == 401

    response = _login(client, "  ADMIN@example.com ", ADMIN_PW)
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["role"] == "admin"
    assert body["tenant"] == "default"
    assert body["user"]["email"] == ADMIN
    assert datetime.fromisoformat(body["expires_at"]) > datetime.now(UTC)

    status = client.get("/auth/status", headers={"X-API-Key": body["token"]})
    assert status.status_code == 200
    assert status.json()["auth_required"] is True
    assert status.json()["user"]["email"] == ADMIN


def test_wrong_password_and_unknown_email_get_one_answer(client, db_session):
    _admin(db_session)

    wrong = _login(client, ADMIN, "not the password")
    unknown = _login(client, "nobody@example.com", ADMIN_PW)

    assert wrong.status_code == unknown.status_code == 401
    assert wrong.json() == unknown.json() == {"detail": "invalid email or password"}


def test_passwords_need_six_to_256_characters(client):
    assert _signup(client, "five@example.com", "12345").status_code == 422
    assert _signup(client, "six@example.com", "123456").status_code == 202
    assert _signup(client, "long@example.com", "x" * 257).status_code == 422


def test_validation_errors_never_echo_the_password(client):
    response = _signup(client, "short@example.com", "tiny5")

    assert response.status_code == 422
    assert "tiny5" not in response.text


def test_sessions_expire_and_sign_out_revokes_only_the_session(client, db_session):
    _admin(db_session)
    headers = _session(client)
    api_token = client.post(
        "/workspace/tokens",
        headers=headers,
        json={"user_id": str(db_session.scalar(select(User.id))), "label": "ci"},
    ).json()

    # Sessions are not workspace credentials and stay off the token list.
    listed = client.get("/workspace/tokens", headers=headers).json()
    assert [t["label"] for t in listed] == ["ci"]

    assert client.post("/auth/logout", headers=headers).json() == {"status": "signed_out"}
    assert client.get("/workspace", headers=headers).status_code == 401

    # Signing out through an API token does not revoke it.
    api_headers = {"X-API-Key": api_token["token"]}
    assert client.post("/auth/logout", headers=api_headers).status_code == 200
    assert client.get("/workspace", headers=api_headers).status_code == 200

    expired = _session(client)
    db_session.expire_all()
    for row in db_session.scalars(select(ApiToken).where(ApiToken.kind == "session")):
        row.expires_at = datetime.now(UTC) - timedelta(minutes=1)
    db_session.commit()
    assert client.get("/workspace", headers=expired).status_code == 401


# ---- sign-up and approval -------------------------------------------------------

def test_signup_waits_for_approval_then_signs_in_with_the_granted_role(
    client, db_session
):
    _admin(db_session)
    admin = _session(client)

    assert _signup(client, "Dana@Example.com").status_code == 202
    assert _login(client, "dana@example.com", PW).json() == {
        "detail": "your account is awaiting approval"
    }
    assert _login(client, "dana@example.com", "wrong password!").status_code == 401

    pending = client.get("/workspace/signups", headers=admin).json()
    assert [p["email"] for p in pending] == ["dana@example.com"]
    assert "password" not in str(pending)

    approved = client.post(
        f"/workspace/signups/{pending[0]['user_id']}/approve",
        headers=admin,
        json={"role": "viewer"},
    )
    assert approved.status_code == 200, approved.text
    assert approved.json()["role"] == "viewer"
    assert client.get("/workspace/signups", headers=admin).json() == []

    dana = _session(client, "dana@example.com", PW)
    assert client.get("/workspace", headers=dana).json()["role"] == "viewer"
    # Approved members are not admins: the queue is closed to them.
    assert client.get("/workspace/signups", headers=dana).status_code == 403

    actions = set(db_session.scalars(select(AuditLog.action)))
    assert {"signup.approved", "session.started"} <= actions


def test_a_rejected_request_is_deleted_and_may_ask_again(client, db_session):
    _admin(db_session)
    admin = _session(client)
    _signup(client, "eve@example.com")
    user_id = client.get("/workspace/signups", headers=admin).json()[0]["user_id"]

    assert client.delete(f"/workspace/signups/{user_id}", headers=admin).json() == {
        "status": "rejected"
    }
    assert _login(client, "eve@example.com", PW).status_code == 401
    assert client.delete(f"/workspace/signups/{user_id}", headers=admin).status_code == 404
    assert _signup(client, "eve@example.com").status_code == 202


def test_signup_never_touches_an_existing_account(client, db_session):
    _admin(db_session)
    admin = _session(client)
    member = client.post(
        "/workspace/members",
        headers=admin,
        json={"email": "frank@example.com", "display_name": "Frank", "role": "analyst"},
    )
    assert member.status_code == 201

    # Same answer as a new email, but no password is planted on Frank or the admin.
    assert _signup(client, "frank@example.com").status_code == 202
    assert _signup(client, ADMIN, "attacker chosen pw").status_code == 202

    assert _login(client, "frank@example.com", PW).status_code == 401
    assert _login(client, ADMIN, "attacker chosen pw").status_code == 401
    assert _login(client, ADMIN, ADMIN_PW).status_code == 200
    assert client.get("/workspace/signups", headers=admin).json() == []


def test_a_removed_member_cannot_sign_in(client, db_session):
    _admin(db_session)
    admin = _session(client)
    _signup(client, "gil@example.com")
    user_id = client.get("/workspace/signups", headers=admin).json()[0]["user_id"]
    client.post(f"/workspace/signups/{user_id}/approve", headers=admin, json={})
    gil = _session(client, "gil@example.com", PW)

    assert client.delete(f"/workspace/members/{user_id}", headers=admin).status_code == 200

    # Removing the membership cascades its sessions away and blocks new ones.
    assert client.get("/workspace", headers=gil).status_code == 401
    assert _login(client, "gil@example.com", PW).json() == {
        "detail": "your account has no workspace access"
    }


# ---- the operator command -------------------------------------------------------

def test_create_admin_command_creates_then_resets(db_session, monkeypatch, capsys):
    import io

    monkeypatch.setattr("sys.stdin", io.StringIO("first password!!\n"))
    assert manage(["create-admin", "--email", "Op@Example.com", "--password-stdin"]) == 0
    monkeypatch.setattr("sys.stdin", io.StringIO("second password!!\n"))
    assert manage(["create-admin", "--email", "op@example.com", "--password-stdin"]) == 0
    monkeypatch.setattr("sys.stdin", io.StringIO("short\n"))
    assert manage(["create-admin", "--email", "op@example.com", "--password-stdin"]) == 2

    db_session.expire_all()
    user = db_session.scalar(select(User).where(User.email == "op@example.com"))
    assert user is not None
    assert passwords.verify_password("second password!!", user.password_hash)
    roles = list(db_session.scalars(select(Membership.role).where(Membership.user_id == user.id)))
    assert roles == ["admin"]
    assert "second password" not in capsys.readouterr().out


# ---- brute-force limits ---------------------------------------------------------

def _age_counters(db_session, seconds: int) -> None:
    db_session.expire_all()
    for row in db_session.scalars(select(AuthThrottle)):
        row.window_start = row.window_start - timedelta(seconds=seconds)
    db_session.commit()


def test_a_locked_email_refuses_even_the_right_password(client, db_session, monkeypatch):
    monkeypatch.setattr(settings, "auth_login_failures_per_email", 3)
    _admin(db_session)

    assert [_login(client, ADMIN, "wrong").status_code for _ in range(3)] == [401] * 3
    locked = _login(client, ADMIN, ADMIN_PW)
    assert locked.status_code == 429
    assert locked.json() == {"detail": "too many attempts; try again later"}
    assert 0 < int(locked.headers["Retry-After"]) <= settings.auth_login_window_seconds

    # The window closes on its own, and a success resets the count.
    _age_counters(db_session, settings.auth_login_window_seconds)
    assert _login(client, ADMIN, ADMIN_PW).status_code == 200
    assert db_session.scalar(select(AuthThrottle).where(
        AuthThrottle.bucket == throttle.login_email(ADMIN).bucket
    )) is None


def test_an_unknown_email_locks_exactly_like_a_real_one(client, db_session, monkeypatch):
    monkeypatch.setattr(settings, "auth_login_failures_per_email", 2)
    _admin(db_session)

    real = [_login(client, ADMIN, "wrong").status_code for _ in range(3)]
    ghost = [_login(client, "ghost@example.com", "wrong").status_code for _ in range(3)]

    assert real == ghost == [401, 401, 429]
    # No email is stored in clear, registered or not.
    buckets = list(db_session.scalars(select(AuthThrottle.bucket)))
    assert not any("@" in b for b in buckets)


def test_failures_across_emails_lock_the_client_address(client, db_session, monkeypatch):
    monkeypatch.setattr(settings, "auth_login_failures_per_ip", 3)
    _admin(db_session)

    spray = [_login(client, f"u{i}@example.com", "wrong").status_code for i in range(3)]
    assert spray == [401] * 3
    assert _login(client, ADMIN, ADMIN_PW).status_code == 429


def test_signups_are_capped_per_address_before_any_account_is_made(
    client, db_session, monkeypatch
):
    monkeypatch.setattr(settings, "auth_signups_per_ip", 2)

    codes = [_signup(client, f"s{i}@example.com").status_code for i in range(3)]

    assert codes == [202, 202, 429]
    emails = set(db_session.scalars(select(User.email)))
    assert emails == {"s0@example.com", "s1@example.com"}


def test_resetting_the_admin_lifts_their_lockout(client, db_session, monkeypatch):
    monkeypatch.setattr(settings, "auth_login_failures_per_email", 1)
    _admin(db_session)
    _login(client, ADMIN, "wrong")
    assert _login(client, ADMIN, ADMIN_PW).status_code == 429

    _admin(db_session)

    assert _login(client, ADMIN, ADMIN_PW).status_code == 200


def test_prune_drops_only_closed_windows(client, db_session):
    _login(client, "old@example.com", "wrong")
    _age_counters(db_session, 2 * settings.auth_signup_window_seconds)
    _login(client, "new@example.com", "wrong")

    # The address bucket restarted its window on the second attempt.
    assert throttle.prune(db_session) == 1
    db_session.commit()
    remaining = set(db_session.scalars(select(AuthThrottle.bucket)))
    assert remaining == {
        throttle.login_email("new@example.com").bucket,
        throttle.login_ip("testclient").bucket,
    }
