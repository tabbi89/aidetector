"""Token-minting grants: the scanner obtains its own token before scanning.

A static credential carries a token that expires; a grant mints a fresh one at
scan time from the target's own auth endpoint. These drive `ResolvedCredential.
mint` against small in-process auth servers — the same shape a real OAuth token
endpoint or cookie login has.
"""
from __future__ import annotations

from fastapi import Body, FastAPI, Form, Header
from fastapi.responses import JSONResponse
from fastapi.testclient import TestClient

from app.domain.enums import AuthType, GrantType
from app.engine.base import ResolvedCredential


def _oauth_app() -> FastAPI:
    app = FastAPI()

    @app.post("/oauth/token")
    def token(
        grant_type: str = Form(...),
        client_id: str = Form(default=""),
        client_secret: str = Form(default=""),
        username: str = Form(default=""),
        password: str = Form(default=""),
        scope: str = Form(default=""),
    ):
        if grant_type == "client_credentials" and client_id == "svc" and client_secret == "sh":
            return {"access_token": "cc-token", "token_type": "bearer"}
        if grant_type == "password" and username == "alice" and password == "pw":
            return {"access_token": "pw-token"}
        return JSONResponse({"error": "invalid_grant"}, status_code=400)

    @app.get("/data")
    def data(authorization: str | None = Header(default=None)):
        ok = authorization in ("Bearer cc-token", "Bearer pw-token")
        return JSONResponse({"ok": ok}, status_code=200 if ok else 401)

    return app


# ---- static is unchanged -------------------------------------------------------

def test_static_grant_is_a_noop():
    cred = ResolvedCredential("u", "user", AuthType.bearer, None, "the-token")
    assert cred.mint(TestClient(_oauth_app())) is True
    assert cred.secret == "the-token"  # untouched


# ---- client_credentials --------------------------------------------------------

def test_client_credentials_mints_a_bearer():
    cred = ResolvedCredential(
        "svc", "service", AuthType.bearer, None, "sh",  # secret = client_secret
        grant_type=GrantType.client_credentials,
        token_url="/oauth/token",
        grant_params={"client_id": "svc"},
    )
    assert cred.mint(TestClient(_oauth_app())) is True
    assert cred.auth_type == AuthType.bearer
    assert cred.secret == "cc-token"
    assert cred.headers() == {"Authorization": "Bearer cc-token"}


def test_password_grant_mints_a_bearer():
    cred = ResolvedCredential(
        "u", "user", AuthType.bearer, None, "pw",  # secret = password
        grant_type=GrantType.password,
        token_url="/oauth/token",
        grant_params={"username": "alice"},
    )
    assert cred.mint(TestClient(_oauth_app())) is True
    assert cred.secret == "pw-token"


def test_a_custom_access_token_field_is_honoured():
    app = FastAPI()

    @app.post("/t")
    def t(grant_type: str = Form(...), client_id: str = Form(default=""),
          client_secret: str = Form(default="")):
        return {"jwt": "weird-field-token"}

    cred = ResolvedCredential(
        "svc", "s", AuthType.bearer, None, "x",
        grant_type=GrantType.client_credentials, token_url="/t",
        grant_params={"client_id": "svc", "access_token_field": "jwt"},
    )
    assert cred.mint(TestClient(app)) is True
    assert cred.secret == "weird-field-token"


# ---- cookie login --------------------------------------------------------------

def test_cookie_grant_captures_the_session_cookie():
    app = FastAPI()

    @app.post("/login")
    def login(payload: dict = Body(default={})):
        if payload.get("username") == "alice" and payload.get("password") == "pw":
            r = JSONResponse({"ok": True})
            r.set_cookie("session", "sess-abc")
            return r
        return JSONResponse({"ok": False}, status_code=401)

    cred = ResolvedCredential(
        "u", "user", AuthType.bearer, None, "pw",  # secret = password
        grant_type=GrantType.cookie,
        token_url="/login",
        grant_params={"username": "alice", "cookie_name": "session"},
    )
    assert cred.mint(TestClient(app)) is True
    assert cred.auth_type == AuthType.header
    assert cred.header_name == "Cookie"
    assert cred.headers() == {"Cookie": "session=sess-abc"}


def test_cookie_grant_supports_form_login():
    app = FastAPI()

    @app.post("/login")
    def login(username: str = Form(...), password: str = Form(...)):
        r = JSONResponse({"ok": True})
        if username == "bob" and password == "s3cret":
            r.set_cookie("sid", "xyz")
        return r

    cred = ResolvedCredential(
        "u", "user", AuthType.bearer, None, "s3cret",
        grant_type=GrantType.cookie, token_url="/login",
        grant_params={"username": "bob", "format": "form", "cookie_name": "sid"},
    )
    assert cred.mint(TestClient(app)) is True
    assert cred.headers() == {"Cookie": "sid=xyz"}


# ---- failure never raises, and degrades to "not ready" -------------------------

def test_bad_credentials_return_false_not_raise():
    cred = ResolvedCredential(
        "svc", "s", AuthType.bearer, None, "wrong-secret",
        grant_type=GrantType.client_credentials, token_url="/oauth/token",
        grant_params={"client_id": "svc"},
    )
    assert cred.mint(TestClient(_oauth_app())) is False


def test_missing_token_url_is_false():
    cred = ResolvedCredential(
        "svc", "s", AuthType.bearer, None, "sh",
        grant_type=GrantType.client_credentials, token_url=None,
        grant_params={"client_id": "svc"},
    )
    assert cred.mint(TestClient(_oauth_app())) is False


def test_an_unreachable_endpoint_is_false_not_an_exception():
    class Boom:
        def request(self, *a, **k):
            raise ConnectionError("target down")

    cred = ResolvedCredential(
        "svc", "s", AuthType.bearer, None, "sh",
        grant_type=GrantType.client_credentials, token_url="/oauth/token",
        grant_params={"client_id": "svc"},
    )
    assert cred.mint(Boom()) is False


# ---- end to end: a minted token actually authenticates -------------------------

def test_a_minted_token_authenticates_a_request():
    from app.engine.base import HttpProbe

    client = TestClient(_oauth_app())
    cred = ResolvedCredential(
        "svc", "service", AuthType.bearer, None, "sh",
        grant_type=GrantType.client_credentials, token_url="/oauth/token",
        grant_params={"client_id": "svc"},
    )
    assert cred.mint(client) is True
    probe = HttpProbe(client, credentials=[cred])
    r = probe.send("GET", "/data", headers=cred.headers())
    assert r is not None and r.status == 200


# ---- header-name sanitization ------------------------------------------------


def test_header_auth_falls_back_when_name_is_invalid():
    # "Authorization Basic" (space in the name) is an illegal HTTP header name.
    cred = ResolvedCredential("api", "admin", AuthType.header, "Authorization Basic", "tok")
    assert cred.headers() == {"Authorization": "tok"}


def test_header_auth_rejects_crlf_injection_in_name():
    cred = ResolvedCredential("api", "admin", AuthType.header, "Authorization\r\nX-Evil: 1", "tok")
    assert cred.headers() == {"Authorization": "tok"}


def test_header_auth_keeps_a_valid_name():
    cred = ResolvedCredential("api", "admin", AuthType.header, "X-API-Key", "tok")
    assert cred.headers() == {"X-API-Key": "tok"}


def test_credential_schema_rejects_invalid_header_name():
    import pytest
    from pydantic import ValidationError

    from app.api.schemas import CredentialCreate

    with pytest.raises(ValidationError):
        CredentialCreate(
            name="c", role="admin", auth_type=AuthType.header,
            header_name="Authorization Basic", secret="tok",
        )
