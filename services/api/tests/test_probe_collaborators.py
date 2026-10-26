"""The two concerns split out of HttpProbe: attribution and 401 recovery.

The probe owns the request budget, which is a stated safety ceiling. It used to
own three other things in the same locked block — path matching, per-check
attribution for the report, and refresh-and-replay on a 401 — so a change to the
coverage report was a change to the DoS guard.

They are collaborators now (``engine/coverage.py``, ``engine/reauth.py``) and
testable on their own, which is the point of the split.
"""
from __future__ import annotations

from typing import Any

from fastapi.testclient import TestClient

from app.domain.enums import AuthType
from app.engine.base import HttpProbe, ResolvedCredential
from app.engine.coverage import CoverageRecorder, path_matcher
from app.engine.reauth import ReauthPolicy
from tests import factories

# ---- attribution --------------------------------------------------------------


def test_matcher_treats_a_variable_as_exactly_one_segment():
    m = path_matcher("/a/{id}")
    assert m.match("/a/7")
    assert not m.match("/a/7/b")
    assert not m.match("/a")


def test_exact_paths_win_over_templated_ones():
    """`/things/count` must attribute to itself, not to `/things/{id}`."""
    ops = [
        factories.operation("GET", "/things/{id}", id="tmpl"),
        factories.operation("GET", "/things/count", id="exact", params=[]),
    ]
    rec = CoverageRecorder(ops)
    assert rec.operation_id("GET", "/things/count") == "exact"
    assert rec.operation_id("GET", "/things/42") == "tmpl"


def test_unmatched_paths_are_simply_not_attributed():
    """A traversal payload in a path segment must not be mis-assigned."""
    rec = CoverageRecorder([factories.operation("GET", "/a/{id}", id="a")])
    assert rec.operation_id("GET", "/completely/other") is None
    assert rec.operation_id("POST", "/a/1") is None      # method matters


def test_note_counts_per_check():
    rec = CoverageRecorder([factories.operation("GET", "/a/{id}", id="a")])
    rec.note("a", "bola")
    rec.note("a", "bola")
    rec.note("a", "bfla")
    rec.note("a", None)          # a request with no check context
    assert rec.per_operation["a"] == {"bola": 2, "bfla": 1, "?": 1}


def test_attribution_never_refuses_anything():
    """The recorder is observational — it has no way to say no.

    Pinned structurally: if it grows a method that can reject a request, the
    budget and the report are entangled again.
    """
    rec = CoverageRecorder([])
    public = {n for n in dir(rec) if not n.startswith("_")}
    # All observational: resolve an operation, count a request, count a response
    # outcome. None can refuse a request, so the budget and the report stay apart.
    assert public == {
        "operation_id", "note", "note_result", "per_operation", "outcomes",
    }


# ---- 401 recovery -------------------------------------------------------------


class _Resp:
    def __init__(self, status: int, text: str = "") -> None:
        self.status_code = status
        self.text = text
        self.headers: dict[str, str] = {}

    def json(self) -> Any:
        return {"access_token": "fresh-token"}


class _Client:
    """Records requests; answers the refresh endpoint with a new token."""

    def __init__(self) -> None:
        self.sent: list[tuple[str, str]] = []

    def request(self, method: str, url: str, **kwargs: Any) -> _Resp:
        self.sent.append((method, url))
        return _Resp(200)


def _cred(secret: str = "old-token"):
    from app.engine.base import ResolvedCredential

    return ResolvedCredential(
        name="alice", role="user", auth_type=AuthType.bearer,
        header_name=None, secret=secret,
        refresh_url="/auth/refresh", refresh_secret="refresh-me",
    )


def test_refreshes_the_credential_that_failed_and_replays():
    cred, client = _cred(), _Client()
    policy = ReauthPolicy([cred], client, lambda m, p: True)

    out = policy.retry(
        "GET", "/a", {"headers": {}}, {"Authorization": "Bearer old-token"}, _Resp(401)
    )
    assert out.status_code == 200
    assert ("POST", "/auth/refresh") in client.sent
    assert ("GET", "/a") in client.sent
    assert cred.secret == "fresh-token"


def test_refresh_registers_the_new_token_for_redaction():
    cred, client = _cred(), _Client()
    recorded: list[str] = []
    policy = ReauthPolicy(
        [cred], client, lambda m, p: True, record_secret=recorded.append
    )

    policy.retry(
        "GET", "/a", {"headers": {}}, {"Authorization": "Bearer old-token"}, _Resp(401)
    )

    assert recorded == ["fresh-token"]


def test_an_unconfigured_custom_header_is_left_alone():
    client = _Client()
    original = _Resp(401)
    policy = ReauthPolicy([_cred()], client, lambda m, p: True)
    assert policy.retry("GET", "/a", {}, {"X-API-Key": "k"}, original) is original
    assert client.sent == []


def test_refreshes_api_key_on_its_configured_header():
    from app.engine.base import ResolvedCredential

    credential = ResolvedCredential(
        name="service",
        role="user",
        auth_type=AuthType.api_key,
        header_name="X-API-Key",
        secret="expired-key",
        refresh_url="/auth/refresh",
        refresh_secret="refresh-me",
    )
    client = _Client()
    policy = ReauthPolicy([credential], client, lambda m, p: True)

    result = policy.retry(
        "GET", "/a", {"headers": {}}, {"X-API-Key": "expired-key"}, _Resp(401)
    )

    assert result.status_code == 200
    assert credential.secret == "fresh-token"
    assert client.sent == [("POST", "/auth/refresh"), ("GET", "/a")]


def test_an_unknown_token_is_left_alone():
    """Only a token this scan is carrying can be refreshed."""
    client = _Client()
    original = _Resp(401)
    policy = ReauthPolicy([_cred("mine")], client, lambda m, p: True)
    out = policy.retry("GET", "/a", {}, {"Authorization": "Bearer someone-elses"}, original)
    assert out is original
    assert client.sent == []


def test_a_spent_budget_stops_the_refresh():
    """Refresh and replay are real requests — neither is free."""
    client = _Client()
    original = _Resp(401)
    policy = ReauthPolicy([_cred()], client, lambda m, p: False)
    out = policy.retry("GET", "/a", {}, {"Authorization": "Bearer old-token"}, original)
    assert out is original
    assert client.sent == []


def test_a_refresh_that_raises_returns_the_original_401():
    class _Boom(_Client):
        def request(self, method: str, url: str, **kwargs: Any):
            raise RuntimeError("network gone")

    original = _Resp(401)
    policy = ReauthPolicy([_cred()], _Boom(), lambda m, p: True)
    out = policy.retry("GET", "/a", {}, {"Authorization": "Bearer old-token"}, original)
    assert out is original


def test_probe_auto_refreshes_expired_bearer():
    from fastapi import Body, FastAPI, Header
    from fastapi.responses import JSONResponse

    app = FastAPI()

    @app.get("/data")
    def data(authorization: str | None = Header(default=None)):
        if authorization == "Bearer new-access":
            return {"ok": True}
        return JSONResponse({"detail": "expired"}, status_code=401)

    @app.post("/token")
    def token(payload: dict = Body(default={})):
        if payload.get("refresh_token") == "rt-secret":
            return {"access_token": "new-access"}
        return JSONResponse({"detail": "bad"}, status_code=400)

    cred = ResolvedCredential(
        "u", "user", AuthType.bearer, None, "old-expired",
        refresh_url="/token", refresh_secret="rt-secret",
    )
    probe = HttpProbe(TestClient(app), credentials=[cred])
    r = probe.send("GET", "/data", headers=cred.headers())
    assert r is not None and r.status == 200  # refreshed then retried
    assert cred.secret == "new-access"  # token rotated in place


def test_probe_auto_refreshes_expired_custom_api_key():
    from fastapi import Body, FastAPI, Header
    from fastapi.responses import JSONResponse

    app = FastAPI()

    @app.get("/data")
    def data(x_api_key: str | None = Header(default=None)):
        if x_api_key == "new-access":
            return {"ok": True}
        return JSONResponse({"detail": "expired"}, status_code=401)

    @app.post("/token")
    def token(payload: dict = Body(default={})):
        if payload.get("refresh_token") == "rt-secret":
            return {"access_token": "new-access"}
        return JSONResponse({"detail": "bad"}, status_code=400)

    cred = ResolvedCredential(
        "u",
        "user",
        AuthType.api_key,
        "X-API-Key",
        "old-expired",
        refresh_url="/token",
        refresh_secret="rt-secret",
    )
    probe = HttpProbe(TestClient(app), credentials=[cred])
    result = probe.send("GET", "/data", headers=cred.headers())

    assert result is not None and result.status == 200
    assert cred.secret == "new-access"
    assert probe.mutations[-1]["request"]["headers"] == {
        "x-api-key": "<redacted>"
    }


def test_probe_no_refresh_without_config():
    from fastapi import FastAPI, Header
    from fastapi.responses import JSONResponse

    app = FastAPI()

    @app.get("/data")
    def data(authorization: str | None = Header(default=None)):
        return JSONResponse({"detail": "expired"}, status_code=401)

    cred = ResolvedCredential("u", "user", AuthType.bearer, None, "old")
    probe = HttpProbe(TestClient(app), credentials=[cred])
    r = probe.send("GET", "/data", headers=cred.headers())
    assert r is not None and r.status == 401  # no refresh_url → left as-is
    assert cred.secret == "old"
