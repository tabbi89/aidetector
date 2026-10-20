"""Identity setup for public, single-key and multi-role APIs.

Three things a user should not have to work around: a spec that already says
how its API authenticates (auth hints), roles whose names the heuristic does
not know (explicit privilege), and keys that ride in the query string or a
cookie rather than a header.
"""
from __future__ import annotations

import json
from types import SimpleNamespace

import pytest

from app.domain.enums import AuthType, Confidence, GrantType
from app.domain.privilege import privilege_rank
from app.engine.base import HttpProbe, ResolvedCredential, TargetOperation
from app.engine.checks.authz import BflaCheck
from app.engine.credentials import QUERY_KEY_HEADER_PREFIX, wire_kwargs
from app.specs.auth_hints import derive_auth_hints
from tests import factories

# ---- auth hints ----------------------------------------------------------------


def _spec(security_schemes=None, *, security=None, paths=None):
    spec = {
        "openapi": "3.0.0",
        "info": {"title": "t", "version": "1"},
        "paths": paths or {"/items": {"get": {"responses": {"200": {"description": "ok"}}}}},
    }
    if security_schemes is not None:
        spec["components"] = {"securitySchemes": security_schemes}
    if security is not None:
        spec["security"] = security
    return spec


def test_a_spec_with_no_security_is_suggested_public():
    hints = derive_auth_hints(_spec())
    assert hints.suggested == "public"
    assert hints.operations == 1 and hints.protected_operations == 0
    assert hints.schemes == ()


def test_a_bearer_spec_is_suggested_one_key():
    hints = derive_auth_hints(
        _spec({"bearerAuth": {"type": "http", "scheme": "bearer"}},
              security=[{"bearerAuth": []}])
    )
    assert hints.suggested == "single"
    assert hints.protected_operations == 1
    assert hints.schemes[0].auth_type == AuthType.bearer


@pytest.mark.parametrize(
    ("raw", "auth_type", "name"),
    [
        ({"type": "apiKey", "in": "header", "name": "X-Api-Token"}, AuthType.api_key,
         "X-Api-Token"),
        ({"type": "apiKey", "in": "header", "name": "Authorization"}, AuthType.header,
         "Authorization"),
        ({"type": "apiKey", "in": "query", "name": "api_key"}, AuthType.query, "api_key"),
        ({"type": "apiKey", "in": "cookie", "name": "sid"}, AuthType.cookie, "sid"),
        ({"type": "http", "scheme": "basic"}, AuthType.basic, None),
        ({"type": "openIdConnect", "openIdConnectUrl": "https://x/.well-known"},
         AuthType.bearer, None),
    ],
)
def test_each_scheme_maps_to_the_channel_it_declares(raw, auth_type, name):
    hint = derive_auth_hints(_spec({"s": raw}, security=[{"s": []}])).schemes[0]
    assert (hint.auth_type, hint.header_name) == (auth_type, name)


def test_oauth_client_credentials_prefills_a_grant():
    scheme = {
        "type": "oauth2",
        "flows": {
            "authorizationCode": {"authorizationUrl": "https://a", "tokenUrl": "https://t0",
                                  "scopes": {"read": ""}},
            "clientCredentials": {"tokenUrl": "https://auth.example/token",
                                  "scopes": {"admin:write": "", "read": ""}},
        },
    }
    hint = derive_auth_hints(_spec({"oauth": scheme}, security=[{"oauth": ["read"]}])).schemes[0]
    assert hint.grant_type == GrantType.client_credentials
    assert hint.token_url == "https://auth.example/token"
    assert hint.scopes == ("read", "admin:write")


def test_swagger2_definitions_are_read():
    spec = {
        "swagger": "2.0",
        "info": {"title": "t", "version": "1"},
        "securityDefinitions": {"key": {"type": "apiKey", "in": "query", "name": "k"}},
        "security": [{"key": []}],
        "paths": {"/a": {"get": {"responses": {"200": {"description": "ok"}}}}},
    }
    hints = derive_auth_hints(spec)
    assert hints.schemes[0].auth_type == AuthType.query
    assert hints.protected_operations == 1


def test_admin_scopes_suggest_roles():
    paths = {
        "/items": {"get": {"responses": {}}},
        "/users": {"delete": {"security": [{"b": ["admin:write"]}], "responses": {}}},
    }
    hints = derive_auth_hints(
        _spec({"b": {"type": "http", "scheme": "bearer"}}, security=[{"b": []}], paths=paths)
    )
    assert hints.suggested == "roles"
    assert [(r.name, r.privilege) for r in hints.roles] == [("user", 1), ("admin", 3)]


def test_optional_security_does_not_count_as_protected():
    # ``[{}]`` alongside a scheme means auth is optional on that operation.
    hints = derive_auth_hints(
        _spec({"b": {"type": "http", "scheme": "bearer"}}, security=[{}, {"b": []}])
    )
    assert hints.protected_operations == 0
    # A declared scheme means the API knows about keys, so not "public".
    assert hints.suggested == "single"


def test_the_used_scheme_is_listed_first():
    schemes = {
        "a_unused": {"type": "http", "scheme": "basic"},
        "z_used": {"type": "http", "scheme": "bearer"},
    }
    hints = derive_auth_hints(_spec(schemes, security=[{"z_used": []}]))
    assert hints.schemes[0].name == "z_used"


# ---- privilege ---------------------------------------------------------------


def test_explicit_privilege_outranks_the_role_name():
    assert privilege_rank("admin", 0) == 0
    assert privilege_rank("viewer") == 0
    assert privilege_rank("editor") == 2
    assert privilege_rank("whatever") == 1


def _cred(name: str, role: str, privilege: int | None = None) -> ResolvedCredential:
    return ResolvedCredential(
        name=name, role=role, auth_type=AuthType.header, header_name="Authorization",
        secret=f"{name}-token", privilege=privilege,
    )


def test_identity_pair_uses_explicit_privilege():
    # Unknown role names: without explicit ranks there is no boundary at all.
    creds = [_cred("ops", "owner", 9), _cred("pat", "tenant", 1)]
    ctx = factories.scan_context([], credentials=creds)
    pair = ctx.identity_pair()
    assert pair is not None
    assert (pair.owner.name, pair.attacker.name) == ("ops", "pat")
    assert BflaCheck.inapplicable(
        factories.scan_context(
            [TargetOperation(id="a", method="GET", path="/admin/x")], credentials=creds
        )
    ) is None


def _tiered_client(allowed: set[str]):
    """``/admin/report`` refuses anonymous callers and every token not in ``allowed``."""

    class Client:
        def request(self, method, url, **kwargs):
            token = (kwargs.get("headers") or {}).get("Authorization")
            if url == "/admin/report":
                status = 200 if token in allowed else (401 if token is None else 403)
            else:
                status = 404
            body = json.dumps({"ok": status == 200})
            return SimpleNamespace(
                status_code=status, headers={}, text=body, content=body.encode()
            )

    return Client()


def _run_bfla(allowed: set[str]):
    op = TargetOperation(id="r", method="GET", path="/admin/report")
    creds = [_cred("vic", "viewer"), _cred("eddie", "editor"), _cred("root", "admin")]
    probe = HttpProbe(_tiered_client(allowed), operations=[op], credentials=creds)
    ctx = factories.scan_context([op], credentials=creds, probe=probe)
    return BflaCheck().run(ctx)


def test_bfla_reaches_a_middle_tier_the_extremes_hide():
    findings = _run_bfla({"eddie-token", "root-token"})
    assert len(findings) == 1
    assert findings[0].evidence["identity"] == "eddie"
    # The spec says privileged, not which tier: a middle-tier hit is a lead.
    assert findings[0].confidence == Confidence.heuristic


def test_bfla_bottom_tier_stays_verified():
    findings = _run_bfla({"vic-token", "eddie-token", "root-token"})
    assert len(findings) == 1
    assert findings[0].evidence["identity"] == "vic"
    assert findings[0].confidence == Confidence.verified


def test_bfla_quiet_when_only_the_top_tier_gets_in():
    assert _run_bfla({"root-token"}) == []


# ---- query and cookie keys ---------------------------------------------------


def _key(auth_type: AuthType, name: str = "api_key") -> ResolvedCredential:
    return ResolvedCredential(
        name="k", role="user", auth_type=auth_type, header_name=name, secret="s3cr3t"
    )


def test_cookie_key_is_sent_as_a_cookie():
    assert _key(AuthType.cookie, "sid").headers() == {"Cookie": "sid=s3cr3t"}


def test_query_key_moves_into_the_query_string_only_on_the_wire():
    headers = _key(AuthType.query).headers()
    assert list(headers) == [QUERY_KEY_HEADER_PREFIX + b"api_key".hex()]
    wire = wire_kwargs({"headers": {**headers, "Accept": "x"}, "params": {"q": "1"}})
    assert wire["params"] == {"q": "1", "api_key": "s3cr3t"}
    assert wire["headers"] == {"Accept": "x"}


def test_wire_kwargs_is_a_no_op_without_a_query_key():
    kwargs = {"headers": {"Authorization": "Bearer x"}, "params": {}}
    assert wire_kwargs(kwargs) is kwargs


def test_a_query_key_reaches_the_target_and_never_the_trace():
    cred = _key(AuthType.query)
    seen: list[dict] = []

    class Client:
        def request(self, method, url, **kwargs):
            seen.append(kwargs)
            return SimpleNamespace(status_code=200, headers={}, text="{}", content=b"{}")

    op = TargetOperation(id="i", method="GET", path="/items")
    probe = HttpProbe(Client(), operations=[op], credentials=[cred])
    probe.send("GET", "/items", headers=cred.headers())

    assert seen[0]["params"] == {"api_key": "s3cr3t"}
    assert not any(k.lower().startswith("x-aidetector-query") for k in seen[0]["headers"])
    row = probe.mutations[0]
    # The trace still knows who sent it, and holds no copy of the key.
    assert row["identity"] == "k"
    assert "s3cr3t" not in json.dumps(row)


def test_a_key_name_that_is_not_a_token_sends_nothing():
    assert _key(AuthType.query, "bad name").headers() == {}


# ---- API ------------------------------------------------------------------------

BEARER_SPEC = json.dumps(
    _spec({"bearerAuth": {"type": "http", "scheme": "bearer"}}, security=[{"bearerAuth": []}])
)


def test_spec_auth_hints_route(client):
    r = client.post("/specs/auth-hints", json={"spec": BEARER_SPEC})
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["suggested"] == "single"
    assert body["schemes"][0]["auth_type"] == "bearer"


def test_spec_auth_hints_rejects_garbage(client):
    assert client.post("/specs/auth-hints", json={"spec": "[1, 2"}).status_code == 422


def test_scan_auth_hints_route(client, new_scan):
    scan_id = new_scan()
    assert client.get(f"/scans/{scan_id}/auth-hints").status_code == 409
    assert client.post(f"/scans/{scan_id}/spec", json={"content": BEARER_SPEC}).status_code == 200
    r = client.get(f"/scans/{scan_id}/auth-hints")
    assert r.status_code == 200, r.text
    assert r.json()["protected_operations"] == 1


def test_credential_privilege_and_query_channel_round_trip(client, new_scan):
    scan_id = new_scan()
    r = client.post(
        f"/scans/{scan_id}/credentials",
        json={"name": "reader", "role": "viewer", "privilege": 0, "auth_type": "query",
              "header_name": "api_key", "secret": "k"},
    )
    assert r.status_code == 201, r.text
    assert (r.json()["privilege"], r.json()["auth_type"]) == (0, "query")
    assert "secret" not in r.json()


@pytest.mark.parametrize("auth_type", ["query", "cookie"])
def test_query_and_cookie_need_a_name(client, new_scan, auth_type):
    r = client.post(
        f"/scans/{new_scan()}/credentials",
        json={"name": "n", "role": "user", "auth_type": auth_type, "secret": "k"},
    )
    assert r.status_code == 422


# ---- hardening (architect review) -----------------------------------------------


def _alias_bomb(depth: int) -> str:
    """A few hundred bytes of YAML whose ``str()`` would be 10**depth nodes."""
    lines = ['a0: &a0 ["x","x","x","x","x","x","x","x","x","x"]']
    for i in range(1, depth + 1):
        refs = ",".join([f"*a{i - 1}"] * 10)
        lines.append(f"a{i}: &a{i} [{refs}]")
    return "\n".join(lines)


def test_auth_hints_never_expand_an_alias_bomb():
    import time

    import yaml

    depth = 9  # ~10**9 nodes if anything stringified it
    text = (
        _alias_bomb(depth)
        + "\nopenapi: 3.0.0\ninfo: {title: t, version: '1'}\n"
        + f"components:\n  securitySchemes:\n    k: {{type: *a{depth}, in: *a{depth}}}\n"
        + f"security: [{{k: *a{depth}}}]\n"
        + f"paths:\n  /x: {{get: {{security: [{{k: *a{depth}}}], responses: {{}}}}}}\n"
    )
    assert len(text) < 2000
    data = yaml.safe_load(text)
    start = time.perf_counter()
    hints = derive_auth_hints(data)
    assert time.perf_counter() - start < 1.0
    assert hints.schemes == ()  # a non-string type is no scheme at all


def test_spec_auth_hints_route_survives_an_alias_bomb(client):
    depth = 9
    text = (
        _alias_bomb(depth)
        + "\nopenapi: 3.0.0\ninfo: {title: t, version: '1'}\n"
        + f"paths:\n  /x: {{get: {{security: [{{k: *a{depth}}}], responses: {{}}}}}}\n"
    )
    r = client.post("/specs/auth-hints", json={"spec": text})
    assert r.status_code == 200, r.text


def test_an_encoded_query_secret_is_masked():
    from app.core.redact import Redactor

    secret = "ab+cd/ef=="
    redactor = Redactor([secret])
    echoed = '{"next": "/items?page=2&api_key=ab%2Bcd%2Fef%3D%3D"}'
    assert "ab%2Bcd%2Fef%3D%3D" not in redactor.text(echoed)
    late = Redactor()
    late.add_secret(secret)
    assert "ab%2Bcd%2Fef%3D%3D" not in late.text(echoed)


def test_sqlmap_request_file_carries_a_query_key_in_the_query_only(tmp_path):
    from contextlib import ExitStack

    from app.engine.sqlmap_confirm import SqlmapConfirmer

    cred = _key(AuthType.query)
    target = {"param": "q", "request": {"headers": cred.headers(), "params": {"q": "1"}}}
    url = "http://target.test/items?q=1"
    with ExitStack() as stack:
        command = SqlmapConfirmer("sqlmap").target_command(target, url, stack)
        raw = open(command[command.index("-r") + 1], newline="").read()
    first, *headers = raw.split("\r\n")
    assert first == "GET /items?q=1&api_key=s3cr3t HTTP/1.1"
    assert not any(h.lower().startswith("x-aidetector-query") for h in headers)
    assert "s3cr3t" not in url  # the evidence URL never carries it


def test_bfla_two_bottom_rank_accounts_are_the_same_tier():
    op = TargetOperation(id="r", method="GET", path="/admin/report")
    creds = [_cred("alice", "user"), _cred("bob", "user"), _cred("root", "admin")]
    probe = HttpProbe(
        _tiered_client({"bob-token", "root-token"}), operations=[op], credentials=creds
    )
    ctx = factories.scan_context([op], credentials=creds, probe=probe)
    [finding] = BflaCheck().run(ctx)
    assert finding.evidence["identity"] == "bob"
    assert finding.confidence == Confidence.verified


def test_privilege_uses_the_role_name_scale(client, new_scan):
    r = client.post(
        f"/scans/{new_scan()}/credentials",
        json={"name": "n", "role": "editor", "privilege": 50, "auth_type": "bearer",
              "secret": "k"},
    )
    assert r.status_code == 422
