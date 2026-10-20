"""A tiny in-process vulnerable app for engine tests.

Mirrors the deliberate flaws in services/target/vulnbank so the engine can be
driven deterministically via a Starlette TestClient — no network, no live server.
"""
from __future__ import annotations

import asyncio

from fastapi import Body, FastAPI, Form, Header, Request
from fastapi.responses import HTMLResponse, JSONResponse, Response

vulnapp = FastAPI()

#: Seed state for every mutable store below. The mutating checks (write oracle,
#: mass assignment, enumeration) change these, so ``reset_state`` puts them back
#: between tests — the in-process target gets the same isolation the database
#: does, and a test can never depend on what a previous one left behind.
_SEED_ACCOUNTS = {
    1: {"id": 1, "owner": "alice", "balance": 42000},
    2: {"id": 2, "owner": "admin", "balance": 9900000},
}
# `owner` and `role` are server-owned state the spec never declares as input,
# and put_widget below binds the whole body — the mass-assignment shape.
_SEED_WIDGETS = {1: {"id": 1, "name": "original", "owner": "admin", "role": "user"}}


def reset_state() -> None:
    """Restore every mutable store to its seed. Called by an autouse fixture."""
    _ACCOUNTS.clear()
    _ACCOUNTS.update({k: dict(v) for k, v in _SEED_ACCOUNTS.items()})
    _WIDGETS.clear()
    _WIDGETS.update({k: dict(v) for k, v in _SEED_WIDGETS.items()})
    _SIGNUPS.clear()
    _ORDERS.clear()
    _ORDER_REFS.clear()
    _RECORDS.clear()
    _PROJECTS.clear()
    _PROJECT_ITEMS.clear()
    _CHECKOUTS.clear()
    _INVOICE_SEQ["n"] = 0
    OUTBOUND.clear()


_ACCOUNTS = {
    1: {"id": 1, "owner": "alice", "balance": 42000},
    2: {"id": 2, "owner": "admin", "balance": 9900000},
}


@vulnapp.get("/accounts/{account_id}")
def get_account(account_id: int, authorization: str | None = Header(default=None)):
    # VULN: any non-empty token accepted; no owner check (BOLA + broken auth).
    if not authorization:
        return JSONResponse({"detail": "missing token"}, status_code=401)
    return _ACCOUNTS.get(account_id, {"id": account_id, "owner": "?", "balance": 0})


# A BOLA whose response carries a per-read timestamp, so two identities reading
# the same object get different *raw* bodies. The engine's raw-body comparison
# used to miss this; the normalised comparison in authz.py must still find it.
_INVOICE_SEQ = {"n": 0}


@vulnapp.get("/invoices/{invoice_id}")
def get_invoice(invoice_id: int, authorization: str | None = Header(default=None)):
    # VULN: auth enforced (anon rejected) but no owner check — object-level authz
    # missing — AND a volatile `updated_at` that changes on every read.
    if not authorization:
        return JSONResponse({"detail": "missing token"}, status_code=401)
    _INVOICE_SEQ["n"] += 1
    return {"id": invoice_id, "amount": 100, "updated_at": _INVOICE_SEQ["n"]}


@vulnapp.post("/admin/users/{user_id}/promote")
def promote(user_id: int, authorization: str | None = Header(default=None)):
    # VULN: privileged, no role check (BFLA).
    if not authorization:
        return JSONResponse({"detail": "missing token"}, status_code=401)
    return {"id": user_id, "role": "admin"}


@vulnapp.get("/admin/status")
def admin_status():
    # Deliberately public despite its path: path naming is not an auth boundary.
    return {"status": "available"}


@vulnapp.get("/admin/audit")
def admin_audit(authorization: str | None = Header(default=None)):
    # VULN: authenticated, but no function-level role check.
    if not authorization:
        return JSONResponse({"detail": "missing token"}, status_code=401)
    return {"events": ["login"]}


@vulnapp.get("/search", response_class=HTMLResponse)
def search(q: str = ""):
    # VULN: reflects input unescaped (XSS).
    return f"<html><body>Results for: {q}</body></html>"


@vulnapp.get("/lookup", response_class=HTMLResponse)
def lookup(name: str = ""):
    # VULN: user input reaches an LDAP filter; malformed input leaks the driver
    # error verbatim (LDAP injection signature).
    if "(" in name or ")" in name or "\\" in name:
        return HTMLResponse(
            f"javax.naming.NamingException: Bad search filter for {name}",
            status_code=500,
        )
    return f"<html><body>user: {name}</body></html>"


# Simulated server-side fetches — an OOB/SSRF sink records what the "server"
# would have requested, so tests can drive the out-of-band confirmation path
# deterministically without a real network callback.
OUTBOUND: list[str] = []


@vulnapp.get("/fetch")
def fetch(url: str = ""):
    # VULN: server fetches an arbitrary user-supplied URL (blind SSRF, query).
    if url.startswith("http"):
        OUTBOUND.append(url)
    return {"fetched": bool(url)}


@vulnapp.get("/aggregate")
def aggregate(source: str = ""):
    # VULN: fetches an upstream URL and RELAYS its response back to the caller
    # unvalidated (API10, unsafe consumption). The fetch is simulated by
    # recording the outbound call; the relay is simulated by echoing the
    # upstream-correlated content into the response, which is the half that
    # distinguishes this from blind SSRF.
    if source.startswith("http"):
        OUTBOUND.append(source)
        return {"upstream": source, "relayed": f"content from {source}"}
    return {"relayed": None}


@vulnapp.post("/webhook")
def webhook(payload: dict = Body(default={})):
    # VULN: fetches a URL taken from a JSON body field (blind SSRF, body).
    url = payload.get("callback") or payload.get("url")
    if isinstance(url, str) and url.startswith("http"):
        OUTBOUND.append(url)
    return {"ok": True}


@vulnapp.post("/xml")
def xml_parse(payload: dict = Body(default={})):
    # VULN: "parses" XML from a body field and resolves external entities — the
    # simulation extracts any http URL inside the field and fetches it, which is
    # what a real XXE entity resolution does out-of-band.
    import re as _re

    for value in payload.values():
        if isinstance(value, str):
            for m in _re.findall(r"http://[^\s\"']+", value):
                OUTBOUND.append(m)
    return {"ok": True}


@vulnapp.post("/deserialize")
def deserialize(payload: dict = Body(default={})):
    # VULN: "deserializes" a body field without constraining the type — the
    # simulation extracts any http URL inside the field and fetches it, which is
    # what a real gadget does when it fires (os.system / URLDNS / __destruct).
    import re as _re

    for value in payload.values():
        if isinstance(value, str):
            for m in _re.findall(r"http://[^\s\"']+", value):
                OUTBOUND.append(m)
    return {"ok": True}


@vulnapp.post("/graphql")
def graphql(payload: dict = Body(default={})):
    # VULN: introspection enabled — answers any introspection query with a schema.
    query = payload.get("query", "")
    if "__schema" in query or "__type" in query:
        return {"data": {"__schema": {"queryType": {"name": "Query"}}}}
    return {"data": None}


@vulnapp.post("/grpc")
async def grpc_reflect(request: Request):
    # VULN: server reflection enabled — answers a list-services request with the
    # service catalogue over gRPC-Web.
    from app.engine.checks.grpc_reflection import grpc_reflection_response

    body = await request.body()
    if b"\x3a\x00" in body:  # ServerReflectionRequest{list_services}
        return Response(
            content=grpc_reflection_response(["grpc.health.v1.Health"]),
            media_type="application/grpc-web+proto",
        )
    return Response(content=b"", media_type="application/grpc-web+proto")


_JWT_MATERIAL: tuple | None = None


def _jwt_material():
    """Lazily generate an RSA keypair for the JWT-confusion simulation."""
    global _JWT_MATERIAL
    if _JWT_MATERIAL is None:
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric import rsa

        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        pem = key.public_key().public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        ).decode()
        _JWT_MATERIAL = (key, pem)
    return _JWT_MATERIAL


@vulnapp.get("/.well-known/jwks.json")
def jwks():
    import base64 as _b64

    key, _pem = _jwt_material()
    nums = key.public_key().public_numbers()

    def b64url(i: int) -> str:
        return _b64.urlsafe_b64encode(
            i.to_bytes((i.bit_length() + 7) // 8, "big")
        ).rstrip(b"=").decode()

    return {"keys": [{"kty": "RSA", "use": "sig", "n": b64url(nums.n), "e": b64url(nums.e)}]}


@vulnapp.get("/jwt")
def jwt_protected(authorization: str | None = Header(default=None)):
    import base64 as _b64
    import hashlib as _hashlib
    import hmac as _hmac
    import json as _json

    _key, pem = _jwt_material()
    if not authorization or not authorization.lower().startswith("bearer "):
        return JSONResponse({"detail": "missing token"}, status_code=401)
    token = authorization.split(" ", 1)[1]
    parts = token.split(".")
    if len(parts) != 3:
        return JSONResponse({"detail": "bad token"}, status_code=401)

    def dec(s: str) -> bytes:
        return _b64.urlsafe_b64decode(s + "=" * (-len(s) % 4))

    try:
        header = _json.loads(dec(parts[0]))
    except Exception:  # noqa: BLE001
        return JSONResponse({"detail": "bad header"}, status_code=401)
    if header.get("jku"):
        # VULN: honors jku — fetches the key-set URL (SSRF via the JWT header).
        OUTBOUND.append(header["jku"])
        return JSONResponse({"detail": "fetched jku"}, status_code=401)
    if header.get("alg") == "HS256":
        # VULN: verifies HS256 with the RSA PUBLIC key as the HMAC secret — the
        # RS256→HS256 key-confusion flaw.
        signing_input = f"{parts[0]}.{parts[1]}".encode()
        sig = dec(parts[2])
        expected = _hmac.new(pem.encode(), signing_input, _hashlib.sha256).digest()
        if _hmac.compare_digest(sig, expected):
            return {"ok": True}
    return JSONResponse({"detail": "invalid"}, status_code=401)


@vulnapp.get("/profiles/{handle}", response_class=HTMLResponse)
def profile(handle: str):
    # VULN: reflects a *path* segment unescaped (path-param XSS).
    return f"<html><body>profile: {handle}</body></html>"


@vulnapp.post("/notes", response_class=HTMLResponse)
def create_note(payload: dict = Body(default={})):
    # VULN: reflects a JSON *body* field unescaped (stored/echoed XSS).
    title = payload.get("title", "")
    return HTMLResponse(f"<html><body>saved: {title}</body></html>")


# In-memory resource store — GET reads it back, PUT/POST mutate it with NO owner
# check, so a low-privilege identity's write persists (BOLA/BFLA on write).
_WIDGETS: dict[int, dict] = {k: dict(v) for k, v in _SEED_WIDGETS.items()}


@vulnapp.get("/widgets/{widget_id}")
def get_widget(widget_id: int):
    return _WIDGETS.get(widget_id, {"id": widget_id, "name": "", "owner": "?"})


@vulnapp.put("/widgets/{widget_id}")
def put_widget(widget_id: int, payload: dict = Body(default={})):
    # VULN: no authorization/owner check — any identity can overwrite any widget.
    w = _WIDGETS.setdefault(widget_id, {"id": widget_id, "owner": "?"})
    for k, v in payload.items():
        w[k] = v
    return w


@vulnapp.post("/widgets")
def create_widget(payload: dict = Body(default={})):
    # VULN: any identity can create; the new id is returned so it is read-back-able.
    nid = (max(_WIDGETS) + 1) if _WIDGETS else 1
    _WIDGETS[nid] = {"id": nid, **payload}
    return _WIDGETS[nid]


@vulnapp.delete("/widgets/{widget_id}")
def delete_widget(widget_id: int):
    _WIDGETS.pop(widget_id, None)
    return {"deleted": widget_id}


@vulnapp.delete("/admin/widgets/{widget_id}")
def admin_delete_widget(widget_id: int, authorization: str | None = Header(default=None)):
    # VULN: rejects anonymous (auth IS enforced) but accepts ANY token — a real
    # broken-auth bypass on a protected, privileged DELETE.
    if not authorization:
        return JSONResponse({"detail": "missing token"}, status_code=401)
    _WIDGETS.pop(widget_id, None)
    return {"deleted": widget_id}


@vulnapp.get("/compute")
def compute(divisor: int = 1):
    # VULN: unhandled input — a spec-valid integer of 0 raises 500 (improper
    # input handling), the class schemathesis boundary generation surfaces.
    return {"result": 100 // divisor}


@vulnapp.get("/accounts")
def list_accounts(authorization: str | None = Header(default=None)):
    # Collection read returning real object ids — the source BOLA's id
    # harvesting pulls from (the item route above is auth-enforced).
    if not authorization:
        return JSONResponse({"detail": "missing token"}, status_code=401)
    return {"items": list(_ACCOUNTS.values())}


@vulnapp.get("/catalog")
def list_catalog(limit: int = 50):
    # VULN: honours a client-controlled page size with no server cap — one
    # request can extract the whole collection (API4, unbounded resource
    # consumption). Generation is bounded only to protect the test process;
    # the point is the count tracks `limit` instead of a fixed ceiling.
    n = max(0, min(limit, 6000))
    return {"items": [{"id": i, "name": f"item-{i}"} for i in range(n)]}


@vulnapp.get("/users/{user_id}")
def get_user_record(user_id: int):
    # VULN: serialises the whole record, credentials and PII included
    # (API3, excessive data exposure). The shape a "return the ORM object"
    # handler produces.
    return {
        "id": user_id,
        "email": "alice@example.com",
        "password_hash": "$2b$12$abcdefghijklmnopqrstuv",
        "ssn": "123-45-6789",
        "session_token": "st_live_9f3a",
        "internal_notes": "flagged by risk team",
        "nested": {"api_key": "ak_live_1234"},
    }


_SIGNUPS: set[str] = set()


@vulnapp.post("/signup")
def signup(payload: dict = Body(default={})):
    # VULN: duplicate-create enumeration oracle — the second identical create is
    # rejected with a conflict that reveals the email already exists.
    email = str(payload.get("email") or "")
    if email in _SIGNUPS:
        return JSONResponse({"message": "email already exists"}, status_code=409)
    _SIGNUPS.add(email)
    return JSONResponse({"id": len(_SIGNUPS), "email": email}, status_code=201)


_ORDERS: dict[int, dict] = {}
_ORDER_REFS: set[str] = set()


@vulnapp.post("/orders")
async def create_order(payload: dict = Body(default={})):
    # VULN: check-then-act with an await between the check and the write. Run
    # sequentially the uniqueness constraint holds (a duplicate ref → 409); run
    # concurrently, several requests pass the `ref in _ORDER_REFS` check before
    # any of them adds it — a time-of-check/time-of-use race the race check
    # catches. The await is what makes the interleave deterministic on the loop.
    ref = str(payload.get("ref") or "")
    if ref in _ORDER_REFS:
        return JSONResponse({"message": "ref already exists"}, status_code=409)
    await asyncio.sleep(0)
    _ORDER_REFS.add(ref)
    nid = (max(_ORDERS) + 1) if _ORDERS else 1
    _ORDERS[nid] = {"id": nid, "ref": ref}
    return JSONResponse(_ORDERS[nid], status_code=201)


@vulnapp.get("/orders/{order_id}")
async def get_order(order_id: int):
    return _ORDERS.get(order_id, {"id": order_id, "ref": ""})


@vulnapp.delete("/orders/{order_id}")
async def delete_order(order_id: int):
    _ORDERS.pop(order_id, None)
    return {"deleted": order_id}


# Records: a create→read pair with a classic cross-tenant BOLA on the item read.
# POST stamps the owner from the caller's token, so a record created by identity A
# provably belongs to A; GET enforces auth (rejects anon) but never scopes to the
# owner, so identity B can read A's freshly-created object. That create-as-A →
# read-as-B sequence is exactly what the seeded_bola check proves.
_RECORDS: dict[int, dict] = {}


@vulnapp.post("/records")
def create_record_owned(
    payload: dict = Body(default={}), authorization: str | None = Header(default=None)
):
    if not authorization:
        return JSONResponse({"detail": "missing token"}, status_code=401)
    nid = (max(_RECORDS) + 1) if _RECORDS else 1
    _RECORDS[nid] = {"id": nid, "owner": authorization, "body": str(payload.get("body") or "")}
    return JSONResponse(_RECORDS[nid], status_code=201)


@vulnapp.get("/records/{record_id}")
def get_record_owned(record_id: int, authorization: str | None = Header(default=None)):
    # VULN: auth IS enforced (anon rejected) but the owner is never checked, so
    # any authenticated identity reads any record — object-level authz missing.
    if not authorization:
        return JSONResponse({"detail": "missing token"}, status_code=401)
    return _RECORDS.get(record_id, {"id": record_id, "owner": "?", "body": ""})


@vulnapp.delete("/records/{record_id}")
def delete_record_owned(record_id: int, authorization: str | None = Header(default=None)):
    _RECORDS.pop(record_id, None)
    return {"deleted": record_id}


_CHECKOUTS: dict[int, dict] = {}


@vulnapp.post("/checkout")
def checkout(payload: dict = Body(default={}), authorization: str | None = Header(default=None)):
    # VULN: a sensitive business flow with no anti-automation — every identical
    # replay mints a NEW order with no throttle, idempotency or challenge, so a
    # script can drive checkout at machine speed (API6). Ignores the body, which
    # is what makes each replay a distinct create.
    nid = (max(_CHECKOUTS) + 1) if _CHECKOUTS else 1
    _CHECKOUTS[nid] = {"id": nid, "item": str(payload.get("item") or "")}
    return JSONResponse(_CHECKOUTS[nid], status_code=201)


@vulnapp.post("/login")
def login(payload: dict = Body(default={}), authorization: str | None = Header(default=None)):
    # Auth-shaped endpoint that never throttles: any token passes, and no 429
    # is ever returned (missing rate limiting).
    if not authorization:
        return JSONResponse({"detail": "missing token"}, status_code=401)
    return {"ok": True}


@vulnapp.post("/oauth/token")
def oauth_token(
    grant_type: str = Form(default=""),
    client_id: str = Form(default=""),
    client_secret: str = Form(default=""),
):
    # A minimal OAuth token endpoint so a grant credential can mint a bearer
    # token through the runner (the happy path the failure-path test lacks).
    if grant_type == "client_credentials" and client_id and client_secret:
        return {"access_token": "minted-token", "token_type": "bearer"}
    return JSONResponse({"error": "invalid_grant"}, status_code=400)


@vulnapp.get("/reset-link")
def reset_link(x_forwarded_host: str | None = Header(default=None)):
    # VULN: builds an absolute URL from the forwarded-host header — the
    # host-header injection / password-reset-poisoning shape.
    host = x_forwarded_host or "example.com"
    return {"reset_link": f"https://{host}/reset?token=abc123"}


@vulnapp.get("/debuginfo")
def debuginfo():
    # VULN: leaks internal debug/trace correlation identifiers in headers.
    return JSONResponse(
        {"ok": True}, headers={"X-Debug-Id": "dbg-123", "X-Trace-Id": "trace-9"}
    )


@vulnapp.get("/hardened")
def hardened():
    # The control: a fully hardened endpoint. A per-endpoint sweep must leave
    # this one out of the missing-header findings the rest of the app earns.
    return JSONResponse(
        {"ok": True},
        headers={
            "X-Content-Type-Options": "nosniff",
            "X-Frame-Options": "DENY",
            "Content-Security-Policy": "default-src 'self'",
            "Referrer-Policy": "strict-origin-when-cross-origin",
            "Permissions-Policy": "geolocation=(), camera=(), microphone=()",
            "Cross-Origin-Opener-Policy": "same-origin",
            "Cross-Origin-Resource-Policy": "same-origin",
            "Cross-Origin-Embedder-Policy": "require-corp",
            "X-Permitted-Cross-Domain-Policies": "none",
            "Document-Policy": "document-write=?0",
            "Integrity-Policy": "blocked-destinations=(script)",
            "Origin-Agent-Cluster": "?1",
            "X-DNS-Prefetch-Control": "off",
            "X-Download-Options": "noopen",
        },
    )


@vulnapp.get("/legacy")
def legacy(origin: str | None = Header(default=None)):
    # VULN: headers present but worthless — framing allowed, CSP allows any
    # origin plus 'unsafe-inline', full-URL referrer. Reflects any Origin with
    # credentials (CORS), and sets a session cookie with no flags.
    return JSONResponse(
        {"ok": True},
        headers={
            "X-Content-Type-Options": "nosniff",
            "X-Frame-Options": "ALLOWALL",
            "Content-Security-Policy": "default-src *; script-src 'unsafe-inline' *",
            "Referrer-Policy": "unsafe-url",
            "Permissions-Policy": "geolocation=(), camera=(), microphone=()",
            "Cross-Origin-Opener-Policy": "same-origin",
            "Cross-Origin-Embedder-Policy": "require-corp",
            "Document-Policy": "document-write=?0",
            "Integrity-Policy": "blocked-destinations=(script)",
            "X-DNS-Prefetch-Control": "off",
            "X-Download-Options": "noopen",
            # Present but set to the value that defeats them.
            "Cross-Origin-Resource-Policy": "cross-origin",
            "X-Permitted-Cross-Domain-Policies": "all",
            "Origin-Agent-Cluster": "?0",
            "Access-Control-Allow-Origin": origin or "*",
            "Access-Control-Allow-Credentials": "true",
            "Set-Cookie": "session=s3cr3t-value; Path=/",
        },
    )


@vulnapp.get("/health")
def health():
    return {"status": "ok"}


# The most common REST naming: a bare ``{id}`` on every item route, with opaque
# string ids, so a placeholder ``1`` is a 404 and only an id read from the
# matching collection reaches the object. Two resources, so a monitor id that
# leaks into ``/incidents/{id}`` misses. Read-only, so no reset is needed.
_MONITORS = {"mon-7f3a": {"id": "mon-7f3a", "owner": "admin", "url": "https://example.com"}}
_INCIDENTS = {"inc-22c1": {"id": "inc-22c1", "monitor": "mon-7f3a", "status": "open"}}


@vulnapp.get("/monitors")
def list_monitors(authorization: str | None = Header(default=None)):
    if not authorization:
        return JSONResponse({"detail": "missing token"}, status_code=401)
    return {"items": list(_MONITORS.values())}


@vulnapp.get("/monitors/{id}")
def get_monitor(id: str, authorization: str | None = Header(default=None)):
    # VULN: authenticated but not owner-scoped (BOLA on a bare-{id} route).
    if not authorization:
        return JSONResponse({"detail": "missing token"}, status_code=401)
    if id not in _MONITORS:
        return JSONResponse({"detail": "not found"}, status_code=404)
    return _MONITORS[id]


@vulnapp.get("/incidents")
def list_incidents(authorization: str | None = Header(default=None)):
    if not authorization:
        return JSONResponse({"detail": "missing token"}, status_code=401)
    return {"items": list(_INCIDENTS.values())}


@vulnapp.get("/incidents/{id}")
def get_incident(id: str, authorization: str | None = Header(default=None)):
    # VULN: same missing owner check as get_monitor.
    if not authorization:
        return JSONResponse({"detail": "missing token"}, status_code=401)
    if id not in _INCIDENTS:
        return JSONResponse({"detail": "not found"}, status_code=404)
    return _INCIDENTS[id]


# Nested resource: a child (item) under a parent (project). Creating an item
# needs a real project_id, so the engine must create the project FIRST — the
# multi-hop create-parent -> create-child -> read sequence. The item read
# enforces auth but never checks the owner (cross-tenant BOLA on a nested path).
_PROJECTS: dict[int, dict] = {}
_PROJECT_ITEMS: dict[tuple[int, int], dict] = {}


@vulnapp.post("/projects")
def create_project(
    payload: dict = Body(default={}), authorization: str | None = Header(default=None)
):
    if not authorization:
        return JSONResponse({"detail": "missing token"}, status_code=401)
    nid = (max(_PROJECTS) + 1) if _PROJECTS else 1
    _PROJECTS[nid] = {"id": nid, "owner": authorization, "name": str(payload.get("name") or "")}
    return JSONResponse(_PROJECTS[nid], status_code=201)


@vulnapp.post("/projects/{project_id}/items")
def create_project_item(
    project_id: int,
    payload: dict = Body(default={}),
    authorization: str | None = Header(default=None),
):
    if not authorization:
        return JSONResponse({"detail": "missing token"}, status_code=401)
    if project_id not in _PROJECTS:
        return JSONResponse({"detail": "no such project"}, status_code=404)
    existing = [k[1] for k in _PROJECT_ITEMS if k[0] == project_id]
    iid = (max(existing) + 1) if existing else 1
    # VULN: server id + owner-from-token, but the whole body is bound on top, so
    # a client can also set server-owned fields at create time (nested mass
    # assignment) and no owner check on the read makes it a nested cross-tenant
    # BOLA once created.
    _PROJECT_ITEMS[(project_id, iid)] = {"id": iid, "owner": authorization, **payload}
    return JSONResponse(_PROJECT_ITEMS[(project_id, iid)], status_code=201)


@vulnapp.get("/projects/{project_id}/items/{item_id}")
def get_project_item(
    project_id: int, item_id: int, authorization: str | None = Header(default=None)
):
    # VULN: auth IS enforced (anon rejected) but the owner is never checked — a
    # nested cross-tenant BOLA the engine only reaches by seeding the project.
    if not authorization:
        return JSONResponse({"detail": "missing token"}, status_code=401)
    return _PROJECT_ITEMS.get(
        (project_id, item_id), {"id": item_id, "owner": "?", "body": ""}
    )


@vulnapp.delete("/projects/{project_id}/items/{item_id}")
def delete_project_item(
    project_id: int, item_id: int, authorization: str | None = Header(default=None)
):
    _PROJECT_ITEMS.pop((project_id, item_id), None)
    return {"deleted": item_id}


@vulnapp.delete("/projects/{project_id}")
def delete_project(project_id: int, authorization: str | None = Header(default=None)):
    _PROJECTS.pop(project_id, None)
    return {"deleted": project_id}


# NestJS-style 404 that echoes the request path — the classic reflection
# false positive: the marker comes back, but only inside the framework's error
# envelope. Must stay LAST so defined routes win.
@vulnapp.get("/{path:path}")
def not_found_echo(path: str):
    return JSONResponse(
        {"message": f"Cannot GET /{path}", "error": "NotFoundException"},
        status_code=404,
    )
