"""The hardened twin of :mod:`tests.vulnapp` — the engine's precision gate.

``vulnapp`` proves the checks *fire*. Nothing proved they stay quiet, and recall
without precision is the failure mode a scanner actually dies of: a report where
nine findings in ten are noise gets ignored, and the tenth goes with it.

So this app answers the same routes with the same shapes and does everything
right: it enforces ownership and role, never reflects input, escapes what it
renders, sets the full header set with real values, returns no server banner or
stack trace, exposes no sensitive field the spec does not declare, rejects
undeclared body fields instead of binding them, and refuses duplicate writes.
``tests/test_precision.py`` runs the whole registry against it and fails on any
finding outside a small, documented allowlist.

Two rules keep this honest as the engine grows:

- **Same surface, different behaviour.** A route here must exist in ``vulnapp``
  with the same method and path shape. A precision gate over endpoints the
  positive tests never touch would prove nothing.
- **Hardened, not hollow.** Returning 404 everywhere would pass trivially and
  test nothing. Every route returns a real, populated response.

One hardening choice is worth naming because it looks like tailoring and is not:
**a write never echoes the value it just stored.** A create that answers with
``{"name": "<what you sent>"}`` reflects attacker-controlled input into its
response verbatim, and the reflection checks report that — correctly. It is a
common REST convention and a real, if low-grade, weakness, so the hardened twin
returns the identifier and lets the client re-read.
"""
from __future__ import annotations

import html

from fastapi import FastAPI, Header, Request
from fastapi.responses import HTMLResponse, JSONResponse, Response

safeapp = FastAPI(docs_url=None, redoc_url=None, openapi_url=None)

#: The full header set ``header_policy`` scores, all at their strong values.
#: One dict so a policy change is a one-line fix here rather than 30.
SECURE_HEADERS = {
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Content-Security-Policy": "default-src 'self'; frame-ancestors 'none'",
    "Referrer-Policy": "strict-origin-when-cross-origin",
    "Permissions-Policy": "geolocation=(), camera=(), microphone=()",
    "Strict-Transport-Security": "max-age=63072000; includeSubDomains; preload",
    "Cross-Origin-Opener-Policy": "same-origin",
    "Cross-Origin-Resource-Policy": "same-origin",
    "Cross-Origin-Embedder-Policy": "require-corp",
    "X-Permitted-Cross-Domain-Policies": "none",
    "Document-Policy": "document-write=?0",
    "Integrity-Policy": "blocked-destinations=(script)",
    "Origin-Agent-Cluster": "?1",
    "X-DNS-Prefetch-Control": "off",
    "X-Download-Options": "noopen",
    "Cache-Control": "no-store",
}

# Ownership is what the authorization checks probe. ``alice`` and ``admin`` are
# the two identities ``factories.two_identities`` supplies.
_OWNERS = {1: "alice", 2: "admin"}

_SEED_WIDGETS = {1: {"id": 1, "name": "original", "owner": "alice"}}
_WIDGETS: dict[int, dict] = {}
_PROJECTS: dict[int, dict] = {}
_PROJECT_ITEMS: dict[tuple[int, int], dict] = {}
_ORDER_REFS: dict[str, int] = {}
_CHECKOUT_KEYS: dict[str, int] = {}
_NEXT = {"id": 100}


def reset_state() -> None:
    """Restore every store to its seed, like ``vulnapp.reset_state``."""
    _WIDGETS.clear()
    _WIDGETS.update({k: dict(v) for k, v in _SEED_WIDGETS.items()})
    _PROJECTS.clear()
    _PROJECT_ITEMS.clear()
    _ORDER_REFS.clear()
    _CHECKOUT_KEYS.clear()
    _NEXT["id"] = 100


def _next_id() -> int:
    _NEXT["id"] += 1
    return _NEXT["id"]


#: Tokens this app accepts, mapped to the identity they name.
#: ``factories.credential`` mints ``<name>-token``.
_TOKENS = {"alice-token": "alice", "admin-token": "admin"}


def _caller(authorization: str | None) -> str | None:
    """The identity a token names, or None when absent or unrecognised.

    An exact token table is the whole difference from ``vulnapp``'s "any
    non-empty token is fine" — it is what makes ``broken_auth``'s forged and
    stripped-signature probes fail here.
    """
    if not authorization:
        return None
    return _TOKENS.get(authorization.removeprefix("Bearer ").strip())


def ok(payload: dict | list, status: int = 200) -> JSONResponse:
    return JSONResponse(payload, status_code=status, headers=dict(SECURE_HEADERS))


def deny(status: int, detail: str) -> JSONResponse:
    """A refusal that says nothing about why beyond the status."""
    return JSONResponse({"detail": detail}, status_code=status, headers=dict(SECURE_HEADERS))


@safeapp.middleware("http")
async def secure_every_response(request: Request, call_next):
    """Header hygiene applies to error responses too, including 404 and 422."""
    response = await call_next(request)
    for name, value in SECURE_HEADERS.items():
        response.headers.setdefault(name, value)
    # No banner: a version string is ``info_disclosure``'s whole signal.
    if "server" in response.headers:
        del response.headers["server"]
    return response


# ---- Authorization: ownership and role are enforced ---------------------------


@safeapp.get("/accounts/{account_id}")
def get_account(account_id: int, authorization: str | None = Header(default=None)):
    caller = _caller(authorization)
    if caller is None:
        return deny(401, "unauthorized")
    if _OWNERS.get(account_id) != caller:
        # 404, not 403: existence itself is not disclosed to a non-owner.
        return deny(404, "not found")
    return ok({"id": account_id, "owner": caller, "balance": 42000})


@safeapp.get("/accounts")
def list_accounts(authorization: str | None = Header(default=None)):
    caller = _caller(authorization)
    if caller is None:
        return deny(401, "unauthorized")
    return ok([{"id": i, "owner": o} for i, o in _OWNERS.items() if o == caller])


# Bare-{id} routes with opaque ids, owner-scoped: each identity lists and reads
# only its own, and another identity's id is a 404.
_MONITORS = {
    "mon-a1": {"id": "mon-a1", "owner": "alice", "url": "https://alice.example"},
    "mon-b2": {"id": "mon-b2", "owner": "admin", "url": "https://admin.example"},
}
_INCIDENTS = {
    "inc-a1": {"id": "inc-a1", "owner": "alice", "status": "open"},
    "inc-b2": {"id": "inc-b2", "owner": "admin", "status": "resolved"},
}


def _owned_list(store: dict[str, dict], authorization: str | None) -> JSONResponse:
    caller = _caller(authorization)
    if caller is None:
        return deny(401, "unauthorized")
    return ok({"items": [r for r in store.values() if r["owner"] == caller]})


def _owned_item(store: dict[str, dict], key: str, authorization: str | None) -> JSONResponse:
    caller = _caller(authorization)
    if caller is None:
        return deny(401, "unauthorized")
    record = store.get(key)
    if record is None or record["owner"] != caller:
        return deny(404, "not found")
    return ok(record)


@safeapp.get("/monitors")
def list_monitors(authorization: str | None = Header(default=None)):
    return _owned_list(_MONITORS, authorization)


@safeapp.get("/monitors/{id}")
def get_monitor(id: str, authorization: str | None = Header(default=None)):
    return _owned_item(_MONITORS, id, authorization)


@safeapp.get("/incidents")
def list_incidents(authorization: str | None = Header(default=None)):
    return _owned_list(_INCIDENTS, authorization)


@safeapp.get("/incidents/{id}")
def get_incident(id: str, authorization: str | None = Header(default=None)):
    return _owned_item(_INCIDENTS, id, authorization)


@safeapp.post("/admin/users/{user_id}/promote")
def promote(user_id: int, authorization: str | None = Header(default=None)):
    caller = _caller(authorization)
    if caller is None:
        return deny(401, "unauthorized")
    if caller != "admin":
        return deny(403, "forbidden")
    return ok({"id": user_id, "role": "admin"})


@safeapp.get("/admin/status")
def admin_status():
    # Public operational metadata can legitimately live under an admin prefix.
    return ok({"status": "available"})


@safeapp.get("/admin/audit")
def admin_audit(authorization: str | None = Header(default=None)):
    caller = _caller(authorization)
    if caller is None:
        return deny(401, "unauthorized")
    if caller != "admin":
        return deny(403, "forbidden")
    return ok({"events": ["login"]})


@safeapp.post("/checkout")
async def checkout(request: Request, authorization: str | None = Header(default=None)):
    # Hardened twin of vulnapp's /checkout: a sensitive flow that demands an
    # Idempotency-Key, so an identical replay is de-duplicated to the same
    # order instead of minting a new one — business_flow stays quiet.
    caller = _caller(authorization)
    if caller is None:
        return deny(401, "unauthorized")
    key = request.headers.get("Idempotency-Key")
    if not key:
        return deny(400, "Idempotency-Key header required")
    existing = _CHECKOUT_KEYS.get(key)
    if existing is not None:
        return ok({"id": existing}, status=201)
    order_id = _next_id()
    _CHECKOUT_KEYS[key] = order_id
    return ok({"id": order_id}, status=201)


@safeapp.get("/catalog")
def list_catalog(limit: int = 50):
    # Hardened twin of vulnapp's /catalog: a client may ask for more, but the
    # page size is capped server-side, so the response never tracks an
    # unbounded `limit` and resource_consumption stays quiet.
    _CAP = 100
    n = max(0, min(limit, _CAP))
    return ok({"items": [{"id": i, "name": f"item-{i}"} for i in range(n)]})


@safeapp.get("/users/{user_id}")
def get_user(user_id: int, authorization: str | None = Header(default=None)):
    caller = _caller(authorization)
    if caller is None:
        return deny(401, "unauthorized")
    if _OWNERS.get(user_id) != caller:
        return deny(404, "not found")
    # Only declared, non-sensitive fields: no password hash, no token, no SSN.
    return ok({"id": user_id, "handle": caller})


# ---- Rendering: input is escaped, never reflected raw --------------------------


@safeapp.get("/search", response_class=HTMLResponse)
def search(q: str = ""):
    body = f"<html><body>Results for: {html.escape(q)}</body></html>"
    return HTMLResponse(body, headers=dict(SECURE_HEADERS))


@safeapp.get("/lookup", response_class=HTMLResponse)
def lookup(name: str = ""):
    # Rejects the metacharacters rather than passing them to a backend, and
    # never leaks a driver error. Shell and expression characters are in the
    # set too: a name is a name.
    if any(c in name for c in "()\\*'\"<>;|&$`{}[]"):
        return deny(400, "invalid name")
    return HTMLResponse(
        f"<html><body>user: {html.escape(name)}</body></html>",
        headers=dict(SECURE_HEADERS),
    )


@safeapp.get("/profiles/{handle}", response_class=HTMLResponse)
def profile(handle: str):
    return HTMLResponse(
        f"<html><body>profile: {html.escape(handle)}</body></html>",
        headers=dict(SECURE_HEADERS),
    )


@safeapp.get("/compute")
def compute(expr: str = ""):
    # Never evaluates; never echoes.
    return ok({"result": 0})


@safeapp.get("/fetch")
def fetch(url: str = ""):
    # No outbound request at all — the SSRF sink simply is not there.
    return deny(400, "url fetching is not supported")


# ---- Writes: undeclared fields rejected, duplicates refused --------------------

_DECLARED_WIDGET_FIELDS = {"name"}


@safeapp.get("/widgets/{widget_id}")
def get_widget(widget_id: int, authorization: str | None = Header(default=None)):
    caller = _caller(authorization)
    if caller is None:
        return deny(401, "unauthorized")
    widget = _WIDGETS.get(widget_id)
    if widget is None or widget["owner"] != caller:
        return deny(404, "not found")
    return ok({"id": widget["id"], "name": widget["name"]})


@safeapp.put("/widgets/{widget_id}")
async def put_widget(
    widget_id: int, request: Request, authorization: str | None = Header(default=None)
):
    caller = _caller(authorization)
    if caller is None:
        return deny(401, "unauthorized")
    widget = _WIDGETS.get(widget_id)
    if widget is None or widget["owner"] != caller:
        return deny(404, "not found")
    body = await request.json()
    if not isinstance(body, dict) or set(body) - _DECLARED_WIDGET_FIELDS:
        # Undeclared fields are refused, not bound — the mass-assignment fix.
        return deny(400, "unexpected field")
    widget["name"] = str(body.get("name", widget["name"]))
    return ok({"id": widget["id"], "updated": True})


@safeapp.post("/widgets")
async def create_widget(request: Request, authorization: str | None = Header(default=None)):
    caller = _caller(authorization)
    if caller is None:
        return deny(401, "unauthorized")
    body = await request.json()
    if not isinstance(body, dict) or set(body) - _DECLARED_WIDGET_FIELDS:
        return deny(400, "unexpected field")
    new_id = _next_id()
    _WIDGETS[new_id] = {"id": new_id, "name": str(body.get("name", "")), "owner": caller}
    return ok({"id": new_id}, status=201)


@safeapp.delete("/widgets/{widget_id}")
def delete_widget(widget_id: int, authorization: str | None = Header(default=None)):
    caller = _caller(authorization)
    if caller is None:
        return deny(401, "unauthorized")
    widget = _WIDGETS.get(widget_id)
    if widget is None or widget["owner"] != caller:
        return deny(404, "not found")
    _WIDGETS.pop(widget_id)
    return Response(status_code=204, headers=dict(SECURE_HEADERS))


@safeapp.post("/orders")
async def create_order(request: Request, authorization: str | None = Header(default=None)):
    """Idempotent by reference — a repeat returns the first order, not an error.

    Returning 409 on a duplicate would also prevent the double-write, but it
    tells the caller whether a reference already exists. ``enumeration`` reports
    that difference as a duplicate-create oracle, and it is right to: true
    idempotency answers identically either way.
    """
    caller = _caller(authorization)
    if caller is None:
        return deny(401, "unauthorized")
    body = await request.json()
    ref = str(body.get("ref", "")) if isinstance(body, dict) else ""
    if not ref:
        return deny(400, "ref is required")
    existing = _ORDER_REFS.get(ref)
    if existing is not None:
        return ok({"id": existing}, status=201)
    order_id = _next_id()
    _ORDER_REFS[ref] = order_id
    return ok({"id": order_id}, status=201)


@safeapp.post("/projects")
async def create_project(request: Request, authorization: str | None = Header(default=None)):
    caller = _caller(authorization)
    if caller is None:
        return deny(401, "unauthorized")
    body = await request.json()
    project_id = _next_id()
    _PROJECTS[project_id] = {
        "id": project_id,
        "name": str(body.get("name", "")) if isinstance(body, dict) else "",
        "owner": caller,
    }
    return ok({"id": project_id}, status=201)


@safeapp.post("/projects/{project_id}/items")
async def create_item(
    project_id: int, request: Request, authorization: str | None = Header(default=None)
):
    caller = _caller(authorization)
    if caller is None:
        return deny(401, "unauthorized")
    project = _PROJECTS.get(project_id)
    if project is None or project["owner"] != caller:
        return deny(404, "not found")
    body = await request.json()
    item_id = _next_id()
    _PROJECT_ITEMS[(project_id, item_id)] = {
        "id": item_id,
        "label": str(body.get("label", "")) if isinstance(body, dict) else "",
        "owner": caller,
    }
    return ok({"id": item_id}, status=201)


@safeapp.get("/projects/{project_id}/items/{item_id}")
def get_item(
    project_id: int, item_id: int, authorization: str | None = Header(default=None)
):
    caller = _caller(authorization)
    if caller is None:
        return deny(401, "unauthorized")
    item = _PROJECT_ITEMS.get((project_id, item_id))
    if item is None or item["owner"] != caller:
        # The cross-tenant read the seeded-BOLA check looks for, refused.
        return deny(404, "not found")
    return ok({"id": item["id"], "label": item["label"]})


@safeapp.delete("/projects/{project_id}/items/{item_id}")
def delete_item(
    project_id: int, item_id: int, authorization: str | None = Header(default=None)
):
    caller = _caller(authorization)
    if caller is None:
        return deny(401, "unauthorized")
    item = _PROJECT_ITEMS.get((project_id, item_id))
    if item is None or item["owner"] != caller:
        return deny(404, "not found")
    _PROJECT_ITEMS.pop((project_id, item_id))
    return Response(status_code=204, headers=dict(SECURE_HEADERS))


@safeapp.delete("/projects/{project_id}")
def delete_project(project_id: int, authorization: str | None = Header(default=None)):
    caller = _caller(authorization)
    if caller is None:
        return deny(401, "unauthorized")
    project = _PROJECTS.get(project_id)
    if project is None or project["owner"] != caller:
        return deny(404, "not found")
    _PROJECTS.pop(project_id)
    return Response(status_code=204, headers=dict(SECURE_HEADERS))


# ---- Auth and hygiene ----------------------------------------------------------


@safeapp.post("/login")
async def login(request: Request):
    # Constant refusal: no user enumeration, no lockout bypass, no token issued
    # to a bad password, and no timing signal worth measuring.
    await request.body()
    return deny(401, "invalid credentials")


@safeapp.get("/health")
def health():
    return ok({"status": "ok"})


@safeapp.api_route("/{path:path}", methods=["GET", "POST", "PUT", "PATCH", "DELETE"])
def catch_all(path: str):
    """Everything undeclared is a plain 404 — no stack trace, no banner."""
    return deny(404, "not found")
