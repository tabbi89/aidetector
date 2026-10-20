"""Write oracle + BOLA/BFLA-on-write — opt-in, mutation-confirming checks.

Driven against the in-process vulnapp, whose /widgets store mutates with no owner
check, so a low-privilege identity's write persists and the read-back confirms it.
"""
from __future__ import annotations

from app.domain.enums import Severity
from app.engine.base import TargetOperation
from app.engine.checks.write_oracle import WriteOracleCheck
from app.engine.resource_map import build_resource_pairs
from tests import factories
from tests.vulnapp import _WIDGETS

CREDS = [factories.credential("admin", "admin"), factories.credential("alice", "user")]

WIDGET_GET = TargetOperation(
    id="w-get", method="GET", path="/widgets/{widget_id}",
    params=[{"name": "widget_id", "in": "path", "required": True}],
)
WIDGET_PUT = TargetOperation(
    id="w-put", method="PUT", path="/widgets/{widget_id}",
    params=[
        {"name": "widget_id", "in": "path", "required": True},
        {"name": "name", "in": "body", "required": False, "schema": {"type": "string"}},
    ],
)
WIDGET_POST = TargetOperation(
    id="w-post", method="POST", path="/widgets",
    params=[{"name": "name", "in": "body", "required": False, "schema": {"type": "string"}}],
)
WIDGET_DELETE = TargetOperation(
    id="w-del", method="DELETE", path="/widgets/{widget_id}",
    params=[{"name": "widget_id", "in": "path", "required": True}],
)


def _ctx(operations, *, allow_mutation=True, creds=None):
    return factories.scan_context(
        operations,
        credentials=CREDS if creds is None else creds,
        allow_mutation=allow_mutation,
    )


def test_resource_map_pairs_update_and_create():
    ops = [WIDGET_GET, WIDGET_PUT, WIDGET_POST]
    pairs = {(p.kind, p.write.method, p.read.path) for p in build_resource_pairs(ops)}
    assert ("update", "PUT", "/widgets/{widget_id}") in pairs
    assert ("create", "POST", "/widgets/{widget_id}") in pairs


def test_write_oracle_confirms_bola_on_update():
    _WIDGETS[1] = {"id": 1, "name": "original", "owner": "admin"}
    findings = WriteOracleCheck().run(_ctx([WIDGET_GET, WIDGET_PUT]))
    assert len(findings) == 1
    f = findings[0]
    assert f.owasp_id == "API1:2023"  # BOLA (object-level) write
    assert f.evidence["writer_identity"] == "alice"
    assert f.evidence["writer_role"] == "user"
    assert f.evidence["reader_identity"] == "admin"
    assert f.evidence["reader_role"] == "admin"
    assert f.evidence["kind"] == "update"
    # the target was restored afterwards (not left holding the canary)
    assert _WIDGETS[1]["name"] == "original"


def test_write_oracle_confirms_create_and_cleans_up():
    before = set(_WIDGETS)
    findings = WriteOracleCheck().run(_ctx([WIDGET_GET, WIDGET_POST, WIDGET_DELETE]))
    assert any(f.evidence["kind"] == "create" for f in findings)
    # the object created to prove the write was deleted (DELETE op available)
    assert set(_WIDGETS) == before


def test_privileged_scope_raises_the_finding_to_bfla_critical():
    """A scope naming staff/internal access is privileged, not just "admin".

    ``write_oracle`` used to carry its own privilege rule that matched only
    ``admin``, so a confirmed write on a ``staff``-scoped operation was reported
    as API1/high while BFLA called the same endpoint privileged. Both now share
    ``app.domain.privilege``, so it is API5/critical.
    """
    scoped_put = TargetOperation(
        id="w-put", method="PUT", path="/widgets/{widget_id}",
        auth_scope="staff:write",
        params=[
            {"name": "widget_id", "in": "path", "required": True},
            {"name": "name", "in": "body", "required": False, "schema": {"type": "string"}},
        ],
    )
    _WIDGETS[1] = {"id": 1, "name": "original", "owner": "admin"}
    findings = WriteOracleCheck().run(_ctx([WIDGET_GET, scoped_put]))

    assert len(findings) == 1
    f = findings[0]
    assert f.owasp_id == "API5:2023"
    assert f.severity is Severity.critical
    assert "BFLA (write)" in f.title


def test_unscoped_write_is_still_object_level():
    """The counterpart: no privileged scope, no promotion. API1/high stands."""
    _WIDGETS[1] = {"id": 1, "name": "original", "owner": "admin"}
    findings = WriteOracleCheck().run(_ctx([WIDGET_GET, WIDGET_PUT]))
    assert findings[0].owasp_id == "API1:2023"
    assert findings[0].severity is Severity.high


def test_write_oracle_noop_without_mutation_flag():
    assert WriteOracleCheck().run(_ctx([WIDGET_GET, WIDGET_PUT], allow_mutation=False)) == []


def test_write_oracle_noop_with_single_identity():
    solo = [CREDS[0]]
    assert WriteOracleCheck().run(_ctx([WIDGET_GET, WIDGET_PUT], creds=solo)) == []


# ---- multi-hop: BOLA-on-write reaches a nested resource ------------------------

PROJ_POST = TargetOperation(
    id="p-post", method="POST", path="/projects",
    params=[{"name": "name", "in": "body", "required": False, "schema": {"type": "string"}}],
)
PROJ_DELETE = TargetOperation(
    id="p-del", method="DELETE", path="/projects/{project_id}",
    params=[{"name": "project_id", "in": "path", "required": True}],
)
ITEM_POST = TargetOperation(
    id="i-post", method="POST", path="/projects/{project_id}/items",
    params=[
        {"name": "project_id", "in": "path", "required": True},
        {"name": "body", "in": "body", "required": False, "schema": {"type": "string"}},
    ],
)
ITEM_GET = TargetOperation(
    id="i-get", method="GET", path="/projects/{project_id}/items/{item_id}",
    params=[
        {"name": "project_id", "in": "path", "required": True},
        {"name": "item_id", "in": "path", "required": True},
    ],
)
ITEM_DELETE = TargetOperation(
    id="i-del", method="DELETE", path="/projects/{project_id}/items/{item_id}",
    params=[
        {"name": "project_id", "in": "path", "required": True},
        {"name": "item_id", "in": "path", "required": True},
    ],
)
NESTED = [PROJ_POST, PROJ_DELETE, ITEM_POST, ITEM_GET, ITEM_DELETE]


def test_write_oracle_confirms_bola_write_on_a_nested_resource():
    from tests.vulnapp import _PROJECT_ITEMS, _PROJECTS

    findings = WriteOracleCheck().run(_ctx(NESTED))
    assert len(findings) == 1
    f = findings[0]
    assert f.owasp_id == "API1:2023"
    assert f.evidence["kind"] == "create"
    assert f.evidence["write"] == "POST /projects/{project_id}/items"
    # The seeded parent and the created child are both gone.
    assert not _PROJECTS and not _PROJECT_ITEMS


def test_write_oracle_skips_a_nested_create_with_no_parent_producer():
    # No POST /projects → the parent cannot be seeded, so the pair is skipped.
    assert WriteOracleCheck().run(_ctx([ITEM_POST, ITEM_GET, ITEM_DELETE])) == []


def _tenanted(*creds):
    from dataclasses import replace

    return [replace(c, tenant=t) for c, t in creds]


def test_a_lower_role_writing_in_its_own_tenant_is_bfla_write():
    """Two identities of one tenant differ only by role, so a write the lower
    one should have been refused is function-level (API5). With tenants set the
    oracle pairs across tenants for BOLA; it must still test this boundary."""
    admin, alice = CREDS
    creds = _tenanted((admin, "a"), (alice, "a"))
    findings = WriteOracleCheck().run(_ctx([WIDGET_GET, WIDGET_PUT], creds=creds))
    assert len(findings) == 1
    f = findings[0]
    assert f.owasp_id == "API5:2023" and f.title.startswith("BFLA (write)")
    assert f.evidence["boundary"] == "role"
    assert (f.evidence["writer_identity"], f.evidence["reader_identity"]) == ("alice", "admin")
    # Ownership advice would be wrong here: the role check is what failed.
    assert "role" in f.remediation
    assert _WIDGETS[1]["name"] == "original"


def test_with_tenants_both_boundaries_are_tested():
    from app.engine.checks.write_oracle import _writer_pairs

    admin, alice = CREDS
    bob = factories.credential("bob", "user")
    ctx = _ctx([WIDGET_GET, WIDGET_PUT], creds=_tenanted((admin, "a"), (alice, "a"), (bob, "b")))
    assert [(o.name, w.name, role) for o, w, role in _writer_pairs(ctx)] == [
        ("admin", "bob", False),   # BOLA across tenants
        ("admin", "alice", True),  # BFLA inside tenant a
    ]


def test_a_role_gated_write_stays_clean():
    """An API that refuses the lower role's write produces nothing — and the
    owner's restore still runs."""
    from fastapi import FastAPI, Header
    from fastapi.responses import JSONResponse
    from fastapi.testclient import TestClient

    app = FastAPI()
    widget = {"id": 1, "name": "original"}

    @app.get("/widgets/{widget_id}")
    def read(widget_id: int, authorization: str | None = Header(default=None)):
        if not authorization:
            return JSONResponse({"error": "sign in"}, status_code=401)
        return widget

    @app.put("/widgets/{widget_id}")
    def write(widget_id: int, body: dict, authorization: str | None = Header(default=None)):
        if authorization != "admin-token":
            return JSONResponse({"error": "This API key can only read"}, status_code=403)
        widget.update({k: v for k, v in body.items() if k == "name"})
        return widget

    admin, alice = CREDS
    ctx = factories.scan_context(
        [WIDGET_GET, WIDGET_PUT], credentials=_tenanted((admin, "a"), (alice, "a")),
        allow_mutation=True, client=TestClient(app),
    )
    assert WriteOracleCheck().run(ctx) == []
    assert widget["name"] == "original"


def test_a_cross_tenant_create_is_deleted_by_its_creator():
    """Across tenants the owner cannot see the attacker's object: its DELETE is a
    404 that cleanup read as "already gone", and the object stayed behind."""
    from fastapi import FastAPI, Header
    from fastapi.responses import JSONResponse
    from fastapi.testclient import TestClient

    app = FastAPI()
    store: dict[str, dict] = {}

    def who(auth: str | None) -> str | None:
        return {"admin-token": "a", "alice-token": "b"}.get(auth or "")

    @app.post("/widgets")
    def make(body: dict, authorization: str | None = Header(default=None)):
        tenant = who(authorization)
        if tenant is None:
            return JSONResponse({}, status_code=401)
        wid = str(len(store) + 1)
        store[wid] = {"id": wid, "tenant": tenant, **body}
        return JSONResponse(store[wid], status_code=201)

    @app.get("/widgets/{wid}")
    def read(wid: str, authorization: str | None = Header(default=None)):
        tenant = who(authorization)
        if tenant is None:
            return JSONResponse({}, status_code=401)
        item = store.get(wid)
        return item if item and item["tenant"] == tenant else JSONResponse({}, status_code=404)

    @app.delete("/widgets/{wid}")
    def remove(wid: str, authorization: str | None = Header(default=None)):
        item = store.get(wid)
        if item is None or item["tenant"] != who(authorization):
            return JSONResponse({}, status_code=404)
        del store[wid]
        return JSONResponse({}, status_code=204)

    admin, alice = CREDS
    ctx = factories.scan_context(
        [WIDGET_GET, WIDGET_POST, WIDGET_DELETE],
        credentials=_tenanted((admin, "a"), (alice, "b")),
        allow_mutation=True, client=TestClient(app),
    )
    assert WriteOracleCheck().run(ctx) == []  # correctly scoped: nothing to report
    assert store == {} and ctx.cleanup_failures == []
