"""Seeded cross-tenant BOLA — the create-as-A → read-as-B stateful sequence.

Driven against the in-process vulnapp, whose /records item read enforces auth
(anonymous is rejected) but never checks the owner, so an object created by one
identity is readable by another — the shape this check proves by seeding.
"""
from __future__ import annotations

from app.domain.enums import Confidence, Severity
from app.engine.base import TargetOperation
from app.engine.checks.seeded_bola import SeededBolaCheck
from tests import factories
from tests.vulnapp import _RECORDS

CREDS = [factories.credential("admin", "admin"), factories.credential("alice", "user")]

RECORD_POST = TargetOperation(
    id="r-post", method="POST", path="/records",
    params=[{"name": "body", "in": "body", "required": False, "schema": {"type": "string"}}],
)
RECORD_GET = TargetOperation(
    id="r-get", method="GET", path="/records/{record_id}",
    params=[{"name": "record_id", "in": "path", "required": True}],
)
RECORD_DELETE = TargetOperation(
    id="r-del", method="DELETE", path="/records/{record_id}",
    params=[{"name": "record_id", "in": "path", "required": True}],
)

# A create→read pair with NO auth on the item read: /widgets is simply public,
# so a second identity reading it proves nothing about scoping.
WIDGET_POST = TargetOperation(
    id="w-post", method="POST", path="/widgets",
    params=[{"name": "name", "in": "body", "required": False, "schema": {"type": "string"}}],
)
WIDGET_GET = TargetOperation(
    id="w-get", method="GET", path="/widgets/{widget_id}",
    params=[{"name": "widget_id", "in": "path", "required": True}],
)


def _ctx(operations, *, allow_mutation=True, creds=None):
    return factories.scan_context(
        operations,
        credentials=CREDS if creds is None else creds,
        allow_mutation=allow_mutation,
    )


def test_seeded_bola_confirms_cross_tenant_read():
    findings = SeededBolaCheck().run(_ctx([RECORD_POST, RECORD_GET, RECORD_DELETE]))
    assert len(findings) == 1
    f = findings[0]
    assert f.check == "seeded_bola"
    assert f.owasp_id == "API1:2023"
    assert f.confidence is Confidence.verified
    assert f.severity is Severity.high
    assert f.evidence["creator_identity"] == "alice"
    assert f.evidence["creator_role"] == "user"
    assert f.evidence["reader_identity"] == "admin"
    assert f.evidence["reader_role"] == "admin"
    assert f.evidence["route"] == "/records/{record_id}"
    assert f.evidence["anon_status"] == 401


def test_seeded_bola_cleans_up_the_object_it_created():
    before = set(_RECORDS)
    SeededBolaCheck().run(_ctx([RECORD_POST, RECORD_GET, RECORD_DELETE]))
    # The seeded object was deleted (a DELETE on the item path exists).
    assert set(_RECORDS) == before


def test_seeded_bola_records_no_response_value():
    """Only names and our own canary marker — never a response body value."""
    findings = SeededBolaCheck().run(_ctx([RECORD_POST, RECORD_GET, RECORD_DELETE]))
    ev = findings[0].evidence
    assert "response_sample" not in ev
    # The owner value the target stored (the reader's token) never appears.
    blob = " ".join(str(v) for v in ev.values())
    assert "admin-token" not in blob and "alice-token" not in blob


def test_seeded_bola_noop_without_mutation_flag():
    assert SeededBolaCheck().run(_ctx([RECORD_POST, RECORD_GET], allow_mutation=False)) == []


def test_seeded_bola_noop_with_single_identity():
    solo = [CREDS[0]]
    assert SeededBolaCheck().run(_ctx([RECORD_POST, RECORD_GET, RECORD_DELETE], creds=solo)) == []


def test_seeded_bola_ignores_a_public_item_read():
    # /widgets GET does not enforce auth, so the anonymous baseline is not
    # rejected and no cross-tenant claim is made.
    assert SeededBolaCheck().run(_ctx([WIDGET_POST, WIDGET_GET])) == []


def test_seeded_bola_only_uses_create_pairs():
    # Without a POST collection there is nothing to seed, so an update-only
    # spec produces no finding here (that shape belongs to the write oracle).
    record_put = TargetOperation(
        id="r-put", method="PUT", path="/records/{record_id}",
        params=[
            {"name": "record_id", "in": "path", "required": True},
            {"name": "body", "in": "body", "required": False, "schema": {"type": "string"}},
        ],
    )
    assert SeededBolaCheck().run(_ctx([record_put, RECORD_GET])) == []


# ---- multi-hop: a nested resource the engine reaches only by seeding a parent --

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


def test_seeded_bola_reaches_a_nested_resource():
    findings = SeededBolaCheck().run(_ctx(NESTED))
    assert len(findings) == 1, "the item under a seeded project is read cross-tenant"
    f = findings[0]
    assert f.owasp_id == "API1:2023"
    assert f.confidence is Confidence.verified
    assert f.evidence["route"] == "/projects/{project_id}/items/{item_id}"
    assert f.evidence["created_via"] == "POST /projects/{project_id}/items"


def test_seeded_bola_tears_down_the_whole_chain():
    from tests.vulnapp import _PROJECT_ITEMS, _PROJECTS

    SeededBolaCheck().run(_ctx(NESTED))
    # Both the seeded parent project and the created child item are gone.
    assert not _PROJECTS and not _PROJECT_ITEMS


def test_seeded_bola_skips_a_nested_pair_with_no_parent_producer():
    # No POST /projects, so the project parent cannot be seeded — the pair is
    # skipped rather than firing requests at a parent that does not exist.
    assert SeededBolaCheck().run(_ctx([ITEM_POST, ITEM_GET, ITEM_DELETE])) == []
