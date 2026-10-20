"""Multi-hop resource sequencing — the create-parent → create-child → read chain.

The pure path analysis is tested directly; the seeding + teardown is driven
against the nested resource in the in-process vulnapp (``/projects/{id}/items``),
which the engine can only reach by creating the project first.
"""
from __future__ import annotations

from app.engine.base import TargetOperation
from app.engine.sequence import (
    ancestor_specs,
    nested_create_pairs,
    run_cleanups,
    seed_ancestors,
)
from tests import factories
from tests.vulnapp import _PROJECTS

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
NESTED = [PROJ_POST, PROJ_DELETE, ITEM_POST, ITEM_GET]


# ---- pure path analysis --------------------------------------------------------

def test_ancestor_specs_excludes_the_leaf_id():
    # A read's own object id is the leaf; only the parents are ancestors.
    assert ancestor_specs("/projects/{project_id}/items/{item_id}") == [
        ("project_id", "/projects")
    ]


def test_ancestor_specs_of_a_create_collection():
    # A nested create's path ends in the collection segment, so its one {param}
    # is a parent that must be seeded.
    assert ancestor_specs("/projects/{project_id}/items") == [("project_id", "/projects")]


def test_ancestor_specs_two_levels_deep():
    assert ancestor_specs("/orgs/{org_id}/projects/{project_id}/items") == [
        ("org_id", "/orgs"),
        ("project_id", "/orgs/{org_id}/projects"),
    ]


def test_top_level_path_has_no_ancestors():
    assert ancestor_specs("/widgets/{widget_id}") == []


def test_nested_create_pairs_include_the_deep_read():
    pairs = {(p.write.path, p.read.path) for p in nested_create_pairs(NESTED)}
    assert ("/projects/{project_id}/items", "/projects/{project_id}/items/{item_id}") in pairs


# ---- seeding + teardown against the vulnapp ------------------------------------

def _ctx(operations, *, allow_mutation=True):
    return factories.scan_context(operations, allow_mutation=allow_mutation)


def test_seed_ancestors_creates_and_resolves_the_parent():
    ctx = _ctx(NESTED)
    identity = ctx.lowest_priv()
    seeded = seed_ancestors(ctx, ITEM_POST, identity)
    assert seeded is not None
    assert seeded.values.get("project_id"), "the project id was seeded from the create"
    assert _PROJECTS, "a real project was created"
    # Tearing down removes exactly what was seeded.
    run_cleanups(ctx, seeded, identity)
    assert not _PROJECTS


def test_seed_ancestors_aborts_when_a_parent_has_no_producer():
    # No POST /projects → the project_id parent cannot be produced.
    ops = [ITEM_POST, ITEM_GET]  # producer for /projects is absent
    ctx = _ctx(ops)
    assert seed_ancestors(ctx, ITEM_POST, ctx.lowest_priv()) is None
    assert not _PROJECTS, "a failed chain leaves nothing behind"


def test_a_top_level_create_needs_no_seeding():
    ctx = _ctx(NESTED)
    seeded = seed_ancestors(ctx, PROJ_POST, ctx.lowest_priv())
    assert seeded is not None
    assert seeded.values == {} and seeded.cleanups == []
