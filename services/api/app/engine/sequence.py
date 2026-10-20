"""Multi-hop resource sequencing: create-parent → create-child → read.

`resource_map` pairs a create with the GET that reads it back, but only for a
*top-level* collection: ``POST /widgets`` ↔ ``GET /widgets/{id}``. A nested
resource — ``POST /projects/{project_id}/items`` — cannot be created without a
real ``project_id`` first, so a scanner that renders the parent id as a baseline
``1`` just gets a 404 and never reaches the object. Nested resources are exactly
where interesting authorization lives (an item under someone else's project),
so this module makes the engine reach them.

It does two things:

- **Find nested create pairs.** ``nested_create_pairs`` is ``build_resource_pairs``
  without the single-path-parameter guard, so a create whose read has parent ids
  (``GET /projects/{project_id}/items/{item_id}``) is paired too.
- **Seed the ancestors.** ``seed_ancestors`` walks a path's non-terminal ``{param}``
  segments, finds the ``POST`` that produces each parent collection, creates the
  parent (as the caller's identity), and captures the returned id — chaining
  earlier ids into later parent paths. It returns the resolved parent ids plus a
  child-first cleanup stack, so the caller tears the chain down in reverse.

Everything here **writes** (it creates parent resources), so it is only ever
called by a check already behind the ``mutate: true`` gate, and every object it
creates is DELETE-cleaned. Best-effort: a parent with no discoverable producer,
or a create that fails, aborts the chain (after cleaning up what was made) rather
than raising.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from app.engine.base import ResolvedCredential, ScanContext, TargetOperation, render_path
from app.engine.cleanup import cleanup_request, creation_request
from app.engine.resource_map import (
    ResourcePair,
    build_body,
    collection_of,
    created_id,
    mutable_body_field,
    path_values,
)


def nested_create_pairs(operations: list[TargetOperation]) -> list[ResourcePair]:
    """Create (write, read) pairs, including nested resources.

    Like ``build_resource_pairs``'s create branch, but the item read may carry
    parent path parameters (``GET /a/{a_id}/b/{b_id}``). The read's leaf id is
    resolved from the create response at run time; the parent ids are seeded by
    :func:`seed_ancestors` before the create fires.
    """
    gets = {op.path: op for op in operations if op.method == "GET"}
    pairs: list[ResourcePair] = []
    for op in operations:
        if op.method != "POST":
            continue
        item = next(
            (g for g in gets.values() if collection_of(g.path) == op.path and g.path_params),
            None,
        )
        if item is not None:
            pairs.append(ResourcePair(write=op, read=item, kind="create"))
    return pairs


def ancestor_specs(path: str) -> list[tuple[str, str]]:
    """Each non-terminal ``{param}`` in ``path`` and the collection that makes it.

    ``/projects/{project_id}/items/{item_id}`` → ``[("project_id", "/projects")]``:
    the trailing ``{item_id}`` is the object's own leaf id (produced by the create,
    not seeded), so it is excluded. A deeper ancestor's collection carries the
    earlier ``{param}`` segments, which are rendered from ids seeded before it.
    """
    segs = [s for s in path.split("/") if s]
    out: list[tuple[str, str]] = []
    for i, seg in enumerate(segs):
        if seg.startswith("{") and seg.endswith("}") and i != len(segs) - 1:
            param = seg[1:-1]
            collection = "/" + "/".join(segs[:i]) if i else "/"
            out.append((param, collection))
    return out


@dataclass
class SeededAncestors:
    """Resolved parent ids and how to delete the parents that were created."""

    #: parent path-parameter name → the id created for it.
    values: dict[str, str] = field(default_factory=dict)
    #: (delete op, rendered path values), child-first, for teardown in reverse.
    cleanups: list[tuple[TargetOperation, dict[str, str]]] = field(default_factory=list)


def _producer(operations: list[TargetOperation], collection: str) -> TargetOperation | None:
    return next((o for o in operations if o.method == "POST" and o.path == collection), None)


def _delete_for(operations: list[TargetOperation], item_path: str) -> TargetOperation | None:
    return next((o for o in operations if o.method == "DELETE" and o.path == item_path), None)


def seed_ancestors(
    ctx: ScanContext, op: TargetOperation, identity: ResolvedCredential
) -> SeededAncestors | None:
    """Create every parent resource ``op`` needs, as ``identity``.

    Returns the resolved parent ids and a child-first cleanup stack, or None when
    a parent cannot be produced (no ``POST`` on its collection, or a create that
    fails). On failure it deletes any parents already created before returning,
    so a half-built chain never leaks. When ``op`` has no ancestors the result is
    empty and always succeeds — a top-level create needs no seeding.
    """
    seeded = SeededAncestors()
    try:
        for param, collection in ancestor_specs(op.path):
            producer = _producer(ctx.operations, collection)
            if producer is None:
                run_cleanups(ctx, seeded, identity)
                return None
            ppath = render_path(collection, seeded.values)
            body = _seed_body(ctx, producer)
            resp = creation_request(ctx, producer, ppath, headers=identity.headers(), json=body)
            if resp is None or resp.status >= 400:
                run_cleanups(ctx, seeded, identity)
                return None
            new_id = created_id(resp.headers, resp.text, producer)
            if not new_id:
                ctx.cleanup_failures.append(
                    f"{producer.method} {producer.path}: created parent has no identifier"
                )
                run_cleanups(ctx, seeded, identity)
                return None
            seeded.values[param] = new_id
            item_path = f"{collection.rstrip('/')}/{{{param}}}"
            delete = _delete_for(ctx.operations, item_path)
            if delete is not None:
                seeded.cleanups.insert(0, (delete, dict(seeded.values)))
            else:
                ctx.cleanup_failures.append(f"POST {collection}: no parent DELETE operation")
    except Exception:
        run_cleanups(ctx, seeded, identity)
        raise
    return seeded


def _seed_body(ctx: ScanContext, producer: TargetOperation) -> dict[str, Any]:
    """A valid create body for a parent: every required field, plus a benign
    marker in one string field so the parent is well-formed."""
    from app.engine.request_bodies import create_body

    field_def = mutable_body_field(producer)
    if field_def is None:
        return build_body(producer, "_seed", "aidxseed")
    return create_body(ctx, producer, str(field_def["name"]), "aidxseed")


def run_cleanups(
    ctx: ScanContext, seeded: SeededAncestors, identity: ResolvedCredential
) -> None:
    """Delete the seeded parents, child-first (the order they were stacked)."""
    for delete, values in seeded.cleanups:
        cleanup_request(
            ctx, delete, render_path(delete.path, values), headers=identity.headers()
        )


@dataclass
class CreateChain:
    """A create pair's parents seeded, ready to render the create and read paths.

    The one place the three write-side create probes share: they all need the
    write path rendered with resolved parent ids, the read path rendered with
    those parents plus the created leaf id, and the seeded parents torn down at
    the end. What each does *between* (a cross-identity write, a mass-assignment
    field, a cross-identity read) is its own.
    """

    seeded: SeededAncestors
    #: Path values for the create op — baselines with every parent id resolved.
    write_values: dict[str, str]

    def read_values(self, read_op: TargetOperation, new_id: str) -> dict[str, str]:
        """Path values for the item read: seeded parents plus the created leaf."""
        leaf = read_op.path_params[-1]
        return {**path_values(read_op), **self.seeded.values, leaf: new_id}


def open_create_chain(
    ctx: ScanContext, write_op: TargetOperation, identity: ResolvedCredential
) -> CreateChain | None:
    """Seed every parent ``write_op`` needs (as ``identity``) and return the chain.

    None when a parent could not be produced — the caller does nothing, and any
    parents already made are torn down before returning. On success the caller
    must ``run_cleanups(ctx, chain.seeded, identity)`` when done, and may create
    and delete the child itself in between. Top-level creates seed nothing and
    always succeed.
    """
    seeded = seed_ancestors(ctx, write_op, identity)
    if seeded is None:
        return None
    return CreateChain(seeded=seeded, write_values={**path_values(write_op), **seeded.values})


def child_delete_op(
    operations: list[TargetOperation], read_op: TargetOperation
) -> TargetOperation | None:
    """The DELETE on the item read's path, for removing a created child."""
    return next(
        (o for o in operations if o.method == "DELETE" and o.path == read_op.path), None
    )
