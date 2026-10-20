"""Seeded cross-tenant BOLA (API1) — the first producer→consumer sequence.

The read-only ``bola`` check infers cross-tenant access from *identical bodies*:
two identities see the same response, and a static-content guard rules out an
endpoint that echoes the request. That is a real signal, but it is inference —
it cannot say the object belongs to a *different* owner, only that the two
identities were not distinguished.

This check removes the inference by controlling the object's provenance. It runs
a real stateful sequence:

1. **Produce as A.** Create an object as identity A, tagging a string body field
   with a unique canary. The object provably belongs to A — A just made it.
2. **Consume as B.** Read that exact object back as a *different* identity B.

If B's read returns the canary, B read an object it does not own — a *verified*
cross-tenant BOLA, not a lead. An anonymous read is checked first as the
baseline: if the item read does not enforce auth at all, the object is simply
public and B reading it proves nothing about scoping.

Like the write oracle this **writes** to the target, so it is opt-in and off by
default (``ctx.allow_mutation`` / the ``mutate: true`` run flag) and cleans up:
the object it created is deleted where the spec exposes a DELETE on the item
path, or reported by id when it does not. It only uses **create** pairs — a
create is what guarantees A owns the object read back — and DELETE is never an
attack verb.
"""
from __future__ import annotations

import uuid

from app.domain.enums import Confidence, Severity
from app.engine.base import EngineFinding, ResolvedCredential, ScanContext, render_path
from app.engine.cleanup import cleanup_request, creation_request
from app.engine.request_bodies import create_body
from app.engine.resource_map import (
    ResourcePair,
    created_id,
    mutable_body_field,
)
from app.engine.sequence import (
    child_delete_op,
    nested_create_pairs,
    open_create_chain,
    run_cleanups,
)

_REJECTED = {401, 403}


class SeededBolaCheck:
    """Create an object as one identity, read it back as another (API1)."""

    key = "seeded_bola"
    # Its findings need the scan's identities; a run that left one out could
    # not have re-found them, so the diff must not call them fixed.
    needs_identities = True
    #: Creates an object to prove a cross-identity read, then deletes it.
    mutates = True

    @staticmethod
    def inapplicable(ctx: ScanContext) -> str | None:
        """Needs write permission, two identities, and a create/read pair."""
        if not ctx.allow_mutation:
            return "writes to the target are off (turn on writes to run it)"
        if ctx.identity_pair() is None:
            return ctx.pair_gap()
        return None

    def run(self, ctx: ScanContext) -> list[EngineFinding]:
        if not ctx.allow_mutation:
            return []
        # A create-as-A → read-as-B sequence needs two distinct identities.
        identities = ctx.identity_pair()
        if identities is None:
            return []
        creator, reader = identities.attacker, identities.owner

        findings: list[EngineFinding] = []
        for pair in nested_create_pairs(ctx.operations):
            try:
                with ctx.probe.test_case(
                    4 + 2 * len(pair.write.path_params), cleanup=1 + len(pair.write.path_params),
                    label=f"{self.key}:{pair.write.method}:{pair.write.path}",
                ) as case:
                    if case is None:
                        continue
                    hit = self._probe(ctx, pair, creator, reader)
                    case["outcome"] = "finding" if hit else "inconclusive"
            except Exception:  # noqa: BLE001 — one bad pair never aborts the check
                hit = None
            if hit is not None:
                findings.append(hit)
        return findings

    def _probe(
        self,
        ctx: ScanContext,
        pair: ResourcePair,
        creator: ResolvedCredential,
        reader: ResolvedCredential,
    ) -> EngineFinding | None:
        write, read = pair.write, pair.read  # POST collection ↔ GET item
        field = mutable_body_field(write)
        if field is None:
            return None
        fname = str(field["name"])
        canary = "aidx" + uuid.uuid4().hex[:10]

        # Multi-hop: create any parent resources the create path needs (as A),
        # so a nested create reaches a real object instead of a 404 on parent 1.
        chain = open_create_chain(ctx, write, creator)
        if chain is None:
            return None  # a parent could not be produced; nothing was left behind

        try:
            # Parent ids come from seeding; the create fills its own leaf.
            w = creation_request(
                ctx, write,
                render_path(write.path, chain.write_values),
                headers=creator.headers(),
                json=create_body(ctx, write, fname, canary),
            )
            if w is None or w.status >= 400:
                return None
            new_id = created_id(w.headers, w.text, read)
            if not new_id:
                ctx.cleanup_failures.append(
                    f"{write.method} {write.path}: created resource has no identifier"
                )
                return None

            rvals = chain.read_values(read, new_id)
            rpath = render_path(read.path, rvals)
            delete = child_delete_op(ctx.operations, read)

            hit: EngineFinding | None = None
            try:
                # Baseline: the item read must enforce auth, else the object is
                # public and B reading it says nothing about ownership scoping.
                anon = ctx.probe.send(read.method, rpath, headers={})
                r_b = ctx.probe.send(read.method, rpath, headers=reader.headers())
                if (
                    anon is not None
                    and anon.status in _REJECTED
                    and r_b is not None
                    and r_b.status < 400
                    and canary in r_b.text
                ):
                    hit = self._finding(
                        write, read, creator, reader, canary, anon.status, r_b, delete is not None
                    )
            finally:
                if delete is not None:
                    deleted = cleanup_request(
                        ctx, delete, render_path(delete.path, rvals), headers=creator.headers()
                    )
                    if hit is not None and not deleted:
                        hit.evidence["cleanup"] = "failed"
                else:
                    ctx.cleanup_failures.append(f"{write.method} {write.path}: no DELETE operation")
        finally:
            run_cleanups(ctx, chain.seeded, creator)  # delete seeded parents, child-first
        return hit

    def _finding(
        self,
        write,
        read,
        creator: ResolvedCredential,
        reader: ResolvedCredential,
        canary: str,
        anon_status: int,
        after,
        has_delete: bool,
    ) -> EngineFinding:
        cleaned = "deleted" if has_delete else "left in place (see id)"
        return EngineFinding(
            check=self.key,
            confidence=Confidence.verified,
            owasp_id="API1:2023",
            severity=Severity.high,
            title=f"Cross-tenant BOLA: {read.method} {read.path} readable by another identity",
            description=(
                f"An object created by identity '{creator.name}' "
                f"(role '{creator.role}') via {write.method} {write.path} was "
                f"read back by identity '{reader.name}' (role '{reader.role}') "
                f"through {read.method} {read.path} — the unique marker written "
                "at creation was returned. The item read rejects anonymous access "
                f"({anon_status}) yet is not scoped to the object's owner, so any "
                "authenticated identity can read another tenant's object by its id. "
                "A confirmed cross-tenant read (seeded read-back proof), not a lead."
            ),
            evidence={
                "method": read.method,
                "route": read.path,
                "path": f"{read.method} {read.path}",
                "created_via": f"{write.method} {write.path}",
                "canary": canary,
                "anon_status": anon_status,
                "reader_status": after.status,
                "creator_identity": creator.name,
                "creator_role": creator.role,
                "reader_identity": reader.name,
                "reader_role": reader.role,
                # ``identity`` names the offending reader for the remediation template.
                "identity": reader.name,
                "cleanup": cleaned,
            },
            operation_id=read.id,
        )
