"""Write oracle + authorization-on-write (BOLA/BFLA).

Unlike every other check, this one *writes* to the target, so it is opt-in and
off by default: it no-ops unless ``ctx.allow_mutation`` is set (the ``mutate: true``
run flag). It proves a write actually took effect — and took effect across
identities — instead of trusting a 2xx status:

1. Pair a mutating op with a GET that reads the same resource back
   (``app/engine/resource_map.py``).
2. Send the write as the **low-privilege** identity, embedding a unique canary in
   a string body field.
3. Read the resource back as the **high-privilege** (owner) identity. If the
   canary is there, a lower-privilege identity's write persisted to an object the
   owner sees — object/function-level authorization is not enforced on the write.
   This is a *verified* finding (read-back proof), not a reflection lead.

Safety: updates are restorable — the original field value is captured first and
written back afterwards. Creates are cleaned up with a DELETE when the spec has
one; otherwise the new object id is reported so it can be removed by hand. DELETE
is never used as an attack verb here (destructive, not restorable).
"""
from __future__ import annotations

import uuid

from app.domain.enums import Confidence, Severity
from app.domain.privilege import is_privileged
from app.engine.base import EngineFinding, ResolvedCredential, ScanContext, render_path
from app.engine.cleanup import cleanup_as, cleanup_request, creation_request
from app.engine.request_bodies import create_body
from app.engine.resource_map import (
    ResourcePair,
    build_resource_pairs,
    json_object,
)
from app.engine.resource_map import (
    build_body as _build_body,
)
from app.engine.resource_map import (
    created_id as _created_id,
)
from app.engine.resource_map import (
    mutable_body_field as _mutable_body_field,
)
from app.engine.resource_map import (
    path_values as _path_values,
)
from app.engine.sequence import (
    child_delete_op,
    nested_create_pairs,
    open_create_chain,
    run_cleanups,
)


def _writer_pairs(
    ctx: ScanContext,
) -> list[tuple[ResolvedCredential, ResolvedCredential, bool]]:
    """``(owner, writer, role_boundary)`` for each write test the identities allow.

    The cross-identity pair always (across tenants once tenants are declared).
    With tenants declared, also the pair inside one tenant whose ranks differ:
    a viewer writing its own workspace's object is the function-level boundary,
    and pairing across tenants alone stopped testing it.
    """
    pairs: list[tuple[ResolvedCredential, ResolvedCredential, bool]] = []
    cross = ctx.identity_pair()
    if cross is not None:
        pairs.append((cross.owner, cross.attacker, False))
    if ctx.tenants_declared():
        within = ctx.privilege_pair()
        if within is not None and ctx.privilege_rank(within.owner) > ctx.privilege_rank(
            within.attacker
        ):
            pairs.append((within.owner, within.attacker, True))
    return pairs


def _extract_field(text: str, field: str) -> str | None:
    """The current value of ``field`` in a JSON object response, for restore."""
    data = json_object(text)
    if data is not None and isinstance(data.get(field), str):
        return str(data[field])
    return None


class WriteOracleCheck:
    key = "write_authz"
    # Its findings need the scan's identities; a run that left one out could
    # not have re-found them, so the diff must not call them fixed.
    needs_identities = True
    #: Creates and updates target resources (and restores them). Never
    #: concurrent with another writer touching the same objects.
    mutates = True

    @staticmethod
    def inapplicable(ctx: ScanContext) -> str | None:
        """Needs write permission, two identities, and a create/update pair."""
        if not ctx.allow_mutation:
            return "writes to the target are off (turn on writes to run it)"
        if not _writer_pairs(ctx):
            return ctx.pair_gap()
        if not build_resource_pairs(ctx.operations):
            return (
                "no spec-paired write and read-back endpoints — proving a write "
                "persisted needs a POST/PUT plus a GET of the same resource"
            )
        return None

    def run(self, ctx: ScanContext) -> list[EngineFinding]:
        if not ctx.allow_mutation:
            return []
        pairs = _writer_pairs(ctx)
        findings: list[EngineFinding] = []
        for owner, attacker, role_boundary in pairs:
            findings.extend(self._probe_pairs(ctx, owner, attacker, role_boundary))
        return findings

    def _probe_pairs(
        self,
        ctx: ScanContext,
        owner: ResolvedCredential,
        attacker: ResolvedCredential,
        role_boundary: bool,
    ) -> list[EngineFinding]:
        # Updates stay single-hop (an existing object's parents already exist);
        # creates use the multi-hop builder so nested resources are seeded.
        update_pairs = [p for p in build_resource_pairs(ctx.operations) if p.kind == "update"]
        create_pairs = nested_create_pairs(ctx.operations)

        findings: list[EngineFinding] = []
        for pair in update_pairs:
            try:
                with ctx.probe.test_case(
                    4, cleanup=1,
                    label=f"{self.key}:{pair.write.method}:{pair.write.path}",
                ) as case:
                    if case is None:
                        continue
                    hit = self._probe_update(ctx, pair, owner, attacker, role_boundary)
                    case["outcome"] = "finding" if hit else "inconclusive"
            except Exception:  # noqa: BLE001 — one bad pair never aborts the check
                hit = None
            if hit is not None:
                findings.append(hit)
        for pair in create_pairs:
            try:
                with ctx.probe.test_case(
                    5 + 2 * len(pair.write.path_params), cleanup=1 + len(pair.write.path_params),
                    label=f"{self.key}:{pair.write.method}:{pair.write.path}",
                ) as case:
                    if case is None:
                        continue
                    hit = self._probe_create(ctx, pair, owner, attacker, role_boundary)
                    case["outcome"] = "finding" if hit else "inconclusive"
            except Exception:  # noqa: BLE001 — one bad pair never aborts the check
                hit = None
            if hit is not None:
                findings.append(hit)
        return findings

    def _probe_update(
        self, ctx, pair: ResourcePair, owner, attacker, role_boundary: bool = False
    ) -> EngineFinding | None:
        write, read = pair.write, pair.read
        field = _mutable_body_field(write)
        if field is None:
            return None
        fname = str(field["name"])
        pvals = _path_values(write, ctx.resource_ids)
        wpath = render_path(write.path, pvals)
        rpath = render_path(read.path, pvals)  # same template + baseline → same object

        before = ctx.probe.send(read.method, rpath, headers=owner.headers())
        if before is None:
            return None
        original = _extract_field(before.text, fname)

        # Never overwrite a field whose original value cannot be restored.
        if original is None:
            return None
        canary = "aidx" + uuid.uuid4().hex[:10]
        hit: EngineFinding | None = None
        try:
            w = ctx.probe.send(
                write.method, wpath, headers=attacker.headers(),
                json=_build_body(write, fname, canary)
            )
            if w is not None and w.status < 400:
                after = ctx.probe.send(read.method, rpath, headers=owner.headers())
                if after is not None and canary in after.text:
                    hit = self._finding(
                        write, read, owner, attacker, fname, canary, w.status, after, "update",
                        role_boundary=role_boundary,
                    )
        finally:
            restored = cleanup_request(
                ctx, write, wpath, headers=owner.headers(), json=_build_body(write, fname, original)
            )
            if hit is not None:
                hit.evidence["cleanup"] = "restored" if restored else "failed"
        return hit

    def _probe_create(
        self, ctx, pair: ResourcePair, owner, attacker, role_boundary: bool = False
    ) -> EngineFinding | None:
        write, read = pair.write, pair.read  # POST collection ↔ GET item
        field = _mutable_body_field(write)
        if field is None:
            return None
        fname = str(field["name"])
        canary = "aidx" + uuid.uuid4().hex[:10]

        # Seed any parent resources as the owner (legitimate scaffolding); the
        # attack is the low-priv child write, read back by the owner.
        chain = open_create_chain(ctx, write, owner)
        if chain is None:
            return None
        try:
            w = creation_request(
                ctx, write,
                render_path(write.path, chain.write_values),
                headers=attacker.headers(),
                json=create_body(ctx, write, fname, canary),
            )
            if w is None or w.status >= 400:
                return None
            new_id = _created_id(w.headers, w.text, read)
            if not new_id:
                ctx.cleanup_failures.append(
                    f"{write.method} {write.path}: created resource has no identifier"
                )
                return None

            rvals = chain.read_values(read, new_id)
            hit: EngineFinding | None = None
            try:
                after = ctx.probe.send(
                    read.method, render_path(read.path, rvals), headers=owner.headers()
                )
                if after is not None and canary in after.text:
                    hit = self._finding(
                        write, read, owner, attacker, fname, canary, w.status, after, "create",
                        role_boundary=role_boundary,
                    )
            finally:
                delete = child_delete_op(ctx.operations, read)
                # As the creator first: across tenants the owner's DELETE is a
                # 404 that reads as "gone" while the object stays.
                deleted = delete is not None and cleanup_as(
                    ctx, delete, render_path(delete.path, rvals), [attacker, owner]
                )
                if delete is None:
                    ctx.cleanup_failures.append(f"{write.method} {write.path}: no DELETE operation")
                if hit is not None:
                    hit.evidence["cleanup"] = "deleted" if deleted else "failed"
        finally:
            run_cleanups(ctx, chain.seeded, owner)  # delete seeded parents, child-first
        return hit

    def _finding(
        self,
        write,
        read,
        owner: ResolvedCredential,
        attacker: ResolvedCredential,
        field: str,
        canary: str,
        wstatus: int,
        after,
        kind: str,
        *,
        role_boundary: bool = False,
    ) -> EngineFinding:
        priv = is_privileged(write.path, write.auth_scope)
        # Within one tenant the two identities differ only by role, so a write
        # the lower one should have been refused is function-level (API5) —
        # whatever the path is called.
        function_level = priv or role_boundary
        owasp = "API5:2023" if function_level else "API1:2023"
        label = "BFLA (write)" if function_level else "BOLA (write)"
        return EngineFinding(
            check=self.key,
            confidence=Confidence.verified,
            owasp_id=owasp,
            severity=Severity.critical if priv else Severity.high,
            title=f"{label}: {write.method} {write.path} write by '{attacker.name}' persisted",
            description=(
                f"A {kind} to {write.path} sent as the "
                f"{'lower-privilege ' if role_boundary else ''}identity "
                f"'{attacker.name}' (role '{attacker.role}') persisted: the value "
                f"written to '{field}' was read back by identity '{owner.name}' "
                f"(role '{owner.role}') via {read.method} {read.path}. The "
                "write took effect across identities, so authorization is not enforced on "
                "this write — a confirmed vulnerability (read-back proof). "
                "Cleanup outcome is recorded in the evidence and scan events."
            ),
            evidence={
                "write": f"{write.method} {write.path}",
                "read_back": f"{read.method} {read.path}",
                "field": field,
                "canary": canary,
                "write_status": wstatus,
                "writer_identity": attacker.name,
                "writer_role": attacker.role,
                "reader_identity": owner.name,
                "reader_role": owner.role,
                "kind": kind,
                "boundary": "role" if role_boundary else "identity",
                "response_sample": after.text[:400],
            },
            operation_id=write.id,
            # The catalogue line is about ownership; here the object was the
            # writer's own tenant's, and what failed is the role check.
            remediation=(
                f"Check the caller's role before {write.method} {write.path} changes "
                f"anything: '{attacker.name}' (role '{attacker.role}') should be refused "
                "this write, yet it persisted. Enforce the permission on the server for "
                "every write route — a read-only key or viewer role must get 403 — rather "
                "than relying on the client to hide the action."
            )
            if role_boundary and not priv
            else "",
        )
