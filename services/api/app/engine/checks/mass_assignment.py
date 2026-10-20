"""Mass assignment (OWASP API6): fields the client can set that it should not.

The write oracle asks "did a write by the wrong *identity* persist". This asks a
different question about the same machinery: did a write of the wrong *field*
persist. An endpoint that binds the whole request body onto its record lets a
caller set properties the server is supposed to own — a role, an owner, a
verified flag, a balance — even though the API never documents them as input.

The oracle, and why each part is there:

1. Read the object first. A candidate must be a field that is **already on the
   object** (so we know its original value and can put it back) whose name means
   server-owned state, and which the write operation's request schema **does not
   declare**. That last condition is what makes this a bug rather than a
   feature: an API that documents ``role`` as input has decided to accept it.
2. Write it with a unique canary.
3. Read back and confirm the field now equals the canary. That is *verified* —
   the value the client sent is the value the server stored.
4. Restore the original value.

On a **create** pair (``POST`` collection ↔ ``GET`` item) there is no object to
read first, so the same oracle runs forward: inject an undeclared server-owned
field from a curated shortlist at creation, read the *created* object back, and
confirm the field equals the canary. It is still verified — the read-back proves
persistence — and the object the probe creates is DELETE-cleaned afterwards, so
nothing is left behind. Update pairs restore; create pairs delete.

**A canary, never a real escalating value.** Sending ``{"role": "admin"}`` would
actually escalate privileges on someone's system; sending ``{"role": "aidx…"}``
proves the field is client-writable, which is the finding, and leaves nothing
dangerous behind. It is also why only string-shaped fields are probed — there is
no non-escalating value for ``is_admin``, so boolean flags are named in the
report's coverage caveats rather than probed.

Opt-in like every state-changing probe: no-ops unless ``ctx.allow_mutation``
(the ``mutate: true`` run flag).
"""
from __future__ import annotations

import re
import uuid
from typing import Any

from app.domain.enums import Confidence, Severity
from app.engine.base import EngineFinding, ScanContext, render_path
from app.engine.cleanup import cleanup_request, creation_request
from app.engine.request_bodies import create_body
from app.engine.resource_map import (
    ResourcePair,
    build_body,
    build_resource_pairs,
    created_id,
    json_object,
    path_values,
)
from app.engine.sequence import (
    CreateChain,
    child_delete_op,
    nested_create_pairs,
    open_create_chain,
    run_cleanups,
)

#: Field names that name server-owned state, by what an attacker gains.
#: Matched against a normalised name (lowercased, separators stripped), so
#: ``owner_id``, ``ownerId`` and ``OwnerID`` are one entry.
#:
#: Kept deliberately tight. The check already requires the field to be *absent
#: from the request schema*, which carries most of the precision — but a name
#: like ``status`` or ``tier`` is legitimately client-settable often enough that
#: including it would trade that precision away for very little.
_PRIVILEGE = (
    "role", "roles", "isadmin", "admin", "isstaff", "issuperuser", "superuser",
    "permissions", "permission", "scopes", "privileges", "group", "groups",
)
_OWNERSHIP = (
    "owner", "ownerid", "userid", "accountid", "tenantid", "organizationid",
    "orgid", "createdby", "authorid",
)
_STATE = (
    "balance", "credits", "quota", "verified", "isverified", "emailverified",
    "confirmed", "isconfirmed", "active", "isactive", "approved", "isapproved",
)

_FAMILIES: tuple[tuple[str, tuple[str, ...], Severity], ...] = (
    # Setting your own role is the whole ballgame — hence critical.
    ("privilege", _PRIVILEGE, Severity.critical),
    ("ownership", _OWNERSHIP, Severity.high),
    ("state", _STATE, Severity.high),
)

_LABEL = {
    "privilege": "a privilege field",
    "ownership": "an ownership field",
    "state": "a server-controlled state field",
}

# Fields probed per resource pair. Each costs a read, a write and a read-back,
# so this bounds a check that writes to the target.
_MAX_FIELDS_PER_PAIR = 2

# Create-time probing can't read a not-yet-existing object to discover its
# fields, so it injects a curated shortlist of the most impactful *string-shaped*
# server-owned names (a canary is a string; a boolean ``is_admin`` has no
# non-escalating value). Names the create schema declares are skipped, and a hit
# is still confirmed by reading the created object back — verified, not guessed.
# Ordered most-severe first so the per-pair cap keeps the findings that matter.
_CREATE_PROBE_NAMES = ("role", "group", "owner", "owner_id", "tenant_id", "created_by")


def normalise(name: str) -> str:
    """Field name to its comparison form: lowercase, separators removed."""
    return re.sub(r"[^a-z0-9]", "", name.lower())


def classify(name: str) -> tuple[str, Severity] | None:
    """The family a field name belongs to, or None if it is not server-owned."""
    key = normalise(name)
    for family, names, severity in _FAMILIES:
        if key in names:
            return family, severity
    return None


def declared_body_fields(op: Any) -> set[str]:
    """Names the operation's request body schema declares — documented input."""
    return {
        str(p["name"])
        for p in op.params
        if p.get("in") == "body" and p.get("name")
    }


def candidate_fields(op: Any, current: dict[str, Any]) -> list[tuple[str, str, Severity]]:
    """Server-owned fields on the object that the write schema does not declare.

    Only string-valued fields: a canary is a string, and there is no
    non-escalating value to write into a boolean flag.
    """
    declared = {normalise(n) for n in declared_body_fields(op)}
    out: list[tuple[str, str, Severity]] = []
    for name, value in current.items():
        if not isinstance(value, str) or normalise(name) in declared:
            continue
        hit = classify(name)
        if hit is not None:
            out.append((name, hit[0], hit[1]))
    # Most-severe first, so the cap keeps the findings that matter.
    order = {Severity.critical: 0, Severity.high: 1}
    return sorted(out, key=lambda t: (order.get(t[2], 2), t[0]))


class MassAssignmentCheck:
    """Writes an undeclared server-owned field and proves it was bound (API6)."""

    key = "mass_assignment"
    #: Writes a canary into a server-owned field, then restores or deletes.
    mutates = True

    @staticmethod
    def inapplicable(ctx: ScanContext) -> str | None:
        if not ctx.allow_mutation:
            return "writes to the target are off (turn on writes to run it)"
        return None

    def run(self, ctx: ScanContext) -> list[EngineFinding]:
        if not ctx.allow_mutation:
            return []
        # A caller allowed to create at all: a read-only key gets 403 and
        # tests nothing.
        identity = ctx.lowest_writer() or ctx.primary_credential()
        if identity is None:
            return []

        # Updates stay single-hop; creates use the multi-hop builder so a nested
        # resource's parents are seeded before the create.
        update_pairs = [p for p in build_resource_pairs(ctx.operations) if p.kind == "update"]
        create_pairs = nested_create_pairs(ctx.operations)

        findings: list[EngineFinding] = []
        for pair in update_pairs:
            try:
                with ctx.probe.test_case(
                    1 + 3 * _MAX_FIELDS_PER_PAIR, cleanup=_MAX_FIELDS_PER_PAIR,
                    label=f"mass-assignment:update:{pair.write.path}",
                ) as case:
                    if case is not None:
                        findings.extend(self._probe(ctx, pair, identity))
            except Exception:  # noqa: BLE001 — one bad pair never aborts the check
                continue
        for pair in create_pairs:
            try:
                parents = len(pair.write.path_params)
                with ctx.probe.test_case(
                    3 * _MAX_FIELDS_PER_PAIR + 2 * parents,
                    cleanup=_MAX_FIELDS_PER_PAIR + parents,
                    label=f"mass-assignment:create:{pair.write.path}",
                ) as case:
                    if case is not None:
                        findings.extend(self._probe_create(ctx, pair, identity))
            except Exception:  # noqa: BLE001 — one bad pair never aborts the check
                continue
        return findings

    def _probe(self, ctx: ScanContext, pair: ResourcePair, identity) -> list[EngineFinding]:
        write, read = pair.write, pair.read
        # Same template + the same spec-valid baselines → the same object.
        rpath = render_path(read.path, path_values(write, ctx.resource_ids))

        before = ctx.probe.send(read.method, rpath, headers=identity.headers())
        if before is None:
            return []
        current = json_object(before.text)
        if not current:
            return []

        findings: list[EngineFinding] = []
        for name, family, severity in candidate_fields(write, current)[:_MAX_FIELDS_PER_PAIR]:
            hit = self._probe_field(ctx, pair, identity, name, family, severity, current)
            if hit is not None:
                findings.append(hit)
        return findings

    def _probe_create(self, ctx: ScanContext, pair: ResourcePair, identity) -> list[EngineFinding]:
        """Create-time mass assignment: set an undeclared server-owned field at
        creation, confirm it by reading the created object back, then delete it.

        Any parent resources are seeded once for the pair (as ``identity``) and
        torn down after every field is probed, so a nested create is reached
        without re-creating the parent per field."""
        write, read = pair.write, pair.read
        declared = {normalise(n) for n in declared_body_fields(write)}
        chain = open_create_chain(ctx, write, identity)
        if chain is None:
            return []  # a parent could not be produced; nothing was left behind
        delete_op = child_delete_op(ctx.operations, read)
        findings: list[EngineFinding] = []
        try:
            probed = 0
            for name in _CREATE_PROBE_NAMES:
                if probed >= _MAX_FIELDS_PER_PAIR:
                    break
                if normalise(name) in declared:
                    continue  # documented input — accepting it is a decision, not a bug
                hit = classify(name)
                if hit is None:
                    continue
                probed += 1
                found = self._probe_create_field(
                    ctx, pair, identity, name, hit[0], hit[1], chain, delete_op
                )
                if found is not None:
                    findings.append(found)
        finally:
            run_cleanups(ctx, chain.seeded, identity)  # delete seeded parents, child-first
        return findings

    def _probe_create_field(
        self,
        ctx: ScanContext,
        pair: ResourcePair,
        identity,
        field: str,
        family: str,
        severity: Severity,
        chain: CreateChain,
        delete_op,
    ) -> EngineFinding | None:
        write, read = pair.write, pair.read
        canary = "aidx" + uuid.uuid4().hex[:10]
        w = creation_request(
            ctx, write,
            render_path(write.path, chain.write_values),
            headers=identity.headers(),
            json=create_body(ctx, write, field, canary),
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
        hit: EngineFinding | None = None
        try:
            after = ctx.probe.send(read.method, rpath, headers=identity.headers())
            body = json_object(after.text) if after is not None else None
            if body is not None and body.get(field) == canary:
                hit = self._finding(pair, identity, field, family, severity, w.status, "create")
        finally:
            if delete_op is not None:
                deleted = cleanup_request(
                    ctx, delete_op, render_path(delete_op.path, rvals), headers=identity.headers()
                )
                if hit is not None and not deleted:
                    hit.evidence["cleanup"] = "failed"
            else:
                ctx.cleanup_failures.append(f"{write.method} {write.path}: no DELETE operation")
                if hit is not None:
                    hit.evidence["cleanup"] = "unavailable"
        return hit

    def _probe_field(
        self,
        ctx: ScanContext,
        pair: ResourcePair,
        identity,
        field: str,
        family: str,
        severity: Severity,
        current: dict[str, Any],
    ) -> EngineFinding | None:
        write, read = pair.write, pair.read
        pvals = path_values(write, ctx.resource_ids)
        wpath = render_path(write.path, pvals)
        rpath = render_path(read.path, pvals)
        original = current[field]

        canary = "aidx" + uuid.uuid4().hex[:10]
        hit: EngineFinding | None = None
        try:
            w = ctx.probe.send(
                write.method,
                wpath,
                headers=identity.headers(),
                json=build_body(write, field, canary),
            )
            if w is None:
                return None

            if w.status < 400:
                after = ctx.probe.send(read.method, rpath, headers=identity.headers())
                body = json_object(after.text) if after is not None else None
                if body is not None and body.get(field) == canary:
                    hit = self._finding(pair, identity, field, family, severity, w.status, "update")
        finally:
            # Restore, always — the write happened whether or not it was a
            # finding, and even if the read-back raised.
            restored = cleanup_request(
                ctx, write,
                wpath,
                headers=identity.headers(),
                json=build_body(write, field, original),
            )
            if hit is not None and not restored:
                hit.evidence["cleanup"] = "failed"
        return hit

    def _finding(
        self,
        pair: ResourcePair,
        identity,
        field: str,
        family: str,
        severity: Severity,
        status: int,
        kind: str,
    ) -> EngineFinding:
        write, read = pair.write, pair.read
        if kind == "create":
            bound = f"accepted '{field}' at creation"
            cleanup = (
                "A canary was written rather than a real privileged value, and the "
                "cleanup outcome is recorded in the evidence and scan events."
            )
        else:
            bound = f"bound '{field}' straight from the request body"
            cleanup = (
                "A canary was written rather than a real privileged value, and the "
                "cleanup outcome is recorded in the evidence and scan events."
            )
        return EngineFinding(
            check=self.key,
            owasp_id="API6:2023",
            severity=severity,
            # The value the client sent is the value the server stored, proven by
            # a read-back. Nothing is inferred.
            confidence=Confidence.verified,
            title=(
                f"Mass assignment: '{field}' is client-writable on "
                f"{write.method} {write.path}"
            )[:255],
            description=(
                f"{write.method} {write.path} {bound} as identity "
                f"'{identity.name}' (role '{identity.role}'), even though the "
                f"operation's request schema never declares it. The value was "
                f"read back unchanged from "
                f"{read.method} {read.path}, so the server stored what the client "
                f"sent. '{field}' is {_LABEL[family]}: state the server is "
                f"supposed to own. {cleanup}"
            ),
            evidence={
                "method": write.method,
                "route": write.path,
                "read_back": f"{read.method} {read.path}",
                "field": field,
                "family": family,
                "identity": identity.name,
                "identity_role": identity.role,
                "write_status": status,
                "declared_body_fields": sorted(declared_body_fields(write)),
                "cleanup": "deleted" if kind == "create" else "restored",
            },
            operation_id=write.id,
        )
