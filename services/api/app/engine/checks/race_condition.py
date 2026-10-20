"""Race condition / limit overrun (a business-logic flaw — OWASP API6).

Some limits are only safe if they are checked and enforced atomically: "this
coupon is unused", "this username is free", "the balance covers this". An
endpoint that checks-then-acts with a gap between the two lets several requests
that arrive at once all pass the check before any of them acts — so the limit is
overrun. One coupon redeemed five times; one username taken twice.

The oracle needs real concurrency, so this check is the one place the engine
fires a **burst that bypasses the per-host rate limiter** (``HttpProbe.burst``),
and it no-ops unless the transport can actually do that — a serialized "burst"
would never catch a race. It also writes, so it is gated on ``mutate: true``
like every state-changing probe.

The sequence, built to avoid false positives:

1. Create an object with a unique value, then create it **again sequentially**
   with the same value. If the duplicate is *not* rejected, the endpoint
   enforces no uniqueness — there is no limit to overrun, so it is skipped.
2. Only then fire ``settings.race_burst`` **concurrent** creates of a fresh
   unique value. If more than one succeeds, the uniqueness check has a
   time-of-check/time-of-use gap — a verified overrun.

Everything it creates is cleaned up with a DELETE where the spec exposes one.
"""
from __future__ import annotations

import uuid
from typing import Any

from app.domain.enums import Confidence, Severity
from app.engine.base import EngineFinding, ProbeResult, ScanContext, render_path
from app.engine.cleanup import cleanup_request
from app.engine.request_bodies import create_body
from app.engine.resource_map import (
    ResourcePair,
    build_resource_pairs,
    created_id,
    path_values,
)

# Body field names that usually carry a uniqueness constraint. Preferred as the
# raced value; otherwise the first string field is used.
_UNIQUE_HINTS = (
    "email", "username", "user", "login", "slug", "handle", "name",
    "imei", "sku", "code", "key", "token", "reference", "ref",
)


def _unique_field(op: Any) -> str | None:
    """A string body field to race on — a uniqueness-hinting name if there is one."""
    string_fields = [
        str(p["name"])
        for p in op.params
        if p.get("in") == "body"
        and p.get("name")
        and (p.get("schema") or {}).get("type") in (None, "string")
        and not (p.get("schema") or {}).get("enum")
    ]
    for hint in _UNIQUE_HINTS:
        for name in string_fields:
            if hint in name.lower():
                return name
    return string_fields[0] if string_fields else None


def is_overrun(results: list[ProbeResult]) -> bool:
    """More than one concurrent create succeeded — the uniqueness check raced."""
    return sum(1 for r in results if 200 <= r.status < 300) > 1


def _rejects_duplicate(result: ProbeResult | None) -> bool:
    """A sequential duplicate was refused — so a constraint exists to overrun.

    Only conflict-class statuses count: a bare 400 is ambiguous and a 401/404/500
    is an auth/routing/server failure, not a uniqueness signal. The body keyword
    match catches the 400-with-"already exists" case.
    """
    if result is None:
        return False
    if result.status in (409, 422):
        return True
    body = (result.text or "").lower()
    return any(w in body for w in ("exist", "duplicate", "already", "taken", "unique", "conflict"))


class RaceConditionCheck:
    key = "race_condition"
    #: Fires a concurrent burst of writes and DELETE-cleans what it creates.
    mutates = True

    @staticmethod
    def inapplicable(ctx: ScanContext) -> str | None:
        if not ctx.allow_mutation:
            return "writes to the target are off (turn on writes to run it)"
        if not ctx.probe.can_burst():
            return (
                "the transport cannot fire a concurrent burst, and a race that "
                "is not raced proves nothing"
            )
        return None

    def run(self, ctx: ScanContext) -> list[EngineFinding]:
        if not ctx.allow_mutation or not ctx.probe.can_burst():
            return []
        from app.core.config import settings

        # A caller allowed to create at all: a read-only key gets 403 and
        # tests nothing.
        identity = ctx.lowest_writer() or ctx.primary_credential()
        if identity is None:
            return []

        findings: list[EngineFinding] = []
        for pair in build_resource_pairs(ctx.operations):
            if pair.kind != "create":
                continue
            try:
                hit = self._probe(ctx, pair, identity, settings.race_burst)
            except Exception:  # noqa: BLE001 — one bad pair never aborts the check
                hit = None
            if hit is not None:
                findings.append(hit)
        return findings

    def _probe(
        self, ctx: ScanContext, pair: ResourcePair, identity, burst: int
    ) -> EngineFinding | None:
        write, read = pair.write, pair.read
        field = _unique_field(write)
        if field is None:
            return None
        wpath = render_path(write.path, path_values(write))
        hdrs = identity.headers()
        created: list[str] = []
        # One seed for the whole probe: the duplicate must differ from the first
        # create only by being the same value of ``field`` again.
        seed = uuid.uuid4().hex[:12]

        def create(value: str) -> ProbeResult | None:
            r = ctx.probe.send(
                write.method, wpath, headers=hdrs,
                json=create_body(ctx, write, field, value, seed=seed),
            )
            if r is not None and 200 <= r.status < 300:
                cid = created_id(r.headers, r.text, read)
                if cid:
                    created.append(cid)
            return r

        try:
            # 1. Prove a uniqueness constraint exists: a sequential duplicate must
            #    be refused, or there is no limit here to overrun.
            probe_value = "aidx" + uuid.uuid4().hex[:10]
            first = create(probe_value)
            if first is None or not (200 <= first.status < 300):
                return None
            if not _rejects_duplicate(create(probe_value)):
                return None

            # 2. Race a fresh value: fire the burst concurrently.
            race_value = "aidx" + uuid.uuid4().hex[:10]
            results = ctx.probe.burst(
                write.method,
                wpath,
                count=burst,
                headers=hdrs,
                json=create_body(ctx, write, field, race_value, seed=seed),
            )
            if results is None:
                return None
            for r in results:
                if 200 <= r.status < 300:
                    cid = created_id(r.headers, r.text, read)
                    if cid:
                        created.append(cid)

            succeeded = sum(1 for r in results if 200 <= r.status < 300)
            if not is_overrun(results):
                return None
            return self._finding(pair, identity, field, succeeded, len(results))
        finally:
            self._cleanup(ctx, read, created, identity)

    def _cleanup(self, ctx: ScanContext, read_op: Any, ids: list[str], identity) -> None:
        """DELETE every object created during the probe, where a DELETE exists."""
        delete_op = next(
            (
                o
                for o in ctx.operations
                if o.method == "DELETE" and o.path == read_op.path
            ),
            None,
        )
        if delete_op is None or not read_op.path_params:
            if ids:
                ctx.cleanup_failures.append(f"{read_op.path}: no usable DELETE operation")
            return
        id_param = read_op.path_params[0]
        for cid in set(ids):
            vals = path_values(read_op)
            vals[id_param] = cid
            cleanup_request(
                ctx, delete_op, render_path(read_op.path, vals), headers=identity.headers()
            )

    def _finding(
        self, pair: ResourcePair, identity, field: str, succeeded: int, fired: int
    ) -> EngineFinding:
        write = pair.write
        return EngineFinding(
            check=self.key,
            owasp_id="API6:2023",
            severity=Severity.high,
            # We watched the constraint reject a sequential duplicate and then let
            # concurrent ones through: the race is observed, not inferred.
            confidence=Confidence.verified,
            title=f"Race condition on {write.method} {write.path} ('{field}')"[:255],
            description=(
                f"{write.method} {write.path} enforces a uniqueness constraint on "
                f"'{field}' sequentially — a duplicate is refused — but {succeeded} "
                f"of {fired} identical requests sent at once all succeeded. The "
                "check and the write are not atomic (time-of-check/time-of-use), "
                "so the limit can be overrun by racing it: the shape behind "
                "double-spends, coupon reuse and duplicate accounts. All objects "
                "created by this probe receive cleanup attempts where the spec exposes a "
                "DELETE; any failed attempts are reported in scan events."
            ),
            evidence={
                "method": write.method,
                "route": write.path,
                "field": field,
                "identity": identity.name,
                "identity_role": identity.role,
                "requests_fired": fired,
                "requests_succeeded": succeeded,
            },
            operation_id=write.id,
        )
