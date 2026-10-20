"""Authorization checks: BOLA (API1) and BFLA (API5).

These are the highest-value API checks and the reason dual credentials exist.
Both are rebuilt around an explicit authorization baseline so a match is
evidence of a *broken boundary*, not of a healthy shared/public endpoint:

- **BOLA** confirms the object endpoint enforces auth (anonymous is rejected)
  and that its response is genuinely object-specific (two different ids return
  different bodies) before flagging that two identities see the same object.
  Object ids are harvested from the spec's collection/parent reads when
  possible, so the oracle probes real objects instead of synthetic ``1``/``2``.
  With a **single credential** (APIs where only one account exists and there
  are no roles) BOLA degrades to sibling probing: fetch an object reachable by
  the identity, then a neighbouring id with the same token. That cannot prove
  cross-tenant access without a second identity, so it reports at low severity
  as a lead instead of silently no-oping.
- **BFLA** derives "privileged" from the security scope the parser keeps (not
  just a ``/admin`` substring) and confirms the low-privilege identity reaches
  the *same* function a privileged identity does.
"""
from __future__ import annotations

import json
import re
from typing import Any

from app.domain.enums import Confidence, Severity
from app.domain.privilege import is_privileged
from app.engine.base import (
    EngineFinding,
    ProbeResult,
    ResolvedCredential,
    ScanContext,
    TargetOperation,
    method_is_allowed,
    render_path,
)
from app.engine.resource_map import param_resource_name, path_param_key, resource_id_for

_REJECTED = {401, 403}

# Id-looking names, case- and separator-insensitive: id, user_id, userId,
# merchantId, statementId, sid, uuid, ... (real specs mix snake and camel case).
_NAME_NORM = re.compile(r"[^a-z0-9]")
_ID_TOKENS = {"id", "uuid", "guid", "key"}

# Response keys that describe *this* response rather than the object it carries,
# and so change between two reads of the same object. Two identities reading the
# same object on a real API usually get different `updated_at` / `request_id`
# stamps, so a raw ``==`` on the body misses the BOLA the oracle exists to find.
# These are stripped before comparing, recursively, so the object's own fields
# decide. Normalised to the separator-insensitive form ``_NAME_NORM`` produces.
_VOLATILE_KEYS = frozenset({
    "updatedat", "createdat", "timestamp", "lastmodified", "date", "time",
    "expiresat", "expiresin", "ttl",
    "requestid", "traceid", "spanid", "correlationid", "nonce", "etag",
})


def _norm_key(name: str) -> str:
    """A response-field name in the same normalised form ``_is_id_name`` uses."""
    return _NAME_NORM.sub("", name.lower())


def _strip_volatile(value: object) -> object:
    """Recursively drop response-metadata keys, keeping the object's own fields."""
    if isinstance(value, dict):
        return {
            k: _strip_volatile(v)
            for k, v in value.items()
            if _norm_key(str(k)) not in _VOLATILE_KEYS
        }
    if isinstance(value, list):
        return [_strip_volatile(v) for v in value]
    return value


def _has_content(value: Any) -> bool:
    """Whether a parsed body holds any data: a non-empty string or a non-zero number."""
    if isinstance(value, dict):
        return any(_has_content(v) for v in value.values())
    if isinstance(value, list):
        return any(_has_content(v) for v in value)
    if isinstance(value, str):
        return value != ""
    if isinstance(value, bool) or value is None:
        return False
    return value != 0


def _carries_data(text: str) -> bool:
    """Whether a response body holds anything that could belong to an object.

    Two identities both receiving ``[]`` is what a correctly scoped API returns
    for "no checks you may see on that monitor" — the query filters on the
    caller's workspace and finds nothing. Identical *empty* bodies are therefore
    no evidence that the second identity read the first one's data, and counting
    them reported a verified BOLA on an API that was doing it right.
    """
    if text.strip() == "":
        return False
    try:
        return _has_content(json.loads(text))
    except (ValueError, TypeError, RecursionError):
        return True  # not JSON: the text itself is the content


def _stable_body(text: str) -> str:
    """A body reduced to what identifies the object, not one particular response.

    Raw equality was the whole comparison, and it was the wrong one: a target
    that stamps a fresh timestamp, request id or cursor on each response makes
    two identities reading the *same* object return two *different* bodies, so
    ``==`` was false and the BOLA was missed. Parsing and re-serialising with
    sorted keys also makes two responses that only differ in key order compare
    equal — same data, same object. Non-JSON bodies are returned untouched.
    """
    try:
        payload = json.loads(text)
    except (ValueError, TypeError):
        return text
    return json.dumps(_strip_volatile(payload), sort_keys=True, separators=(",", ":"))


def _is_id_name(name: str) -> bool:
    norm = _NAME_NORM.sub("", name.lower())
    return norm in _ID_TOKENS or norm.endswith("id")


def _is_object_op(op: TargetOperation) -> bool:
    if op.method != "GET":
        return False
    return any(_is_id_name(n) for n in op.path_params)


def _id_param(op: TargetOperation) -> str | None:
    return next((n for n in op.path_params if _is_id_name(n)), None)


def _sibling_of(oid: str) -> str | None:
    """The next enumerable id after ``oid``; None for non-numeric ids."""
    if not oid.isdigit():
        return None
    return str(int(oid) + 1)


def _next_ids(oid: str, count: int) -> list[str]:
    """Up to ``count`` successive neighbours of ``oid``; none for a non-enumerable id."""
    out: list[str] = []
    current = oid
    for _ in range(count):
        following = _sibling_of(current)
        if following is None:
            break
        out.append(following)
        current = following
    return out


def _collection_candidates(path: str, levels: int = 2) -> list[str]:
    """Walk up the path stripping trailing segments: ``/a/{id}/b`` → ``/a/{id}``, ``/a``."""
    parts = path.rstrip("/").split("/")
    out: list[str] = []
    for i in range(1, levels + 1):
        if len(parts) - i < 2:
            break
        out.append("/".join(parts[: len(parts) - i]) or "/")
    return out


def _extract_ids(text: str, limit: int = 8) -> list[str]:
    """Pull id-looking values out of a JSON response body (best-effort).

    Harvesting more than a couple of ids matters: the BOLA oracle only probes
    the objects a collection read actually returned, and a weakness that only
    manifests past the first page (or the first two rows) was invisible when the
    harvest stopped at three. The per-request cost is the same shape — the probe
    still sends one read per candidate — so the cap is only about staying
    representative without walking an unbounded list.
    """
    try:
        data = json.loads(text)
    except ValueError:
        return []
    found: list[str] = []

    def walk(node: object) -> None:
        if len(found) >= limit:
            return
        if isinstance(node, dict):
            for k, v in node.items():
                if len(found) >= limit:
                    return
                if _is_id_name(k) and isinstance(v, str | int) and not isinstance(v, bool):
                    s = str(v).strip()
                    if s and " " not in s and len(s) <= 64:
                        found.append(s)
                        continue
                walk(v)
        elif isinstance(node, list):
            for item in node[:25]:
                walk(item)
                if len(found) >= limit:
                    return

    walk(data)
    return found


def _harvest_ids(
    ctx: ScanContext,
    cred: ResolvedCredential,
    op: TargetOperation,
    cache: dict[str, list[str]],
) -> list[str]:
    """Real object ids read from a collection/parent GET, if the spec has one.

    Probing harvested ids makes the BOLA oracle meaningful on real APIs, where
    synthetic ids ``1``/``2`` usually 404. Cached per read path — sibling
    operations under the same collection share one harvest request.
    """
    for cand in _collection_candidates(op.path):
        if cand in cache:
            if cache[cand]:
                return cache[cand]
            continue
        cache[cand] = []
        reader = next(
            (o for o in ctx.operations if o.method == "GET" and o.path == cand), None
        )
        if reader is None:
            continue
        vals = {p: "1" for p in reader.path_params}
        r = ctx.probe.send("GET", render_path(reader.path, vals), headers=cred.headers())
        if r is not None and r.status < 400:
            ids = _extract_ids(r.text)
            if ids:
                cache[cand] = ids
                return ids
    return []


def _resource_key(name: str) -> str:
    """Normalize an object parameter/collection name for dependency matching."""
    value = re.sub(r"[^a-z0-9]", "", name.lower())
    for suffix in ("uuid", "guid", "id"):
        if value.endswith(suffix) and len(value) > len(suffix):
            return value[: -len(suffix)]
    return value


def _collection_name(path: str) -> str:
    """Return the final static collection segment from an operation path."""
    parts = [part for part in path.rstrip("/").split("/") if part]
    for part in reversed(parts):
        if not (part.startswith("{") and part.endswith("}")):
            return _resource_key(part)
    return ""


def _same_resource_name(left: str, right: str) -> bool:
    """Match singular/camel-case parameter names to plural collections."""
    if left == right:
        return True
    return left.rstrip("s") == right.rstrip("s")


def _harvest_dependency_ids(
    ctx: ScanContext,
    cred: ResolvedCredential,
    op: TargetOperation,
    values: dict[str, str],
    cache: dict[str, list[str]],
) -> dict[str, str]:
    """Resolve path IDs from related collection/parent reads.

    A large API often has no ``GET /statements`` collection. Instead,
    ``GET /statements/{merchantId}`` consumes an ID produced by
    ``GET /merchants`` (or ``POST /merchants``), and a download route then
    consumes a statement ID returned by that parent read. The old BOLA probe
    filled every path parameter with ``1`` and consequently stopped at 404/401.

    This resolver remains read-only: it harvests identifiers from GET responses
    already described by the spec. It never creates a resource; state-changing
    setup remains behind the explicit mutation-gated seeded checks.
    """
    resolving: set[str] = set()

    def resolve(param: str, path: str) -> str | None:
        key = _resource_key(param_resource_name(path, param))
        if param in values:
            return values[param]
        if key in resolving:
            return None
        provisioned = resource_id_for(path, param, getattr(ctx, "resource_ids", {}))
        # A read-only seeded id was read as the primary identity, which need not
        # be the identity this resolver harvests for (the owner): an attacker's
        # own parent object would turn a cross-identity read into a self-read.
        if path_param_key(path, param) in getattr(ctx, "seeded_resource_keys", ()):
            provisioned = None
        if provisioned:
            values[param] = provisioned
            return provisioned
        if cache.get(key):
            values[param] = cache[key][0]
            return values[param]
        resolving.add(key)
        try:
            # First look for a GET collection whose name matches the parameter,
            # e.g. merchantId -> GET /v1/merchants.
            readers = [
                candidate
                for candidate in ctx.operations
                if candidate.method == "GET"
                and not candidate.path_params
                and _same_resource_name(_collection_name(candidate.path), key)
            ]
            # Then allow a parent read to supply a leaf ID, e.g.
            # /statements/{merchantId} -> /statements/{merchantId}/download/{statementId}.
            prefix_readers = [
                candidate
                for candidate in ctx.operations
                if candidate.method == "GET"
                and candidate.path != op.path
                and op.path.startswith(candidate.path.rstrip("/"))
                and len(candidate.path_params) < len(op.path_params)
            ]
            readers.extend(sorted(prefix_readers, key=lambda candidate: -len(candidate.path)))
            for reader in readers:
                reader_values: dict[str, str] = {}
                for parent in reader.path_params:
                    resolved = resolve(parent, reader.path)
                    reader_values[parent] = resolved or "1"
                path = render_path(reader.path, reader_values)
                cache_key = f"{reader.method}:{path}"
                if cache.get(cache_key):
                    ids = cache[cache_key]
                else:
                    response = ctx.probe.send(reader.method, path, headers=cred.headers())
                    ids = (
                        _extract_ids(response.text)
                        if response is not None and response.status < 400
                        else []
                    )
                    cache[cache_key] = ids
                if ids:
                    cache[key] = ids
                    values[param] = ids[0]
                    return values[param]
        finally:
            resolving.discard(key)
        return None

    for param in op.path_params:
        resolve(param, op.path)
    return values


def _harvest_for(
    ctx: ScanContext,
    cred: ResolvedCredential,
    op: TargetOperation,
    target_param: str | None,
    cache: dict[str, list[str]],
) -> tuple[dict[str, str], list[str]]:
    """Real ids for ``op`` as ``cred`` sees them: its parents' path values, and
    candidates for ``target_param`` (falling back to ids another operation
    harvested for the same resource)."""
    dependency_values = _harvest_dependency_ids(ctx, cred, op, {}, cache)
    harvested = _harvest_ids(ctx, cred, op, cache)
    if not harvested and target_param:
        harvested = cache.get(_resource_key(param_resource_name(op.path, target_param)), [])
    return dependency_values, harvested


def _same_body_for_sibling(
    ctx: ScanContext,
    op: TargetOperation,
    path_values: dict[str, str],
    target_param: str | None,
    oid: str,
    cred: ResolvedCredential,
    body: str,
) -> bool:
    """Static-content guard: if the same identity gets an identical body for a
    *different* object id, the response is not object-specific (static page /
    echo), so identical cross-identity bodies are not BOLA evidence."""
    sib = _sibling_of(oid)
    if sib is None:
        return False
    path2 = render_path(op.path, {**path_values, target_param or "": sib})
    response = ctx.probe.send(op.method, path2, headers=cred.headers())
    return response is not None and _stable_body(response.text) == _stable_body(body)


class BolaCheck:
    """Broken Object Level Authorization — same object readable by two identities."""

    key = "bola"
    # Its findings need the scan's identities; a run that left one out could
    # not have re-found them, so the diff must not call them fixed.
    needs_identities = True
    #: Read-only in itself, but under ``mutate`` it harvests ids that the
    #: write oracles may create or change underneath it.
    serial_when_mutating = True

    @staticmethod
    def inapplicable(ctx: ScanContext) -> str | None:
        if not ctx.credentials:
            return "no usable credential supplied — BOLA needs an authenticated identity"
        if not any(_is_object_op(op) for op in ctx.operations):
            return "no GET operation has an id-shaped path parameter to probe for BOLA"
        return None

    def run(self, ctx: ScanContext) -> list[EngineFinding]:
        if not ctx.credentials:
            return []
        if len(ctx.credentials) == 1:
            return self._single_identity(ctx)
        return self._two_identity(ctx)

    def _two_identity(self, ctx: ScanContext) -> list[EngineFinding]:
        pair = ctx.identity_pair()
        if pair is None:
            # Two or more identities, all in one declared tenant: there is no
            # cross-tenant pair, so only the single-identity lead remains.
            return self._single_identity(ctx)
        hi, lo = pair.owner, pair.attacker
        findings: list[EngineFinding] = []
        harvest_cache: dict[str, list[str]] = {}

        for op in ctx.operations:
            if not _is_object_op(op):
                continue
            target_param = op.path_params[-1] if op.path_params else _id_param(op)
            dependency_values, harvested = _harvest_for(ctx, hi, op, target_param, harvest_cache)
            ids = (harvested or ["1", "2"])[:3]
            for oid in ids:
                path_values = {
                    p: dependency_values.get(p, "1") for p in op.path_params
                }
                if target_param:
                    path_values[target_param] = oid
                path1 = render_path(op.path, path_values)

                # Baseline: the endpoint must enforce auth, else it is simply
                # public and identical responses prove nothing about scoping.
                anon = ctx.probe.send(op.method, path1, headers={})
                if anon is None:
                    break
                if anon.status not in _REJECTED:
                    continue

                r_hi = ctx.probe.send(op.method, path1, headers=hi.headers())
                r_lo = ctx.probe.send(op.method, path1, headers=lo.headers())
                if r_hi is None or r_lo is None:
                    break
                if not (r_hi.status < 400 and r_lo.status < 400):
                    continue

                if _same_body_for_sibling(ctx, op, path_values, target_param, oid, hi, r_hi.text):
                    continue

                if _carries_data(r_lo.text) and _stable_body(r_lo.text) == _stable_body(
                    r_hi.text
                ):
                    findings.append(
                        self._cross_identity_read(
                            op, path1, hi, lo, anon=anon, r_hi=r_hi, r_lo=r_lo,
                            ids=ids, harvested=bool(harvested),
                        )
                    )
                    break
        return findings

    def _cross_identity_read(
        self,
        op: TargetOperation,
        path: str,
        hi: ResolvedCredential,
        lo: ResolvedCredential,
        *,
        anon: ProbeResult,
        r_hi: ProbeResult,
        r_lo: ProbeResult,
        ids: list[str],
        harvested: bool,
    ) -> EngineFinding:
        return EngineFinding(
            check=self.key,
            confidence=Confidence.verified,
            owasp_id="API1:2023",
            severity=Severity.high,
            title=f"Cross-identity read (BOLA) on {op.method} {op.path}",
            description=(
                f"Object at {path} rejects anonymous access "
                f"({anon.status}) yet returns an identical, "
                f"object-specific response to two different identities "
                f"('{hi.name}' [{hi.role}] and '{lo.name}' "
                f"[{lo.role}]). The object is not scoped "
                "to the caller: an attacker could read other users' "
                "objects by changing the id."
            ),
            evidence={
                "method": op.method,
                "route": op.path,
                "path": path,
                "identity_a": hi.name,
                "identity_a_role": hi.role,
                "identity_b": lo.name,
                "identity_b_role": lo.role,
                "anon_status": anon.status,
                "status_a": r_hi.status,
                "status_b": r_lo.status,
                "object_ids": ids,
                "ids_harvested": harvested,
                "response_sample": r_hi.text[:400],
            },
            operation_id=op.id,
        )

    def _single_identity(self, ctx: ScanContext) -> list[EngineFinding]:
        """Degraded mode for APIs with exactly one account and no roles.

        Cross-tenant access cannot be proven without a second identity, but the
        sibling probe still surfaces the lead: the identity's own (or a
        baseline) object is fetched, then a neighbouring id with the same
        token. A sibling object response is reported at low severity for
        manual confirmation. Reads only; never mutates.
        """
        cred = ctx.primary_credential()
        assert cred is not None  # caller checks len == 1
        findings: list[EngineFinding] = []
        harvest_cache: dict[str, list[str]] = {}

        for op in ctx.operations:
            if not _is_object_op(op):
                continue
            idp = _id_param(op)
            if idp is None:
                continue
            dependency_values, harvested = _harvest_for(ctx, cred, op, idp, harvest_cache)
            baseline = harvested[0] if harvested else "1"
            siblings = _next_ids(baseline, 2)
            if not siblings:
                continue  # non-enumerable id (e.g. uuid): no sibling signal

            r_own = ctx.probe.send(
                op.method,
                render_path(op.path, {**dependency_values, idp: baseline}),
                headers=cred.headers(),
            )
            if r_own is None:
                break
            if r_own.status >= 400:
                continue
            for sib in siblings:
                r_sib = ctx.probe.send(
                    op.method,
                    render_path(op.path, {**dependency_values, idp: sib}),
                    headers=cred.headers(),
                )
                if r_sib is None:
                    break
                if r_sib.status >= 400:
                    continue
                # Same body for both ids is the static-content echo guard from
                # the two-identity path: not evidence of a second object.
                if _stable_body(r_sib.text) == _stable_body(r_own.text):
                    continue
                findings.append(
                    EngineFinding(
                        check=self.key,
                        confidence=Confidence.heuristic,
                        owasp_id="API1:2023",
                        severity=Severity.low,
                        title=(
                            f"Sibling object reachable with the same identity on "
                            f"{op.method} {op.path}"
                        ),
                        description=(
                            "Only one credential was provided, so cross-tenant access "
                            "cannot be proven. The scanner read an object reachable "
                            "with this identity"
                            + (" (harvested from the API)" if harvested
                               else " (synthetic baseline)")
                            + f", then fetched the neighbouring id '{sib}' with the "
                            "same token and received an object response. Treat as a "
                            f"lead: confirm '{sib}' belongs to a different owner and "
                            "that the API should reject it. Upload a second, "
                            "lower-privilege credential to verify."
                        ),
                        evidence={
                            "method": op.method,
                            "route": op.path,
                            "path": render_path(
                                op.path,
                                {**{p: "1" for p in op.path_params}, idp: baseline},
                            ),
                            "param": idp,
                            "mode": "single-identity",
                            "identity": cred.name,
                            "identity_role": cred.role,
                            "baseline_id": baseline,
                            "baseline_harvested": bool(harvested),
                            "sibling_id": sib,
                            "baseline_status": r_own.status,
                            "sibling_status": r_sib.status,
                        },
                        operation_id=op.id,
                    )
                )
                break
        return findings


def _first_admitted(
    ctx: ScanContext, method: str, path: str, tiers: list[ResolvedCredential]
) -> tuple[ResolvedCredential, ProbeResult] | None:
    """The least privileged identity the function admits, with its response.

    Least privileged first: the bottom tier is the strongest evidence, and with
    only two identities this is a single probe. A middle tier is tried only when
    every tier below it was refused; a spent budget stops the walk.
    """
    for candidate in tiers:
        response = ctx.probe.send(method, path, headers=candidate.headers())
        if response is None:
            return None
        if response.status < 400:
            return candidate, response
    return None


class BflaCheck:
    """Broken Function Level Authorization — privileged op callable by low-priv."""

    key = "bfla"
    # Its findings need the scan's identities; a run that left one out could
    # not have re-found them, so the diff must not call them fixed.
    needs_identities = True

    @staticmethod
    def inapplicable(ctx: ScanContext) -> str | None:
        pair = ctx.privilege_pair()
        if pair is None:
            if ctx.tenants_declared():
                return (
                    "no tenant has two identities — BFLA compares a low and a privileged "
                    "identity of the same tenant"
                )
            return "fewer than two usable identities — BFLA needs a low and privileged account"
        if ctx.privilege_rank(pair.owner) <= ctx.privilege_rank(pair.attacker):
            return "credential roles do not establish a low-to-high privilege boundary"
        privileged = [op for op in ctx.operations if is_privileged(op.path, op.auth_scope)]
        if not privileged:
            # Said apart from the mutation case: "with the current mutation
            # setting" read as "turn writes on" to someone who had.
            return (
                "no operation is admin-only by its path (/admin) or declared scope — "
                "writes a lower role should be refused are tested by write_authz "
                "(under mutate)"
            )
        if not any(
            method_is_allowed(op.method, allow_mutation=ctx.allow_mutation) for op in privileged
        ):
            return (
                "every admin-only operation is a write, and writes to the target are off "
                "(enable 'mutate' to probe them)"
            )
        return None

    def run(self, ctx: ScanContext) -> list[EngineFinding]:
        pair = ctx.privilege_pair()
        if pair is None:
            return []
        high, floor = pair.owner, pair.attacker
        if ctx.privilege_rank(high) <= ctx.privilege_rank(floor):
            return []
        tiers = ctx.lower_privileged(high)
        findings: list[EngineFinding] = []
        harvest_cache: dict[str, list[str]] = {}

        for op in ctx.operations:
            if not is_privileged(op.path, op.auth_scope):
                continue
            if not method_is_allowed(op.method, allow_mutation=ctx.allow_mutation):
                continue
            target_param = op.path_params[-1] if op.path_params else None
            path_values, harvested = _harvest_for(ctx, high, op, target_param, harvest_cache)
            if target_param and harvested:
                path_values[target_param] = harvested[0]
            path = render_path(
                op.path, {p: path_values.get(p, "1") for p in op.path_params}
            )

            # A public function is not a function-level authorization bypass,
            # even when its path or declared scope looks privileged.
            anon = ctx.probe.send(op.method, path, headers={})
            if anon is None or anon.status not in _REJECTED:
                continue

            admitted = _first_admitted(ctx, op.method, path, tiers)
            if admitted is None:
                continue
            low, r_low = admitted

            # Reference: confirm a privileged identity is meant to use this op, so
            # a broken-for-everyone endpoint isn't misreported as low-priv access.
            r_high = ctx.probe.send(op.method, path, headers=high.headers())
            if r_high is None or r_high.status >= 400:
                continue

            # The bottom tier reaching a privileged function is the boundary the
            # identities establish. A middle tier is a lead: the spec says the
            # function is privileged, not which tier it is meant for, and an
            # editor may legitimately hold a ``manage:`` scope.
            # By rank, not identity: two bottom-rank accounts are the same tier.
            bottom = ctx.privilege_rank(low) == ctx.privilege_rank(tiers[0])
            findings.append(
                self._open_to_low_privilege(
                    op, path, low, high, bottom=bottom, anon=anon, r_low=r_low,
                    r_high=r_high, harvested=bool(harvested),
                )
            )
        return findings

    def _open_to_low_privilege(
        self,
        op: TargetOperation,
        path: str,
        low: ResolvedCredential,
        high: ResolvedCredential,
        *,
        bottom: bool,
        anon: ProbeResult,
        r_low: ProbeResult,
        r_high: ProbeResult,
        harvested: bool,
    ) -> EngineFinding:
        return EngineFinding(
            check=self.key,
            confidence=Confidence.verified if bottom else Confidence.heuristic,
            owasp_id="API5:2023",
            severity=Severity.high,
            title=(
                f"Privileged function open to low privilege (BFLA) on "
                f"{op.method} {op.path}"
            ),
            description=(
                f"Privileged operation {op.method} {op.path} returned "
                f"{r_low.status} for low-privilege identity "
                f"'{low.name}' (role '{low.role}'). "
                + (
                    "Function-level authorization does not appear to be enforced."
                    if bottom
                    else "Less privileged identities were refused, so confirm "
                    "this tier is not meant to use it."
                )
            ),
            evidence={
                "method": op.method,
                "route": op.path,
                "path": path,
                "identity": low.name,
                "identity_role": low.role,
                "privileged_identity": high.name,
                "privileged_role": high.role,
                "anon_status": anon.status,
                "status": r_low.status,
                "privileged_status": r_high.status,
                "ids_harvested": harvested,
                "response_sample": r_low.text[:400],
            },
            operation_id=op.id,
        )
