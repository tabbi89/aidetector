"""Create real prerequisite resources for dependent read authorization probes.

Some APIs do not expose a useful standalone statement/detail fixture: a merchant
must exist before ``/statements/{merchantId}`` can return anything or
``/merchants/{merchantId}`` can be updated. This pass is deliberately
mutation-gated and conservative. It creates only a top-level POST collection
that is referenced by an enabled path, records the returned ID, and queues a
declared DELETE for teardown when one exists. All values are generated from the
operation's declared body shape; the AI planner may describe the dependency, but
it never supplies arbitrary executable request data.
"""
from __future__ import annotations

import logging
import uuid
from collections.abc import Callable
from typing import Any

from app.ai.types import Usage
from app.core.redact import Redactor
from app.engine.base import ScanContext, TargetOperation, render_path
from app.engine.cleanup import creation_request
from app.engine.request_bodies import _unprivileged_choice
from app.engine.request_bodies import value_from_schema as _value_from_schema
from app.engine.resource_map import (
    build_body,
    collection_of,
    created_id,
    mutable_body_field,
    param_resource_name,
    resource_id_for,
    resource_key,
)
from app.engine.resource_proposal import proposal_payload, request_schema, validate_body
from app.engine.spec_values import base_value

log = logging.getLogger("aidetector.engine")


def _key(name: str) -> str:
    # The same key ``path_values`` and the id seed look ids up by. A private
    # variant once kept the trailing "s" of a suffix-stripped name, so a
    # predefined ``address_id`` was stored as "address" and read as "addre".
    return resource_key(name)


def _same(left: str, right: str) -> bool:
    return _key(left) == _key(right)


def _collection_name(path: str) -> str:
    parts = [part for part in path.rstrip("/").split("/") if part]
    for part in reversed(parts):
        if not (part.startswith("{") and part.endswith("}")):
            return _key(part)
    return ""


def _producer_for(ctx: ScanContext, param: str) -> TargetOperation | None:
    """Find a top-level POST collection whose resource matches ``param``."""
    for op in ctx.operations:
        if op.method == "POST" and not op.path_params and _same(_collection_name(op.path), param):
            return op
    return None


def _read_for(ctx: ScanContext, producer: TargetOperation) -> TargetOperation | None:
    return next(
        (
            op
            for op in ctx.operations
            if op.method == "GET" and collection_of(op.path) == producer.path and op.path_params
        ),
        None,
    )


def _consumer_for(
    ctx: ScanContext, producer: TargetOperation, resource_key: str
) -> TargetOperation | None:
    """Find an enabled operation whose path needs the produced resource id.

    Resource setup used to consider only GET consumers. That silently skipped a
    very common selected-operation set: POST a collection plus PATCH/PUT its
    item. The create response can still supply the id even when an item GET was
    not selected; read-back verification is useful, but it is not a prerequisite
    for creating and registering the fixture.
    """
    direct: TargetOperation | None = None
    for op in ctx.operations:
        if op is producer:
            continue
        matching = [
            param
            for param in op.path_params
            if _same(param_resource_name(op.path, param), resource_key)
        ]
        if not matching:
            continue
        if collection_of(op.path) == producer.path:
            return op
        direct = direct or op
    return direct


def _value_for(field: dict[str, Any], seed: str) -> Any:
    name = str(field.get("name", ""))
    schema = field.get("schema") or {}
    enum = schema.get("enum")
    if isinstance(enum, list) and enum:
        return _unprivileged_choice(enum)
    normalized = _key(name)
    if normalized == "email" or schema.get("format") == "email":
        return f"{seed}@example.invalid"
    if normalized == "phone":
        digits = "".join(ch for ch in seed if ch.isdigit()).ljust(7, "7")[-7:]
        return "+1555" + digits
    if schema.get("type") in {"string", None}:
        return f"aidx{seed}"
    return base_value(schema)


def _full_body(
    producer: TargetOperation,
    spec: dict[str, Any] | None,
    seed: str,
    target_base_url: str | None = None,
) -> dict[str, Any] | None:
    """The create body built from the full request schema, when resolvable.

    Returns ``None`` when the spec is unavailable or has no resolvable JSON
    body, so the caller can fall back to the minimal flattened-field body.
    """
    schema = request_schema(spec, producer, target_base_url)
    if not schema or not isinstance(spec, dict):
        return None
    body = _value_from_schema(schema, spec, seed)
    if not isinstance(body, dict) or not body:
        return None
    # Ensure at least one identity field is present even when the DTO declares
    # nothing required (very common): email/phone/name are the fields a create
    # endpoint is most likely to validate on.
    fields = [p for p in producer.params if p.get("in") == "body" and p.get("name")]
    preferred = next(
        (p for p in fields if _key(str(p["name"])) in {"email", "phone", "name", "label", "title"}),
        mutable_body_field(producer),
    )
    if preferred is not None and str(preferred["name"]) not in body:
        body[str(preferred["name"])] = _value_for(preferred, seed)
    return body


def _body(
    producer: TargetOperation,
    spec: dict[str, Any] | None = None,
    target_base_url: str | None = None,
) -> dict[str, Any]:
    """Build a create body, preferring a full spec-valid shape.

    Falls back to the prior minimal body (one preferred identity field plus any
    required flattened fields) when the full schema is not resolvable.
    """
    seed = uuid.uuid4().hex[:12]
    full = _full_body(producer, spec, seed, target_base_url)
    if full is not None:
        return full
    fields = [p for p in producer.params if p.get("in") == "body" and p.get("name")]
    preferred = next(
        (p for p in fields if _key(str(p["name"])) in {"email", "phone", "name", "label", "title"}),
        mutable_body_field(producer),
    )
    if preferred is None:
        return build_body(producer, "_seed", f"aidx{seed}")
    body = {
        str(field["name"]): _value_for(field, seed)
        for field in fields
        if field.get("required")
    }
    body[str(preferred["name"])] = _value_for(preferred, seed)
    return body


def _response_observation(ctx: ScanContext, response: Any) -> dict[str, Any]:
    """Bounded, redacted failure context for the optional AI retry."""
    redactor = Redactor([credential.secret for credential in ctx.credentials])
    return {
        "status": response.status,
        "content_type": response.headers.get("content-type", "")[:80],
        "body_bytes": min(len(response.content or b""), 65536),
        "error_excerpt": redactor.text(response.text[:2000]),
    }


def _ai_propose(
    planner: Any,
    ctx: ScanContext,
    producer: TargetOperation,
    previous_body: dict[str, Any],
    response: Any,
    schema_context: dict[str, Any] | None,
) -> tuple[dict[str, Any] | None, str | None, list[Usage]]:
    """Ask the planner for a valid create body, validated against the spec.

    The planner's output is untrusted, so it is rejected unless it matches the
    operation's declared body shape (``validate_body``). Returns
    ``(body, None, usages)`` on a usable proposal, ``(None, reason, usages)``
    when the proposal is rejected, or ``(None, None, [])`` when the AI runtime
    is unavailable. Never raises — the fallback must not fail resource setup.
    """
    try:
        result = planner.propose_resource(
            proposal_payload(
                producer,
                ctx.spec,
                previous_body=previous_body,
                response=_response_observation(ctx, response),
                schema_context=schema_context,
                target_base_url=ctx.base_url,
            )
        )
    except Exception:  # noqa: BLE001 — AI fallback is optional
        return None, None, []
    usages: list[Usage] = []
    if isinstance(result, tuple):
        raw = result[0]
        if len(result) > 1 and isinstance(result[1], list):
            usages = [usage for usage in result[1] if isinstance(usage, Usage)]
    else:
        raw = result
    if not isinstance(raw, dict):
        return None, None, usages
    body, reason = validate_body(producer, raw)
    if body is None:
        return None, reason, usages
    return body, None, usages


def provision(
    ctx: ScanContext,
    planner: Any = None,
    *,
    schema_context: dict[str, Any] | None = None,
    on_ai_usage: Callable[[list[Usage]], None] | None = None,
) -> list[str]:
    """Provision prerequisite resources and return human-readable setup notes.

    A deterministic body is always attempted first. When explicit refinement is
    enabled, clear payload rejections can feed a bounded, redacted observation
    to a supplied planner for up to ``resource_attempts`` total tries.
    """
    notes: list[str] = []
    for raw_key, provided_id in ctx.predefined_resource_ids.items():
        key = _key(raw_key)
        if not key or not provided_id:
            continue
        ctx.resource_ids[key] = provided_id
        ctx.created_resources.append(
            {
                "resource": key,
                "create_method": "",
                "create_path": "",
                "read_method": "",
                "read_path": "",
                "status": "provided",
                "via_ai": False,
                "cleanup": "not_needed",
                "source": "predefined",
                "attempts": [],
            }
        )
        notes.append(f"using predefined '{key}' resource id")

    if not ctx.allow_mutation:
        return notes
    # The most privileged identity, not the first one listed. A fixture is
    # created by its owner: a read-only key listed first answers every create
    # with 403, and the owner is also who the authorization checks compare a
    # lower identity against.
    credential = ctx.highest_priv()
    if credential is None:
        return [*notes, "resource setup skipped: no credential supplied"]

    needed: list[str] = []
    for operation in ctx.operations:
        for param in operation.path_params:
            if resource_id_for(operation.path, param, ctx.resource_ids) is not None:
                continue  # a predefined id, possibly keyed on the bare name
            key = _key(param_resource_name(operation.path, param))
            if key not in needed:
                needed.append(key)

    if not needed:
        return [*notes, "resource setup skipped: no enabled endpoint needs a resource id"]

    for key in needed:
        if key in ctx.resource_ids:
            continue
        try:
            limit = ctx.resource_attempts if ctx.resource_refine else 1
            with ctx.probe.test_case(limit + 2, cleanup=1, label=f"resource:{key}") as case:
                if case is None:
                    notes.append(f"resource setup skipped: no complete-case budget for '{key}'")
                    continue
                previous = len(ctx.resource_cleanups)
                try:
                    _provision_one(
                        ctx, key, credential, planner, schema_context, on_ai_usage, notes
                    )
                finally:
                    if len(ctx.resource_cleanups) > previous:
                        ctx.probe.defer_cleanup()
        except Exception as exc:  # noqa: BLE001 — one bad resource is not the pass
            # Isolated per resource on purpose. The caller wraps this whole
            # function in a blanket except, so without this a single malformed
            # schema would take down setup for every *other* resource too, and
            # report only "resource setup unavailable" with no reason.
            log.exception("resource setup failed for %r", key)
            notes.append(f"resource setup failed for '{key}': {type(exc).__name__}: {exc}"[:300])
    return notes


def _provision_one(
    ctx: ScanContext,
    key: str,
    credential: Any,
    planner: Any,
    schema_context: dict[str, Any] | None,
    on_ai_usage: Callable[[list[Usage]], None] | None,
    notes: list[str],
) -> None:
    """Create the one resource ``key`` names, appending what happened to ``notes``."""
    producer = _producer_for(ctx, key)
    if producer is None:
        notes.append(f"resource setup skipped: no create endpoint for '{key}'")
        return
    consumer = _consumer_for(ctx, producer, key)
    if consumer is None:
        notes.append(f"resource setup skipped: no dependent endpoint for '{key}'")
        return
    reader = _read_for(ctx, producer)
    body = _body(producer, ctx.spec, ctx.base_url)
    response = None
    used_ai = False
    attempts: list[dict[str, Any]] = []
    limit = ctx.resource_attempts if ctx.resource_refine else 1
    for attempt_number in range(1, limit + 1):
        response = creation_request(
            ctx,
            producer,
            render_path(producer.path, {}),
            headers=credential.headers(),
            json=body,
        )
        attempt: dict[str, Any] = {
            "number": attempt_number,
            "source": "ai" if used_ai else "deterministic",
            "status": response.status if response is not None else None,
        }
        if response is not None and response.status >= 400:
            attempt["error"] = _response_observation(ctx, response)["error_excerpt"][:240]
        attempts.append(attempt)
        if response is None or response.status < 400:
            break
        # Only retry a clear payload rejection. Auth, throttling,
        # transport, and 5xx outcomes do not make another create safe.
        if (
            not ctx.resource_refine
            or planner is None
            or not producer.body_params
            or response.status not in {400, 409, 422}
            or attempt_number >= limit
        ):
            break
        proposed, ai_note, usages = _ai_propose(
            planner, ctx, producer, body, response, schema_context
        )
        if on_ai_usage is not None and usages:
            on_ai_usage(usages)
        if ai_note:
            notes.append(
                f"resource proposal rejected ({ai_note}): "
                f"{producer.method} {producer.path}"
            )
        if proposed is None:
            break
        body = proposed
        used_ai = True
    if response is None or response.status >= 400:
        status = "budget exhausted" if response is None else f"HTTP {response.status}"
        last_error = attempts[-1].get("error", "") if attempts else ""
        notes.append(
            f"resource setup failed after {len(attempts)} attempt(s): "
            f"{producer.method} {producer.path} ({status})"
            + (f" — {last_error}" if last_error else "")
        )
        return
    # The dependent consumer supplies the path-parameter names used for id
    # extraction when a matching item GET was not selected.
    identifier = created_id(response.headers, response.text, reader or consumer)
    if not identifier:
        ctx.cleanup_failures.append(
            f"{producer.method} {producer.path}: created resource has no identifier"
        )
        return
    ctx.resource_ids[key] = identifier
    verification = None
    if reader is not None:
        read_path = render_path(reader.path, {reader.path_params[-1]: identifier})
        verification = ctx.probe.send(
            reader.method, read_path, headers=credential.headers()
        )
    resource_name = _collection_name(producer.path)
    if reader is None:
        notes.append(
            f"created {resource_name} resource for dependent operations; "
            "no matching item read-back endpoint was selected"
        )
    elif verification is None:
        notes.append(f"created {resource_name} resource; read-back unavailable")
    elif verification.status >= 400:
        notes.append(
            f"created {resource_name} resource; read-back HTTP {verification.status}"
        )
    else:
        notes.append(
            f"created and verified {resource_name} resource"
            f"{(' (AI-proposed body)' if used_ai else '')} for dependent reads"
        )
    delete = next(
        (
            op
            for op in ctx.operations
            if op.method == "DELETE"
            and reader is not None
            and op.path == reader.path
        ),
        None,
    )
    if delete is None:
        # No DELETE endpoint is legitimate for a testing-only target: the
        # resource still feeds dependent reads; it just persists on target.
        notes.append(
            f"created {resource_name} resource; no DELETE endpoint — persists on target"
        )
    status = "created"
    if verification is not None and verification.status < 400:
        status = "verified"
    elif verification is not None:
        status = "read_back_failed"
    resource_record = {
        "resource": resource_name,
        "create_method": producer.method,
        "create_path": producer.path,
        "read_method": reader.method if reader is not None else "",
        "read_path": reader.path if reader is not None else "",
        "status": status,
        "via_ai": used_ai,
        "cleanup": "queued" if delete is not None else "none",
        "source": "ai" if used_ai else "deterministic",
        "attempts": attempts,
    }
    ctx.created_resources.append(resource_record)
    if delete is not None:
        assert reader is not None  # delete pairing above requires it
        cleanup_path = render_path(
            delete.path, {reader.path_params[-1]: identifier}
        )
        ctx.resource_cleanups.append(
            (delete, cleanup_path, credential, resource_record)
        )
