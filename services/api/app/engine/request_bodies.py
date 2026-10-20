"""Spec-valid JSON request bodies, built from the operation's declared schema.

Shared by resource setup and every check that *creates* an object
(``write_authz``, ``seeded_bola``, ``mass_assignment``, ``race_condition``,
parent seeding). Those checks once sent only the one field carrying their
canary, plus whatever the parser had flattened as required; against a create
DTO written as ``allOf`` + ``required`` that was a body with neither required
field, and the target answered 400 from validation — before the authorization
decision the probe existed to test.

Pure: no SQLAlchemy, no ``app.models`` (``tests/test_layering.py``).
"""
from __future__ import annotations

import uuid
from typing import Any

from app.domain.privilege import PRIVILEGE_TOKENS
from app.engine.base import ScanContext, TargetOperation
from app.engine.resource_map import build_body
from app.engine.resource_proposal import request_schema
from app.engine.seed_values import string_value
from app.engine.spec_values import schema_type

#: How deep the body builder will descend. A real create DTO nests three or four
#: levels; past this the spec is either pathological or self-referential, and an
#: ever-deeper body would be rejected anyway.
_MAX_SCHEMA_DEPTH = 8


def _resolve_ref(ref: str, spec: dict[str, Any]) -> dict[str, Any] | None:
    """Follow a local ``$ref`` into the document, or return None.

    Walks the JSON pointer rather than taking the last segment, so two schemas
    named alike in different sections cannot be confused for one another.
    """
    if not ref.startswith("#/"):
        return None  # remote refs are never fetched here — see specs/remote_refs
    node: Any = spec
    for segment in ref[2:].split("/"):
        segment = segment.replace("~1", "/").replace("~0", "~")
        if not isinstance(node, dict) or segment not in node:
            return None
        node = node[segment]
    return node if isinstance(node, dict) else None


def _composed(schema: dict[str, Any], spec: dict[str, Any]) -> dict[str, Any] | None:
    """Flatten ``allOf`` / ``oneOf`` / ``anyOf`` into one object schema.

    ``allOf`` is how OpenAPI 3.0 spells inheritance, so a create DTO composed
    from a base and an extension is ordinary, not exotic. Without this the
    builder falls through every branch and returns a *string* where an object
    belongs — a body the target rejects, from a spec that was perfectly valid.
    ``oneOf``/``anyOf`` take the first branch: any one of them is a legal body.

    The schema's own ``properties`` and ``required`` count too. ``{"allOf":
    [{"$ref": Input}], "required": ["name", "url"]}`` is how a create DTO
    reuses an update one and makes fields mandatory; dropping that sibling list
    built a body with neither field, and the target answered 400.
    """
    for keyword in ("allOf", "oneOf", "anyOf"):
        parts = schema.get(keyword)
        if not isinstance(parts, list) or not parts:
            continue
        branches = parts if keyword == "allOf" else parts[:1]
        own = schema.get("properties")
        own_required = schema.get("required")
        merged: dict[str, Any] = {
            "type": "object",
            "properties": dict(own) if isinstance(own, dict) else {},
            "required": list(own_required) if isinstance(own_required, list) else [],
        }
        for part in branches:
            resolved = part
            if isinstance(part, dict) and "$ref" in part:
                resolved = _resolve_ref(str(part["$ref"]), spec) or {}
            if not isinstance(resolved, dict):
                continue
            nested = _composed(resolved, spec) or resolved
            props = nested.get("properties")
            if isinstance(props, dict):
                merged["properties"].update(props)
            required = nested.get("required")
            if isinstance(required, list):
                merged["required"].extend(required)
        if merged["properties"]:
            return merged
    return None


_COMPOSITIONS = ("allOf", "oneOf", "anyOf")


def _scalar_branch(schema: dict[str, Any]) -> dict[str, Any] | None:
    """A scalar composition's first branch, with the outer keywords kept; else None.

    ``{"type": "integer", "anyOf": [{"const": 0}, {"minimum": 100}]}`` is one
    integer field, not an object: its value comes from a branch (``0``), and the
    outer ``type`` still applies to it.
    """
    if schema_type(schema) == "object" or isinstance(schema.get("properties"), dict):
        return None
    for keyword in _COMPOSITIONS:
        parts = schema.get(keyword)
        if isinstance(parts, list) and parts and isinstance(parts[0], dict):
            outer = {k: v for k, v in schema.items() if k not in _COMPOSITIONS}
            return {**outer, **parts[0]}
    return None


def value_from_schema(
    schema: Any,
    spec: dict[str, Any],
    seed: str,
    name: str = "",
    *,
    depth: int = 0,
    seen: frozenset[str] = frozenset(),
) -> Any:
    """Recursively build a spec-valid value for a request-body schema.

    The parser keeps only top-level body fields, so a nested create (merchant +
    bank account + owner) would otherwise get a one-field body and a 400. This
    resolves ``$ref`` against the spec's components and fills every required
    field; object-typed fields are included even when optional at their level,
    because a nested API rejects a create that omits the nested object.

    ``seen`` carries the ``$ref``s already on this branch. A self-referential
    schema (a tree node whose child is a tree node) is common and would
    otherwise recurse until the interpreter gives up — and because resource
    setup is wrapped in a blanket ``except``, that failure would surface as
    "resource setup unavailable" with no hint that one cyclic schema caused it.
    """
    if depth > _MAX_SCHEMA_DEPTH:
        return {}
    if isinstance(schema, dict) and "$ref" in schema:
        ref = str(schema["$ref"])
        if ref in seen:
            # A cycle. An empty object is the honest answer: the field exists,
            # and we cannot invent an infinitely deep value for it.
            return {}
        resolved = _resolve_ref(ref, spec)
        if resolved is not None:
            return value_from_schema(
                resolved, spec, seed, name, depth=depth + 1, seen=seen | {ref}
            )
        return string_value(name, {}, seed)
    schema = schema if isinstance(schema, dict) else {}
    composed = _composed(schema, spec)
    if composed is not None:
        return value_from_schema(composed, spec, seed, name, depth=depth + 1, seen=seen)
    branch = _scalar_branch(schema)
    if branch is not None:
        # ``{"allOf": [{"$ref": Kind}], "description": …}`` wraps a scalar (an
        # enum) only to attach a description. Its value is the branch's value;
        # an invented string where an enum belongs is a body the target refuses.
        return value_from_schema(branch, spec, seed, name, depth=depth + 1, seen=seen)
    t = schema_type(schema)
    props = schema.get("properties")
    if t == "object" or isinstance(props, dict):
        # A free-form object (``type: object`` with no properties, or
        # ``additionalProperties: true``) declares no fields to fill. An empty
        # object is what it asked for.
        if not isinstance(props, dict):
            return {}
        required = set(schema.get("required") or [])
        obj: dict[str, Any] = {}
        for pname, pschema in props.items():
            might_be_object = isinstance(pschema, dict) and (
                "$ref" in pschema
                or schema_type(pschema) == "object"
                or "properties" in pschema
                or any(k in pschema for k in _COMPOSITIONS)
            )
            if pname not in required and not might_be_object:
                continue
            value = value_from_schema(
                pschema, spec, seed, pname, depth=depth + 1, seen=seen
            )
            # An optional field goes in only when it really is a nested object:
            # an optional scalar behind a $ref or an anyOf is left to the
            # target's default, which is valid by definition — an invented
            # value for it is the commonest reason a create is refused.
            if pname not in required and not (isinstance(value, dict) and value):
                continue
            obj[pname] = value
        return obj
    if t == "array":
        item = value_from_schema(
            schema.get("items") or {}, spec, seed, name, depth=depth + 1, seen=seen
        )
        return [item]
    if "const" in schema:
        return schema["const"]
    enum = schema.get("enum")
    if isinstance(enum, list) and enum:
        return _unprivileged_choice(enum)
    if t in ("integer", "number"):
        minimum = schema.get("minimum")
        if isinstance(minimum, int | float) and not isinstance(minimum, bool):
            return minimum
        return 1
    if t == "boolean":
        return False
    return string_value(name, schema, seed)


def _unprivileged_choice(options: list[Any]) -> Any:
    """The first enum value that does not name privileged access.

    A create body fills a required enum with one of its values; ``role:
    [admin, user]`` must become ``user``. A scanner that grants itself a role
    while testing someone's API has escalated privileges, not found a bug.
    """
    for option in options:
        text = str(option).lower()
        if not any(token in text for token in (*PRIVILEGE_TOKENS, "owner", "super")):
            return option
    return options[0]


def spec_body(
    op: TargetOperation,
    spec: dict[str, Any] | None,
    seed: str,
    target_base_url: str | None = None,
) -> dict[str, Any] | None:
    """The body built from ``op``'s full request schema, or None when the spec
    declares no resolvable JSON object body."""
    schema = request_schema(spec, op, target_base_url)
    if not schema or not isinstance(spec, dict):
        return None
    body = value_from_schema(schema, spec, seed)
    return body if isinstance(body, dict) and body else None


def create_body(
    ctx: ScanContext,
    op: TargetOperation,
    field: str,
    value: Any,
    *,
    seed: str | None = None,
) -> dict[str, Any]:
    """A create body the target can accept, with ``field`` set to ``value``.

    Every required field the spec declares is filled with a valid value, then
    ``field`` carries the probe's canary. Without a usable spec this is
    :func:`~app.engine.resource_map.build_body`'s minimal body, as before. Pass
    ``seed`` to make two calls build the same other fields (a duplicate-create
    probe needs that); by default each call varies them, so successive creates
    do not collide on some unique field the probe is not about.
    """
    minimal = build_body(op, field, value)
    full = spec_body(op, ctx.spec, seed or uuid.uuid4().hex[:12], ctx.base_url)
    if full is None:
        return minimal
    body = {**minimal, **full}
    body[field] = value
    return body
