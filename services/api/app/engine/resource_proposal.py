"""Validate an AI-proposed create body and build the AI's value-free input.

J1 (AI-created valid resources): when the deterministic resource seed fails
validation, the planner proposes a spec-valid body. This module is the trust
boundary between the model's output and the probe — everything the model returns
is checked against the operation's declared body fields before any request is
sent. Pure (no I/O) so the validation is unit-testable, and value-free on the
way in (no secrets, no target values).
"""
from __future__ import annotations

from typing import Any

from app.engine.base import TargetOperation
from app.specs.parser import spec_operation

_MAX_FIELDS = 100
_MAX_STR = 512


def body_fields(producer: TargetOperation) -> list[dict[str, Any]]:
    """The operation's declared JSON request-body field params."""
    return [p for p in producer.params if p.get("in") == "body" and p.get("name")]


def _value_ok(schema: dict[str, Any], value: Any) -> bool:
    """A shallow, defensive check of one value against its schema facts."""
    t = schema.get("type")
    if t == "string":
        if not isinstance(value, str) or len(value) > _MAX_STR:
            return False
    elif t == "integer":
        if isinstance(value, bool) or not isinstance(value, int):
            return False
    elif t == "number":
        if isinstance(value, bool) or not isinstance(value, int | float):
            return False
    elif t == "boolean":
        if not isinstance(value, bool):
            return False
    elif t == "object":
        if not isinstance(value, dict) or len(value) > _MAX_FIELDS:
            return False
    elif t == "array":
        if not isinstance(value, list) or len(value) > _MAX_FIELDS:
            return False

    enum = schema.get("enum")
    if enum and value not in enum:
        return False
    if isinstance(value, str):
        if isinstance(schema.get("minLength"), int) and len(value) < schema["minLength"]:
            return False
        if isinstance(schema.get("maxLength"), int) and len(value) > schema["maxLength"]:
            return False
    if isinstance(value, int | float) and not isinstance(value, bool):
        minimum = schema.get("minimum")
        maximum = schema.get("maximum")
        if isinstance(minimum, int | float) and not isinstance(minimum, bool) and value < minimum:
            return False
        if isinstance(maximum, int | float) and not isinstance(maximum, bool) and value > maximum:
            return False
    return True


def validate_body(
    producer: TargetOperation, body: Any
) -> tuple[dict[str, Any] | None, str]:
    """Accept a proposed create body only when it matches the declared shape.

    Returns ``(body, "")`` on success, or ``(None, reason)`` on rejection. Only
    declared top-level field names are allowed, required fields must be present,
    and each value must pass ``_value_ok``. Nested objects under an object-typed
    field are allowed but size-bounded.
    """
    if not isinstance(body, dict):
        return None, "not a JSON object"
    if len(body) > _MAX_FIELDS:
        return None, "too many fields"
    declared = {str(p["name"]): (p.get("schema") or {}) for p in body_fields(producer)}
    if not declared:
        return None, "no declared body fields"
    for name, value in body.items():
        if name not in declared:
            return None, f"undeclared field {name!r}"
        if not _value_ok(declared[name], value):
            return None, f"value for {name!r} does not match its schema"
    for p in body_fields(producer):
        if p.get("required") and p["name"] not in body:
            return None, f"required field {p['name']!r} missing"
    return body, ""


def request_schema(
    spec: dict[str, Any] | None,
    producer: TargetOperation,
    target_base_url: str | None = None,
) -> dict[str, Any] | None:
    """The operation's declared JSON request-body schema, best-effort.

    Public because ``resource_bootstrap`` builds a create body from the same
    schema this module validates a proposal against — the two must agree on what
    "the declared body" is, so they read it through one function.
    """
    op = spec_operation(spec, producer.method, producer.path, target_base_url)
    if op is None:
        return None
    body = op.get("requestBody")
    if not isinstance(body, dict):
        return None
    content = body.get("content")
    if not isinstance(content, dict):
        return None
    for ctype, media in content.items():
        if (
            "json" in str(ctype).lower()
            and isinstance(media, dict)
            and isinstance(media.get("schema"), dict)
        ):
            return media["schema"]
    return None


def proposal_payload(
    producer: TargetOperation,
    spec: dict[str, Any] | None,
    *,
    previous_body: dict[str, Any] | None = None,
    response: dict[str, Any] | None = None,
    schema_context: dict[str, Any] | None = None,
    target_base_url: str | None = None,
) -> dict[str, Any]:
    """The bounded input the planner needs to craft or refine a create body.

    Carries the flattened body fields plus the full declared request-body schema
    and the spec's components (so the model can resolve ``$ref`` to nested
    required fields and cross-field rules). A prior body contains scanner-made
    fixture values only; the response is a redacted failure observation and DB
    context is read-only schema metadata. No credentials or database rows.
    """
    fields = [
        {
            "name": str(p.get("name")),
            "required": bool(p.get("required")),
            "schema": p.get("schema") or {},
        }
        for p in body_fields(producer)
    ]
    payload: dict[str, Any] = {
        "method": producer.method,
        "path": producer.path,
        "fields": fields,
    }
    schema = request_schema(spec, producer, target_base_url)
    if schema is not None:
        payload["request_schema"] = schema
    components = spec.get("components") if isinstance(spec, dict) else None
    if isinstance(components, dict):
        payload["components"] = components
    if previous_body is not None:
        payload["previous_body"] = previous_body
    if response is not None:
        payload["previous_response"] = response
    if schema_context is not None:
        payload["database_schema_metadata"] = schema_context
    return payload
