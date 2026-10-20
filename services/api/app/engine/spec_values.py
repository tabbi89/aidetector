"""Spec-shaped injection: type/enum/format-aware values and injection points.

The parser retains each parameter's declared schema facts (``type`` / ``format``
/ ``enum``) in the operation's ``params``. These helpers turn that into:

- **baseline values** — a spec-valid placeholder for the params we are *not*
  injecting, so a payload survives upfront type/enum validation and reaches the
  sink instead of being rejected with a 400/422 before it ever runs;
- **injection values** — the payload placed into the *target* param, kept
  type-plausible (a valid prefix for typed/enum/formatted params) while the
  ``aidx`` marker still travels verbatim so reflection detection is unchanged;
- **injection points** — the concrete sinks a reflection payload is placed into:
  query + path params on ``GET``, JSON body fields on ``POST``/``PUT``/``PATCH``.

Pure (no I/O) so the injection checks stay unit-testable. Path params on
mutating verbs and query params on mutating verbs are deliberately *not* fuzzed:
reflection is a response-body signal, and we avoid blasting junk path segments
at non-idempotent endpoints.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from app.engine.base import TargetOperation, render_path

_MUTATING = ("POST", "PUT", "PATCH")
_NUMERICISH = ("integer", "number", "boolean")
_FORMATTED = (
    "uuid", "email", "date", "date-time", "uri", "url",
    "hostname", "ipv4", "ipv6",
)


@dataclass(frozen=True)
class InjectionPoint:
    location: str  # "query" | "path" | "body"
    name: str
    schema: dict[str, Any] = field(default_factory=dict)
    pointer: tuple = ()
    body: Any = None
    media_type: str = "application/json"
    variant: int = 0


def schema_type(schema: dict[str, Any] | None) -> str | None:
    """A schema's ``type`` as one name.

    OpenAPI 3.1 allows a list (``["integer", "null"]``). Code that compared the
    raw value against a set raised ``TypeError: unhashable type: 'list'``, and
    the body-shape builder swallowed it — every body point of every operation
    using one was silently dropped. The first non-``null`` entry is the value
    a valid request would carry.
    """
    kind = (schema or {}).get("type")
    if isinstance(kind, list):
        named = [str(k) for k in kind if k != "null"]
        return named[0] if named else ("null" if kind else None)
    return kind if isinstance(kind, str) else None


def base_value(schema: dict[str, Any] | None) -> str:
    """A spec-valid placeholder for a parameter given its declared schema facts.

    Used to fill the params we are not injecting (and path templates) so the
    request passes type/enum/format validation.
    """
    schema = schema or {}
    enum = schema.get("enum")
    if isinstance(enum, list) and enum:
        return str(enum[0])
    fmt = schema.get("format")
    if fmt == "uuid":
        return "00000000-0000-4000-8000-000000000000"
    if fmt == "email":
        return "probe@example.com"
    if fmt == "date":
        return "2020-01-01"
    if fmt == "date-time":
        return "2020-01-01T00:00:00Z"
    if fmt in ("uri", "url"):
        return "https://example.com"
    if fmt == "hostname":
        return "example.com"
    if fmt == "ipv4":
        return "192.0.2.1"
    if fmt == "ipv6":
        return "2001:db8::1"
    t = schema_type(schema)
    if t in ("integer", "number"):
        return "1"
    if t == "boolean":
        return "true"
    return "1"


def injection_value(schema: dict[str, Any] | None, payload: str) -> str:
    """The value placed into the *target* parameter.

    For enum / numeric / formatted params we keep a valid prefix so an upfront
    validator is more likely to pass the value through to the sink, while the
    payload (and its ``aidx`` marker) still travels verbatim. A plain string or
    an unschema'd param gets the payload as-is (back-compatible with the prior
    query-only behaviour).
    """
    schema = schema or {}
    enum = schema.get("enum")
    if isinstance(enum, list) and enum:
        return f"{enum[0]}{payload}"
    t = schema_type(schema)
    if t in _NUMERICISH:
        return f"{base_value(schema)}{payload}"
    if t == "string" and schema.get("format") in _FORMATTED:
        return f"{base_value(schema)}{payload}"
    return payload


def injection_points(op: TargetOperation, allow_body_writes: bool = False) -> list[InjectionPoint]:
    """The sinks to fuzz for ``op``.

    ``GET`` → query and path params (idempotent, reflective, always fuzzed).
    ``POST``/``PUT``/``PATCH`` → JSON body fields, but only when
    ``allow_body_writes`` is set: sending a body to a mutating verb changes target
    state (creates/updates resources), so it is gated behind the ``mutate: true``
    opt-in exactly like the write oracle. Other verbs/locations are untouched.
    """
    pts: list[InjectionPoint] = []
    if op.method == "GET" or (op.method in _MUTATING and allow_body_writes):
        for p in op.params:
            name, loc = p.get("name"), p.get("in")
            if not name:
                continue
            allowed = (op.method == "GET" and loc in ("query", "path")) or (
                op.method in _MUTATING and loc == "body"
            )
            if allowed:
                if loc == "header" and name.lower() in {
                    "host", "content-length", "transfer-encoding", "connection",
                    "authorization", "proxy-authorization", "cookie", "content-type",
                }:
                    continue
                pts.append(InjectionPoint(str(loc), str(name), p.get("schema") or {}))

    return pts


def _baseline_map(op: TargetOperation, location: str, exclude: str) -> dict[str, str]:
    """Spec-valid values for the *required* params in ``location`` except the target."""
    out: dict[str, str] = {}
    for p in op.params:
        name = p.get("name")
        if p.get("in") == location and name and name != exclude and p.get("required"):
            out[name] = base_value(p.get("schema") or {})
    return out


def prepare(
    op: TargetOperation,
    point: InjectionPoint,
    value: str,
    resource_ids: dict[str, str] | None = None,
) -> tuple[str, dict[str, str] | None, dict[str, str] | None]:
    """Build ``(path, params, json_body)`` for a probe send that injects ``value``
    into ``point`` while filling the operation's other required params with
    spec-valid baselines."""
    path_values = {
        p["name"]: base_value(p.get("schema") or {})
        for p in op.params
        if p.get("in") == "path" and p.get("name")
    }
    if resource_ids:
        from app.engine.resource_map import resource_id_for

        for name in op.path_params:
            supplied = resource_id_for(op.path, name, resource_ids)
            if supplied is not None:
                path_values[name] = supplied
    json_body: dict[str, str] | None = None

    # Always seed the operation's required query params with spec-valid values so
    # the request passes validation, whichever sink we are injecting into.
    query = _baseline_map(op, "query", point.name if point.location == "query" else "")

    if point.location == "path":
        path_values[point.name] = value
    elif point.location == "query":
        query[point.name] = value
    elif point.location == "body":
        json_body = _baseline_map(op, "body", point.name)
        json_body[point.name] = value

    return render_path(op.path, path_values), (query or None), json_body
