"""Bounded schema alternatives and transport-aware injection request builders.

Keep the schema tree here; the legacy flattened body fields remain available to
resource pairing. A variant is one complete body, never a union of alternatives.
"""

from __future__ import annotations

import copy
import json
from dataclasses import replace
from typing import Any
from urllib.parse import quote, urlencode

from app.engine.base import ScanContext, TargetOperation
from app.engine.spec_values import (
    InjectionPoint,
    base_value,
    injection_points,
    prepare,
    schema_type,
)

MAX_POINTS = 32
MAX_VARIANTS = 4
_BLOCKED_HEADERS = {
    "host",
    "content-length",
    "transfer-encoding",
    "connection",
    "authorization",
    "proxy-authorization",
    "cookie",
    "content-type",
}


def resolve(schema: Any, root: dict, depth: int = 0) -> dict:
    if depth > 8 or not isinstance(schema, dict):
        return {"not": {}}
    if "$ref" in schema:
        ref = schema["$ref"]
        if not isinstance(ref, str) or not ref.startswith("#/"):
            return {"not": {}}
        node: Any = root
        for part in ref[2:].split("/"):
            node = (
                node.get(part.replace("~1", "/").replace("~0", "~"))
                if isinstance(node, dict)
                else None
            )
        return resolve(node, root, depth + 1)
    out = dict(schema)
    for key in ("properties",):
        if isinstance(out.get(key), dict):
            out[key] = {k: resolve(v, root, depth + 1) for k, v in out[key].items()}
    if isinstance(out.get("items"), dict):
        out["items"] = resolve(out["items"], root, depth + 1)
    for key in ("allOf", "oneOf", "anyOf"):
        if isinstance(out.get(key), list):
            out[key] = [resolve(v, root, depth + 1) for v in out[key][:MAX_VARIANTS]]
    return out


def _merge(left: dict, right: dict) -> dict:
    merged = {**left, **right}
    if "properties" in left or "properties" in right:
        merged["properties"] = {**left.get("properties", {}), **right.get("properties", {})}
    if "required" in left or "required" in right:
        merged["required"] = sorted(set(left.get("required", []) + right.get("required", [])))
    return merged


def variants(schema: dict, depth: int = 0) -> list[dict]:
    if depth > 8:
        return []
    base = {k: v for k, v in schema.items() if k not in {"oneOf", "anyOf", "allOf"}}
    alternatives = [base]
    for part in schema.get("allOf", []):
        alternatives = [
            _merge(v, child) for v in alternatives for child in variants(part, depth + 1)
        ][:MAX_VARIANTS]
    union = schema.get("oneOf", schema.get("anyOf", []))
    if union:
        alternatives = [
            _merge(v, child)
            for v in alternatives
            for part in union
            for child in variants(part, depth + 1)
        ][:MAX_VARIANTS]
    expanded = []
    for alternative in alternatives:
        branches = [alternative]
        for name, prop in alternative.get("properties", {}).items():
            children = variants(prop, depth + 1)
            branches = [
                {**branch, "properties": {**branch["properties"], name: child}}
                for branch in branches
                for child in children
            ][:MAX_VARIANTS]
        if isinstance(alternative.get("items"), dict):
            branches = [
                {**branch, "items": child}
                for branch in branches
                for child in variants(alternative["items"], depth + 1)
            ][:MAX_VARIANTS]
        expanded.extend(branches)
    return expanded[:MAX_VARIANTS]


def baseline(schema: dict, depth: int = 0) -> Any:
    if depth > 8:
        raise ValueError("schema depth exceeded")
    choices = variants(schema, depth)
    if not choices:
        raise ValueError("unsupported schema")
    schema = choices[0]
    if "const" in schema:
        return schema["const"]
    if schema.get("enum"):
        return schema["enum"][0]
    kind = schema_type(schema)
    if kind == "object" or "properties" in schema:
        return {
            k: baseline(v, depth + 1)
            for k, v in schema.get("properties", {}).items()
            if not v.get("readOnly")
        }
    if kind == "array":
        count = max(1, schema.get("minItems", 1))
        if count > 4:
            raise ValueError("array minimum exceeds bounded generator")
        return [baseline(schema.get("items", {}), depth + 1) for _ in range(count)]
    if kind == "boolean":
        return True
    if kind in {"integer", "number"}:
        value = max(1, schema.get("minimum", 1))
        if "maximum" in schema:
            value = min(value, schema["maximum"])
        return int(value) if kind == "integer" else float(value)
    if kind == "null":
        return None
    text = base_value(schema)
    minimum = schema.get("minLength", 0)
    if minimum > 1024:
        raise ValueError("string minimum exceeds bounded generator")
    return text.ljust(minimum, "a")[: schema.get("maxLength", 1024)]


def leaves(value: Any, path: tuple = ()):
    if isinstance(value, dict):
        for key, child in value.items():
            yield from leaves(child, (*path, key))
    elif isinstance(value, list):
        for index, child in enumerate(value):
            yield from leaves(child, (*path, index))
    else:
        yield path, value


def body_schemas(ctx: ScanContext, op: TargetOperation) -> list[tuple[str, dict]]:
    spec = ctx.spec or {}
    paths = spec.get("paths", {})
    matches = [item for path, item in paths.items() if op.path == path or op.path.endswith(path)]
    item = paths.get(op.path) or (matches[0] if len(matches) == 1 else {})
    raw = item.get(op.method.lower(), {})
    body = raw.get("requestBody", {})
    content = body.get("content", {})
    result = [
        (ctype, resolve(media.get("schema", {}), spec))
        for ctype, media in content.items()
        if isinstance(media, dict)
        and (
            "json" in ctype
            or ctype in {"application/x-www-form-urlencoded", "multipart/form-data", "text/plain"}
        )
    ]
    if not result:
        for param in raw.get("parameters", []):
            if param.get("in") == "body":
                result.append(("application/json", resolve(param.get("schema", {}), spec)))
    return result[:MAX_VARIANTS]


def points(ctx: ScanContext, op: TargetOperation) -> list[InjectionPoint]:
    pts = injection_points(op, ctx.allow_mutation)
    if op.method == "GET":
        reserved = {
            "host", "content-length", "transfer-encoding", "connection",
            "authorization", "proxy-authorization", "cookie", "content-type",
        }
        for param in op.params:
            location = param.get("in")
            name = param.get("name")
            if location in {"header", "cookie"} and name and name.lower() not in reserved:
                pts.append(InjectionPoint(str(location), str(name), param.get("schema") or {}))
    if op.method not in {"POST", "PUT", "PATCH"} or not ctx.allow_mutation:
        return pts[:MAX_POINTS]
    schemas = body_schemas(ctx, op)
    if not schemas:
        return pts[:MAX_POINTS]
    pts = [p for p in pts if p.location != "body"]
    from jsonschema import Draft202012Validator

    for media, schema in schemas:
        encoded = json.dumps(schema)
        if len(encoded) > 32768 or '"$ref"' in encoded:
            continue  # unresolved refs must never trigger validator network I/O
        for variant_index, variant in enumerate(variants(schema)):
            try:
                value = baseline(variant)
                # Never describe a structurally rejected variant as a valid control.
                if not Draft202012Validator(schema).is_valid(value):
                    continue
            except Exception:
                continue
            for pointer, _leaf in leaves(value):
                if len(pts) >= MAX_POINTS:
                    return pts
                name = "/" + "/".join(str(p).replace("~", "~0").replace("/", "~1") for p in pointer)
                pts.append(InjectionPoint("body", name, {}, pointer, value, media, variant_index))
    return pts


def request(
    ctx: ScanContext,
    op: TargetOperation,
    point: InjectionPoint,
    value: Any,
    headers: dict[str, str],
) -> tuple[str, dict[str, Any]]:
    old_point = (
        point
        if point.location in {"path", "query", "body"}
        else replace(point, location="query", name="__unused__")
    )
    path, params, prepared_body = prepare(op, old_point, value, ctx.resource_ids)
    body: Any = prepared_body
    if params:
        params.pop("__unused__", None)
    outgoing = dict(headers)
    # Required transport fields, preserving actual credentials supplied by the user.
    for param in op.params:
        name, loc = param.get("name", ""), param.get("in")
        if loc == "header" and param.get("required") and name.lower() not in _BLOCKED_HEADERS:
            if name.lower() not in {k.lower() for k in outgoing}:
                outgoing[name] = base_value(param.get("schema"))
    if point.location == "header":
        if point.name.lower() in _BLOCKED_HEADERS:
            raise ValueError("reserved transport header")
        outgoing[point.name] = str(value)
    if point.location == "cookie":
        cookie_key = next((k for k in outgoing if k.lower() == "cookie"), "Cookie")
        cookies = [
            c.strip()
            for c in outgoing.get(cookie_key, "").split(";")
            if c.strip() and c.strip().split("=", 1)[0] != point.name
        ]
        cookies.append(f"{point.name}={quote(str(value), safe='')}")
        outgoing[cookie_key] = "; ".join(cookies)
    if point.body is not None:
        body = copy.deepcopy(point.body)
        if not point.pointer:
            body = value
        else:
            node = body
            for part in point.pointer[:-1]:
                node = node[part]
            node[point.pointer[-1]] = value
    elif op.method in {"POST", "PUT", "PATCH"}:
        # Legacy top-level fields still get JSON-native sibling types.
        body = {
            p["name"]: baseline(p.get("schema") or {})
            for p in op.params
            if p.get("in") == "body" and p.get("required")
        }
        if point.location == "body":
            body[point.name] = value
    kwargs: dict[str, Any] = {"headers": outgoing, "params": params}
    if body is not None:
        media = point.media_type
        if media == "application/x-www-form-urlencoded":
            if not isinstance(body, dict) or any(isinstance(v, dict | list) for v in body.values()):
                raise ValueError("nested form encoding unsupported")
            outgoing["Content-Type"] = media
            kwargs["content"] = urlencode(body).encode()
        elif media == "multipart/form-data":
            if not isinstance(body, dict) or any(isinstance(v, dict | list) for v in body.values()):
                raise ValueError("nested multipart encoding unsupported")
            boundary = "runpentests-boundary"
            parts = []
            for name, item in body.items():
                if any(c in str(name) for c in '\r\n"'):
                    raise ValueError("invalid multipart field name")
                parts.append(
                    f'--{boundary}\r\nContent-Disposition: form-data; name="{name}"'
                    f"\r\n\r\n{item}\r\n"
                )
            kwargs["content"] = ("".join(parts) + f"--{boundary}--\r\n").encode()
            outgoing["Content-Type"] = f"{media}; boundary={boundary}"
        elif media == "text/plain":
            if isinstance(body, dict | list):
                raise ValueError("structured plain-text body unsupported")
            kwargs["content"] = str(body).encode()
            outgoing["Content-Type"] = media
        else:
            kwargs["json"] = body
    return path, kwargs


def control_value(point: InjectionPoint) -> Any:
    if point.body is not None:
        value = point.body
        for part in point.pointer:
            value = value[part]
        return value
    return baseline(point.schema)
