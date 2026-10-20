"""OpenAPI / Swagger parsing → normalized operations.

Supports OpenAPI 3.x and Swagger 2.0, from JSON or YAML text. Kept
dependency-light and defensive: malformed specs raise SpecError with a
human-readable reason rather than a stack trace.
"""
from __future__ import annotations

import json
import re
from collections.abc import Iterator
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urlsplit

import yaml

HTTP_METHODS = {"get", "put", "post", "delete", "patch", "head", "options", "trace"}


class SpecError(ValueError):
    """Raised when a spec cannot be parsed into operations."""


@dataclass
class ParsedOperation:
    method: str
    path: str
    params: list[dict[str, Any]] = field(default_factory=list)
    auth_scope: str | None = None


def load_spec(text: str, *, remote_ref_allowlist: list[str] | None = None) -> dict[str, Any]:
    """Parse spec text as JSON, falling back to YAML.

    Internal ``$ref``s are inlined with prance (SSRF-safe: never fetches). Remote
    ``$ref``s are inlined only when ``remote_ref_allowlist`` (from
    ``settings.spec_ref_allowlist`` by default) permits their host — off unless
    configured. See ``app/specs/remote_refs.py``.
    """
    text = text.strip()
    if not text:
        raise SpecError("spec is empty")
    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        try:
            data = yaml.safe_load(text)
        except yaml.YAMLError as exc:
            raise SpecError(f"spec is not valid JSON or YAML: {exc}") from exc
    if not isinstance(data, dict):
        raise SpecError("spec root must be an object")
    if "$ref" not in text:
        return data
    # Inline allowlisted remote $refs first (a no-op unless configured), so the
    # internal resolver below then composes the fetched schemas alongside ours.
    internal_text = text
    allowlist = _remote_ref_allowlist(remote_ref_allowlist)
    if allowlist and ("http://" in text or "https://" in text):
        from app.specs.remote_refs import inline_remote_refs

        data = inline_remote_refs(data, allowlist=allowlist)
        internal_text = json.dumps(data)
    # Best-effort: inline internal $refs with prance so composed/nested schemas
    # resolve robustly. Internal-only (RESOLVE_INTERNAL) so a malicious spec can
    # never make us fetch a remote $ref (SSRF). Any failure falls back to the raw
    # dict, which the lenient hand-rolled resolver still handles.
    resolved = _resolve_spec_refs(internal_text)
    if resolved is not None:
        data = resolved
    return data


def _remote_ref_allowlist(override: list[str] | None) -> list[str]:
    """The remote-$ref host allowlist: an explicit override, else settings."""
    if override is not None:
        return override
    try:
        from app.core.config import settings

        return settings.spec_ref_allowlist_set()
    except Exception:  # noqa: BLE001 — config unavailable → remote refs stay off
        return []


def _resolve_spec_refs(text: str) -> dict[str, Any] | None:
    """Return the spec with internal ``$ref``s inlined via prance, or None."""
    try:
        from prance import ResolvingParser
        from prance.util.resolver import RESOLVE_INTERNAL
    except Exception:  # noqa: BLE001 — prance optional; degrade to hand-rolled refs
        return None
    try:
        parser = ResolvingParser(
            spec_string=text,
            resolve_types=RESOLVE_INTERNAL,  # never fetch remote/file refs (SSRF-safe)
            backend="openapi-spec-validator",
            strict=False,
            lazy=False,
        )
        spec = parser.specification
    except Exception:  # noqa: BLE001 — any resolution problem → fall back to raw
        return None
    return spec if isinstance(spec, dict) else None


def spec_warnings(data: dict[str, Any]) -> list[str]:
    """Non-fatal structural problems in a spec, via openapi-spec-validator.

    The hand-rolled parser is deliberately lenient so it can still extract
    operations from a partial spec. This runs a real schema validation on top so
    genuine structural issues (bad ``$ref`` targets, malformed parameter objects)
    can be surfaced to the user as warnings instead of silently producing thin
    coverage. Never raises — a validator problem must not block an upload.
    """
    try:
        from openapi_spec_validator import validate as _validate
    except Exception:  # noqa: BLE001 — validator optional; degrade to no warnings
        return []
    try:
        _validate(data)  # type: ignore[arg-type]
    except Exception as exc:  # noqa: BLE001 — surface as a warning, never fatal
        first = str(exc).strip().splitlines()[0] if str(exc).strip() else "invalid spec"
        return [first[:300]]
    return []


def _spec_version(data: dict[str, Any]) -> str:
    if "openapi" in data:
        return "3"
    if "swagger" in data:
        return "2"
    raise SpecError("missing 'openapi' or 'swagger' version field")


def _security_scope(op_security: Any, global_security: Any) -> str | None:
    """Retain security scheme names and OAuth scopes used for privilege decisions."""
    sec = op_security if op_security is not None else global_security
    if not sec:
        return None
    names: list[str] = []
    for req in sec:
        if isinstance(req, dict):
            for scheme, scopes in req.items():
                names.append(str(scheme))
                if isinstance(scopes, list):
                    names.extend(str(scope) for scope in scopes if scope)
    return ", ".join(dict.fromkeys(names)) or None


_SERVER_VAR = re.compile(r"\{([^{}]+)\}")


def _server_path(servers: Any) -> str:
    """Path component of the first OpenAPI server, expanding variable defaults."""
    if not isinstance(servers, list) or not servers or not isinstance(servers[0], dict):
        return ""
    server = servers[0]
    raw = server.get("url")
    if not isinstance(raw, str):
        return ""
    raw_variables = server.get("variables")
    variables: dict[Any, Any] = raw_variables if isinstance(raw_variables, dict) else {}

    def replace(match: re.Match[str]) -> str:
        value = variables.get(match.group(1), {})
        return str(value.get("default", "")) if isinstance(value, dict) else ""

    path = urlsplit(_SERVER_VAR.sub(replace, raw)).path.rstrip("/")
    return path if path and path != "/" else ""


def join_route(prefix: str, path: str, target_base_url: str | None) -> str:
    """Combine a declared server/basePath with an operation path once.

    Public so a consumer that reads the spec document itself (Schemathesis in
    ``schema_fuzz``) composes the same runtime route the parser stored.
    """
    if not path.startswith("/") or path.startswith("//"):
        raise SpecError(f"operation path must be origin-relative and start with '/': {path!r}")
    prefix = (prefix or "").strip()
    if prefix and (not prefix.startswith("/") or prefix.startswith("//")):
        raise SpecError(f"server/basePath must be origin-relative: {prefix!r}")
    prefix = prefix.rstrip("/")
    target_path = urlsplit(target_base_url or "").path.rstrip("/")
    desired = f"{prefix}{path}" or "/"
    if prefix and target_path and (
        target_path == prefix or target_path.endswith(prefix)
    ):
        return path
    if target_path and (desired == target_path or desired.startswith(f"{target_path}/")):
        return desired[len(target_path):] or "/"
    return desired


def routing_warnings(data: dict[str, Any], target_base_url: str) -> list[str]:
    """Explain ambiguous target/spec path composition before a scan runs."""
    version = _spec_version(data)
    prefixes: set[str] = set()
    if version == "2":
        prefix = str(data.get("basePath") or "").rstrip("/")
        if prefix:
            prefixes.add(prefix)
    else:
        root = _server_path(data.get("servers"))
        if root:
            prefixes.add(root)
        paths = data.get("paths")
        if isinstance(paths, dict):
            for item in paths.values():
                if not isinstance(item, dict):
                    continue
                item_prefix = _server_path(item.get("servers"))
                if item_prefix:
                    prefixes.add(item_prefix)
                for operation in item.values():
                    if isinstance(operation, dict):
                        op_prefix = _server_path(operation.get("servers"))
                        if op_prefix:
                            prefixes.add(op_prefix)

    target_path = urlsplit(target_base_url).path.rstrip("/")
    if not target_path:
        return []
    return [
        (
            f"target base path '{target_path}' and spec server path '{prefix}' "
            f"do not overlap; requests will be composed under '{target_path}{prefix}'"
        )
        for prefix in sorted(prefixes)
        if not (
            target_path == prefix
            or target_path.endswith(prefix)
            or prefix.startswith(f"{target_path}/")
        )
    ]


def _schema_facts(src: dict[str, Any]) -> dict[str, Any]:
    """Compact validation facts from a schema-ish dict.

    Works for an OpenAPI 3 ``schema`` object, a Swagger 2 parameter (which carries
    ``type``/``format``/``enum`` inline), or a JSON body property schema. Kept
    compact on purpose — it is persisted in the operation's ``params`` JSON and
    consumed by the schema-driven engine passes. Nested request-body structure
    is intentionally handled by the parser rather than copied wholesale into
    every operation row.
    """
    out: dict[str, Any] = {}
    t = src.get("type")
    if isinstance(t, str):
        out["type"] = t
    fmt = src.get("format")
    if isinstance(fmt, str):
        out["format"] = fmt
    enum = src.get("enum")
    if isinstance(enum, list) and enum:
        vals = [e for e in enum if isinstance(e, str | int | float | bool)]
        if vals:
            out["enum"] = vals
    for key in ("minLength", "maxLength", "minimum", "maximum"):
        value = src.get(key)
        if isinstance(value, int | float) and not isinstance(value, bool):
            out[key] = value
    for key in ("exclusiveMinimum", "exclusiveMaximum"):
        value = src.get(key)
        if isinstance(value, bool) or isinstance(value, int | float):
            out[key] = value
    return out


def _param_schema(p: dict[str, Any]) -> dict[str, Any]:
    """Schema facts for a non-body parameter (OpenAPI 3 ``schema`` or Swagger 2 inline)."""
    schema = p.get("schema")
    if isinstance(schema, dict):
        return _schema_facts(schema)
    return _schema_facts(p)


def _resolve_ref(schema: Any, root: dict[str, Any], _depth: int = 0) -> Any:
    """Follow a JSON ``$ref`` (e.g. ``#/components/schemas/Note``) into ``root``.

    Real specs (FastAPI especially) put request bodies behind a ``$ref`` to
    ``components/schemas``; without this, no body fields are surfaced. Bounded
    depth guards against ref cycles. Also flattens a single ``allOf`` wrapper.
    """
    seen = 0
    while isinstance(schema, dict) and "$ref" in schema and seen < 10:
        ref = schema["$ref"]
        if not isinstance(ref, str) or not ref.startswith("#/"):
            return schema
        node: Any = root
        for part in ref[2:].split("/"):
            if not isinstance(node, dict):
                return schema
            node = node.get(part)
        schema = node
        seen += 1
    if isinstance(schema, dict) and "properties" not in schema and isinstance(
        schema.get("allOf"), list
    ):
        for part in schema["allOf"]:
            resolved = _resolve_ref(part, root, _depth + 1)
            if isinstance(resolved, dict) and isinstance(resolved.get("properties"), dict):
                return resolved
    return schema


def _follow_ref(schema: Any, root: dict[str, Any]) -> Any:
    """Chase a ``#/`` ``$ref`` chain to its target (no ``allOf`` flattening)."""
    seen = 0
    while isinstance(schema, dict) and "$ref" in schema and seen < 10:
        ref = schema["$ref"]
        if not isinstance(ref, str) or not ref.startswith("#/"):
            return schema
        node: Any = root
        for part in ref[2:].split("/"):
            if not isinstance(node, dict):
                return schema
            node = node.get(part)
        schema = node
        seen += 1
    return schema


def _merge_schema(
    schema: Any, root: dict[str, Any], _depth: int = 0
) -> tuple[dict[str, Any], set[str]]:
    """Collect ``(properties, required)`` from a possibly-composed object schema.

    Resolves ``$ref`` and merges the properties of every ``allOf`` / ``oneOf`` /
    ``anyOf`` member (recursively, bounded depth), so a request body built from
    composed schemas surfaces *all* candidate fields for body-sink fuzzing and
    the write oracle — not just the first ``allOf`` branch. ``required`` is taken
    from the base and ``allOf`` members only (``oneOf``/``anyOf`` fields are
    optional by nature).
    """
    if _depth > 8:
        return {}, set()
    schema = _follow_ref(schema, root)
    if not isinstance(schema, dict):
        return {}, set()

    props: dict[str, Any] = {}
    required: set[str] = set()

    declared = schema.get("properties")
    if isinstance(declared, dict):
        for name, prop in declared.items():
            if isinstance(name, str):
                props.setdefault(name, prop if isinstance(prop, dict) else {})
    req = schema.get("required")
    if isinstance(req, list):
        required |= {r for r in req if isinstance(r, str)}

    for key in ("allOf", "oneOf", "anyOf"):
        members = schema.get(key)
        if isinstance(members, list):
            for member in members:
                mprops, mreq = _merge_schema(member, root, _depth + 1)
                for name, prop in mprops.items():
                    props.setdefault(name, prop)
                if key == "allOf":
                    required |= mreq
    return props, required


def _body_fields(
    op: dict[str, Any], raw_params: list[dict[str, Any]], root: dict[str, Any]
) -> list[dict[str, Any]]:
    """Top-level JSON request-body field names, as ``in: "body"`` params.

    Handles OpenAPI 3 (``requestBody.content['application/json'].schema``) and
    Swagger 2 (a parameter with ``in: body`` carrying a ``schema``), resolving a
    ``$ref`` schema against the spec root. Only the first level of ``properties``
    is surfaced — enough to seed body-sink fuzzing and the write oracle.
    """
    schema: Any = None
    body = op.get("requestBody")
    if isinstance(body, dict):
        content = body.get("content")
        if isinstance(content, dict):
            for ctype, media in content.items():
                if "json" in str(ctype).lower() and isinstance(media, dict):
                    schema = media.get("schema")
                    break
    if schema is None:
        for p in raw_params:
            if isinstance(p, dict) and p.get("in") == "body" and isinstance(p.get("schema"), dict):
                schema = p["schema"]
                break
    props, req_set = _merge_schema(schema, root)
    if not props:
        return []
    fields: list[dict[str, Any]] = []
    for name, prop in props.items():
        entry: dict[str, Any] = {"name": name, "in": "body", "required": name in req_set}
        facts = _schema_facts(prop) if isinstance(prop, dict) else {}
        if facts:
            entry["schema"] = facts
        fields.append(entry)
    return fields


def _declared_operations(
    data: dict[str, Any], version: str, keys: set[str] | None = None
) -> Iterator[tuple[str, dict[str, Any], str, dict[str, Any], str]]:
    """Each spec operation as ``(path key, path item, method, operation, prefix)``.

    ``prefix`` is the server/basePath the operation is served under: Swagger 2's
    ``basePath``, else the nearest OpenAPI 3 ``servers`` (operation, then path
    item, then root). The one walk behind :func:`parse_operations`,
    :func:`route_prefixes` and :func:`spec_operation`, so they cannot disagree
    on a route. ``keys`` limits the walk to those path keys.
    """
    paths = data.get("paths")
    if not isinstance(paths, dict):
        return
    root_prefix = (
        str(data.get("basePath") or "") if version == "2" else _server_path(data.get("servers"))
    )
    for path, item in paths.items():
        if not isinstance(path, str) or not isinstance(item, dict):
            continue
        if keys is not None and path not in keys:
            continue
        item_prefix = (
            _server_path(item.get("servers"))
            if version == "3" and "servers" in item
            else root_prefix
        )
        for method, op in item.items():
            if method.lower() not in HTTP_METHODS or not isinstance(op, dict):
                continue
            op_prefix = (
                _server_path(op.get("servers"))
                if version == "3" and "servers" in op
                else item_prefix
            )
            yield path, item, method, op, op_prefix


def route_prefixes(data: dict[str, Any]) -> dict[tuple[str, str], str]:
    """``(METHOD, spec path key) -> declared prefix`` for every operation.

    Pair with :func:`join_route` to turn a spec path key into the runtime route
    :func:`parse_operations` stored. Empty for a spec without a version.
    """
    try:
        version = _spec_version(data)
    except SpecError:
        return {}
    return {
        (method.upper(), path): prefix
        for path, _item, method, _op, prefix in _declared_operations(data, version)
    }


def spec_operation(
    data: dict[str, Any] | None,
    method: str,
    path: str,
    target_base_url: str | None = None,
) -> dict[str, Any] | None:
    """The raw spec operation behind a parsed ``(method, runtime path)``.

    A parsed path may carry the spec's server/basePath prefix (or have part of
    it cut by the target base URL), so it is not always a key of ``paths``.
    With ``target_base_url`` the route is recomposed exactly as
    :func:`parse_operations` composed it. Without it, or when that finds
    nothing (operations parsed against an earlier target), the exact key wins,
    else the one operation whose declared prefix plus key is the path.
    """
    found = _locate(data, method, path, target_base_url)
    return found[2] if found is not None else None


def recompose_route(
    data: dict[str, Any] | None,
    method: str,
    path: str,
    *,
    old_target: str | None,
    new_target: str | None,
) -> str | None:
    """The route :func:`parse_operations` composes under ``new_target`` for the
    operation stored as ``path``, or None when the spec has no such operation.

    ``path`` was composed under ``old_target`` — or under an earlier target still,
    which the lookup's fallbacks (exact key, prefix plus key) find too. A scan
    whose target changes keeps its operations; only their routes move.
    """
    found = _locate(data, method, path, old_target)
    if found is None:
        return None
    key, prefix, _op = found
    try:
        return join_route(prefix, key, new_target)
    except SpecError:
        return None


def _locate(
    data: dict[str, Any] | None,
    method: str,
    path: str,
    target_base_url: str | None,
) -> tuple[str, str, dict[str, Any]] | None:
    """``(path key, declared prefix, raw operation)`` behind a parsed route.

    The one lookup behind :func:`spec_operation` and :func:`recompose_route`.
    """
    if not isinstance(data, dict):
        return None
    paths = data.get("paths")
    if not isinstance(paths, dict):
        return None
    try:
        version = _spec_version(data)
    except SpecError:
        version = ""
    # A key can only produce this route if one ends with the other; checking
    # that first keeps a lookup from parsing every server entry in the spec.
    keys = {
        key for key in paths
        if isinstance(key, str) and (path.endswith(key) or key.endswith(path))
    }
    if version and target_base_url is not None:
        matches: list[tuple[str, str, dict[str, Any]]] = []
        for key, _item, op_method, op, prefix in _declared_operations(data, version, keys):
            if op_method.lower() != method.lower():
                continue
            try:
                if join_route(prefix, key, target_base_url) == path:
                    matches.append((key, prefix, op))
            except SpecError:
                continue
        if matches:
            return matches[0] if len(matches) == 1 else None
    item = paths.get(path)
    if isinstance(item, dict):
        exact = item.get(method.lower())
        if not isinstance(exact, dict):
            return None
        prefix = next(
            (
                found_prefix
                for _key, _item, op_method, _op, found_prefix in (
                    _declared_operations(data, version, {path}) if version else ()
                )
                if op_method.lower() == method.lower()
            ),
            "",
        )
        return path, prefix, exact
    if not version:
        return None
    candidates = [
        (key, prefix, op)
        for key, _item, op_method, op, prefix in _declared_operations(data, version, keys)
        if op_method.lower() == method.lower() and f"{prefix.rstrip('/')}{key}" == path
    ]
    return candidates[0] if len(candidates) == 1 else None


def parse_operations(
    data: dict[str, Any], *, target_base_url: str | None = None
) -> list[ParsedOperation]:
    """Flatten a spec's paths into normalized operations."""
    version = _spec_version(data)  # validates version presence
    paths = data.get("paths")
    if not isinstance(paths, dict) or not paths:
        raise SpecError("spec has no 'paths'")

    global_security = data.get("security")
    operations: list[ParsedOperation] = []

    for path, item, method, op, op_prefix in _declared_operations(data, version):
        shared_params = item.get("parameters", [])
        raw_params = list(shared_params) + list(op.get("parameters", []))
        params: list[dict[str, Any]] = []
        for p in raw_params:
            if not (isinstance(p, dict) and p.get("name") and p.get("in") != "body"):
                continue
            entry: dict[str, Any] = {
                "name": p.get("name"),
                "in": p.get("in"),
                "required": bool(p.get("required", False)),
            }
            facts = _param_schema(p)
            if facts:
                entry["schema"] = facts
            params.append(entry)
        # Expand JSON body schemas into individual `in: "body"` field params.
        params.extend(_body_fields(op, raw_params, data))
        operations.append(
            ParsedOperation(
                method=method.upper(),
                path=join_route(op_prefix, path, target_base_url),
                params=params,
                auth_scope=_security_scope(op.get("security"), global_security),
            )
        )

    if not operations:
        raise SpecError("no operations found in spec paths")
    return operations


def _response_schema(data: dict[str, Any], method: str, path: str) -> Any:
    """The resolved 2xx JSON response schema for an operation, or None.

    Shared by :func:`declared_response_fields` and
    :func:`declared_response_field_paths`. Array responses are unwrapped to their
    ``items`` schema so a collection endpoint is compared against one element's
    shape.
    """
    paths = data.get("paths")
    if not isinstance(paths, dict):
        return None
    item = paths.get(path)
    if not isinstance(item, dict):
        # Runtime operations may carry a server/basePath prefix that is not a
        # key in the spec. Match only on a full path-segment suffix.
        matches = [
            value
            for candidate, value in paths.items()
            if isinstance(candidate, str)
            and isinstance(value, dict)
            and (path == candidate or path.endswith(candidate))
        ]
        item = matches[0] if len(matches) == 1 else None
    if not isinstance(item, dict):
        return None
    op = item.get(method.lower())
    if not isinstance(op, dict):
        return None
    responses = op.get("responses")
    if not isinstance(responses, dict):
        return None

    schema: Any = None
    for code, response in responses.items():
        if not str(code).startswith("2") or not isinstance(response, dict):
            continue
        # OpenAPI 3 (content/media-type) with a Swagger 2 fallback (schema).
        content = response.get("content")
        if isinstance(content, dict):
            for ctype, media in content.items():
                if "json" in str(ctype).lower() and isinstance(media, dict):
                    schema = media.get("schema")
                    break
        if schema is None:
            schema = response.get("schema")
        if schema is not None:
            break
    if schema is None:
        return None

    schema = _follow_ref(schema, data)
    if isinstance(schema, dict) and schema.get("type") == "array":
        schema = _follow_ref(schema.get("items"), data)
    return schema


def declared_response_fields(
    data: dict[str, Any], method: str, path: str
) -> set[str] | None:
    """Top-level field names an operation's success response declares.

    ``None`` when the operation, or a 2xx JSON response schema for it, is not in
    the spec — the caller must treat "no declared contract" differently from
    "declares nothing", since only the second is evidence of anything.

    Composition (``$ref`` / ``allOf`` / ``oneOf`` / ``anyOf``) resolves through
    the same merge the request-body expansion uses, so the two agree.
    """
    schema = _response_schema(data, method, path)
    if schema is None:
        return None
    props, _ = _merge_schema(schema, data)
    return set(props) if props else None


def declared_response_field_paths(
    data: dict[str, Any], method: str, path: str
) -> set[str] | None:
    """Nested field paths an operation's success response schema declares.

    :func:`declared_response_fields` stops at the top level; this recurses into
    object properties and array items, producing paths in the same ``owner.email``
    / ``items[].id`` dotted form :func:`app.engine.exposure_policy.field_names`
    records for a response body. Spec drift can then be judged on nested fields,
    not just the top level. ``None`` when the operation has no documented 2xx
    JSON schema, for the same reason as the top-level helper.
    """
    schema = _response_schema(data, method, path)
    if schema is None:
        return None
    return _schema_field_paths(schema, data)


def _schema_field_paths(schema: Any, root: dict[str, Any]) -> set[str]:
    """Every field path a (possibly composed) object schema declares, recursively.

    An object property with no ``properties`` of its own contributes its own path
    and nothing beneath it — an opaque object's contents were never specified, so
    they are not declared. Bounded depth mirrors ``_merge_schema``.
    """
    found: set[str] = set()

    def walk(node: Any, prefix: str, depth: int) -> None:
        if depth > 8:
            return
        node = _follow_ref(node, root)
        if not isinstance(node, dict):
            return
        if node.get("type") == "array":
            walk(_follow_ref(node.get("items"), root), f"{prefix}[]", depth + 1)
            return
        props, _ = _merge_schema(node, root)
        for name, prop in props.items():
            where = f"{prefix}.{name}" if prefix else name
            found.add(where)
            walk(prop, where, depth + 1)

    walk(schema, "", 0)
    return found
