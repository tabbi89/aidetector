"""Turn a HAR capture or a Postman collection into an OpenAPI dict.

No OpenAPI spec means no scan — which shuts out a lot of in-house APIs that were
never documented but *were* exercised. Both a browser/proxy HAR export and a
Postman collection are records of real requests; this converts either into the
same minimal OpenAPI 3 document the parser already understands, so the whole
engine works on an undocumented API without a single check knowing the source.

The conversion is deliberately lossy in one direction and lossless in another:

- **Paths are templated.** A recorded URL is concrete (`/users/1837`); the
  segments that look like ids (numeric, UUID, long hex) become ``{id}`` so
  many captures of one endpoint collapse to one operation and the path-param
  fuzzers have something to vary.
- **Request bodies and query params are kept as shape, not value.** Field names
  and inferred types become the request schema; the values are dropped.
- **Response bodies become a response schema.** A HAR carries the responses, so
  the imported spec can declare what each endpoint returned — which is exactly
  what ``data_exposure`` diffs against for spec drift. Values are never kept.

Everything here is pure: text in, a dict out. Malformed input raises
``SpecError`` with a reason, the same failure the OpenAPI path uses.
"""
from __future__ import annotations

import json
import re
from typing import Any
from urllib.parse import urlsplit

import yaml

from app.specs.parser import SpecError, load_spec

_HTTP_METHODS = {"get", "put", "post", "delete", "patch", "head", "options", "trace"}
_UUID = re.compile(r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$")
_LONG_HEX = re.compile(r"^[0-9a-fA-F]{12,}$")


# ---- format sniffing -----------------------------------------------------------

def looks_like_har(obj: Any) -> bool:
    return (
        isinstance(obj, dict)
        and isinstance(obj.get("log"), dict)
        and isinstance(obj["log"].get("entries"), list)
    )


def looks_like_postman(obj: Any) -> bool:
    return (
        isinstance(obj, dict)
        and isinstance(obj.get("item"), list)
        and isinstance(obj.get("info"), dict)
    )


# ---- shared helpers ------------------------------------------------------------

def _is_id_segment(seg: str) -> bool:
    """A path segment that names a specific object, not a resource kind."""
    if not seg:
        return False
    if seg.isdigit():
        return True
    if _UUID.match(seg) or _LONG_HEX.match(seg):
        return True
    # A version marker (v2, v2024) is a resource kind, not an object id.
    if re.match(r"^v\d+$", seg):
        return False
    # A segment mixing letters and several digits (order-1837).
    return bool(re.search(r"\d{3,}", seg))


def _templatize(path: str) -> str:
    """Concrete path → templated: id-looking segments become ``{id}``/``{idN}``.

    Named uniquely (``{id}``, ``{id2}``, …) so a path with two ids stays valid.
    """
    out: list[str] = []
    n = 0
    for seg in path.split("/"):
        if _is_id_segment(seg):
            n += 1
            out.append("{id}" if n == 1 else f"{{id{n}}}")
        else:
            out.append(seg)
    return "/".join(out) or "/"


def _json_type(value: Any) -> str:
    if isinstance(value, bool):
        return "boolean"
    if isinstance(value, int):
        return "integer"
    if isinstance(value, float):
        return "number"
    if isinstance(value, list):
        return "array"
    if isinstance(value, dict):
        return "object"
    return "string"


def _object_schema(obj: dict[str, Any]) -> dict[str, Any]:
    """A flat OpenAPI object schema from a JSON object's top-level keys."""
    return {
        "type": "object",
        "properties": {
            str(k): {"type": _json_type(v)} for k, v in obj.items() if isinstance(k, str)
        },
    }


def _response_schema(text: str | None) -> dict[str, Any] | None:
    """Infer a response schema from a JSON response body (object or array)."""
    if not text:
        return None
    try:
        data = json.loads(text)
    except (ValueError, TypeError):
        return None
    if isinstance(data, dict):
        return _object_schema(data)
    if isinstance(data, list) and data and isinstance(data[0], dict):
        return {"type": "array", "items": _object_schema(data[0])}
    return None


class _Builder:
    """Accumulates operations into an OpenAPI ``paths`` object, merging dupes."""

    def __init__(self) -> None:
        self._paths: dict[str, dict[str, Any]] = {}

    def add(
        self,
        method: str,
        path: str,
        *,
        query: list[str] | None = None,
        body: dict[str, Any] | None = None,
        response: dict[str, Any] | None = None,
        status: str = "200",
    ) -> None:
        method = method.lower()
        if method not in _HTTP_METHODS or not path:
            return
        templated = _templatize(path)
        op = self._paths.setdefault(templated, {}).setdefault(method, {})

        # Merge query params by name.
        params = {p["name"]: p for p in op.get("parameters", []) if isinstance(p, dict)}
        for name in query or []:
            params.setdefault(name, {"name": name, "in": "query", "required": False})
        if params:
            op["parameters"] = list(params.values())

        # Merge request-body properties (first body wins per field).
        if body:
            existing = (
                op.setdefault("requestBody", {})
                .setdefault("content", {})
                .setdefault("application/json", {})
                .setdefault("schema", {"type": "object", "properties": {}})
            )
            existing.setdefault("type", "object")
            existing.setdefault("properties", {})
            for k, v in body.get("properties", {}).items():
                existing["properties"].setdefault(k, v)

        # Keep the first response schema seen for the operation.
        if response and "responses" not in op:
            op["responses"] = {status: {"content": {"application/json": {"schema": response}}}}

    def document(self, title: str) -> dict[str, Any]:
        if not self._paths:
            raise SpecError("no requests found to import")
        return {
            "openapi": "3.0.0",
            "info": {"title": title, "version": "1.0.0"},
            "paths": self._paths,
        }


# ---- HAR -----------------------------------------------------------------------

def har_to_openapi(obj: dict[str, Any]) -> dict[str, Any]:
    entries = obj.get("log", {}).get("entries", [])
    if not isinstance(entries, list):
        raise SpecError("HAR log.entries is not a list")
    b = _Builder()
    for entry in entries:
        if not isinstance(entry, dict):
            continue
        req = entry.get("request")
        if not isinstance(req, dict):
            continue
        method = str(req.get("method") or "")
        url = str(req.get("url") or "")
        if not method or not url:
            continue
        path = urlsplit(url).path or "/"
        query = [
            str(q.get("name"))
            for q in (req.get("queryString") or [])
            if isinstance(q, dict) and q.get("name")
        ]
        body = _har_body(req.get("postData"))
        resp = entry.get("response") if isinstance(entry.get("response"), dict) else {}
        content = resp.get("content") if isinstance(resp, dict) else {}
        raw_status = str(resp.get("status") or "200") if isinstance(resp, dict) else "200"
        # Only a 2xx body describes the success shape; an error body is not the
        # declared 200 response and would poison data_exposure drift on imports.
        response = None
        if raw_status.startswith("2"):
            response = _response_schema(
                content.get("text") if isinstance(content, dict) else None
            )
        b.add(
            method, path, query=query, body=body, response=response,
            status=raw_status if raw_status.startswith("2") else "200",
        )
    return b.document("Imported from HAR")


def _har_body(post_data: Any) -> dict[str, Any] | None:
    if not isinstance(post_data, dict):
        return None
    mime = str(post_data.get("mimeType") or "").lower()
    text = post_data.get("text")
    if "json" in mime and isinstance(text, str):
        try:
            parsed = json.loads(text)
        except (ValueError, TypeError):
            return None
        return _object_schema(parsed) if isinstance(parsed, dict) else None
    # urlencoded / form params carry a params list of {name,value}.
    params = post_data.get("params")
    if isinstance(params, list):
        names = {str(p.get("name")): {"type": "string"} for p in params
                 if isinstance(p, dict) and p.get("name")}
        if names:
            return {"type": "object", "properties": names}
    return None


# ---- Postman -------------------------------------------------------------------

def postman_to_openapi(obj: dict[str, Any]) -> dict[str, Any]:
    b = _Builder()
    _postman_walk(obj.get("item", []), b)
    return b.document("Imported from Postman")


def _postman_walk(items: Any, b: _Builder) -> None:
    if not isinstance(items, list):
        return
    for item in items:
        if not isinstance(item, dict):
            continue
        if isinstance(item.get("item"), list):  # a folder
            _postman_walk(item["item"], b)
            continue
        req = item.get("request")
        if isinstance(req, dict):
            _postman_add(req, b)


def _postman_add(req: dict[str, Any], b: _Builder) -> None:
    method = str(req.get("method") or "")
    url = req.get("url")
    path, query = _postman_url(url)
    if not method or not path:
        return
    body = _postman_body(req.get("body"))
    b.add(method, path, query=query, body=body)


def _postman_url(url: Any) -> tuple[str, list[str]]:
    """A Postman url (string or object) → (path, query names)."""
    if isinstance(url, str):
        return urlsplit(url).path or "/", []
    if not isinstance(url, dict):
        return "", []
    segments = url.get("path")
    if isinstance(segments, list):
        parts = [str(s).lstrip("/") for s in segments if s is not None]
        # Postman path variables are ``:var``; normalise to ``{var}``.
        path = "/" + "/".join(re.sub(r"^:(.+)$", r"{\1}", p) for p in parts)
    else:
        raw = str(url.get("raw") or "")
        path = urlsplit(raw).path or "/"
    query = [
        str(q.get("key"))
        for q in (url.get("query") or [])
        if isinstance(q, dict) and q.get("key")
    ]
    return path, query


def _postman_body(body: Any) -> dict[str, Any] | None:
    if not isinstance(body, dict):
        return None
    mode = body.get("mode")
    if mode == "raw" and isinstance(body.get("raw"), str):
        try:
            parsed = json.loads(body["raw"])
        except (ValueError, TypeError):
            return None
        return _object_schema(parsed) if isinstance(parsed, dict) else None
    if mode in ("urlencoded", "formdata"):
        rows = body.get(mode)
        if isinstance(rows, list):
            names = {str(r.get("key")): {"type": "string"} for r in rows
                     if isinstance(r, dict) and r.get("key")}
            if names:
                return {"type": "object", "properties": names}
    return None


# ---- one entry point: OpenAPI, HAR, or Postman ---------------------------------


def load_source(text: str) -> tuple[dict[str, Any], str]:
    """Parse an uploaded spec/capture into (OpenAPI dict, text to persist).

    HAR and Postman are converted to a synthesised OpenAPI document, and *that*
    JSON is what gets stored as ``spec_text`` — so everything downstream
    (``declared_response_fields``, the coverage/report views, a re-parse) sees
    OpenAPI regardless of what was uploaded. A real OpenAPI/Swagger doc is passed
    through ``load_spec`` unchanged, preserving the user's original text.
    """
    stripped = text.strip()
    if not stripped:
        raise SpecError("spec is empty")
    try:
        obj: Any = json.loads(stripped)
    except json.JSONDecodeError:
        try:
            obj = yaml.safe_load(stripped)
        except yaml.YAMLError as exc:
            raise SpecError(f"not valid JSON or YAML: {exc}") from exc
    if looks_like_har(obj):
        doc = har_to_openapi(obj)
        return doc, json.dumps(doc, indent=2)
    if looks_like_postman(obj):
        doc = postman_to_openapi(obj)
        return doc, json.dumps(doc, indent=2)
    return load_spec(text), text
