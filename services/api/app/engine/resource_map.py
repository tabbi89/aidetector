"""Pair mutating operations with a GET that reads the same resource back.

The write oracle needs to prove a mutation *persisted*, which means reading the
resource back after writing it. That requires knowing, for a write, which GET
returns the same object. We infer that from the spec's path shapes:

- **item update**: ``PUT``/``PATCH /x/{id}`` ↔ ``GET /x/{id}`` (identical path
  template). The read-back id is the same one we wrote.
- **create**: ``POST /x`` (collection) ↔ ``GET /x/{id}`` (item). The read-back id
  comes from the create response (``Location`` header or a JSON id field), so the
  pair only records the item-read template; the id is resolved at run time.

DELETE is intentionally not paired here — it is destructive and not restorable,
so the write oracle stays on create/update.

The small pure helpers for *building* such a write — spec-valid path values, a
request body with one field set — live here too, because both write-side checks
(``write_oracle`` and ``mass_assignment``) need exactly the same ones.
"""
from __future__ import annotations

import json
import re
from dataclasses import dataclass
from typing import Any

from app.engine.base import TargetOperation
from app.engine.spec_values import base_value

_MUTATING = ("PUT", "PATCH")


@dataclass(frozen=True)
class ResourcePair:
    write: TargetOperation
    read: TargetOperation
    kind: str  # "update" | "create"


def collection_of(item_path: str) -> str | None:
    """`/x/{id}` -> `/x`; None if the path does not end in a single `{var}`."""
    if not item_path.endswith("}"):
        return None
    head, _, tail = item_path.rpartition("/")
    if not (tail.startswith("{") and tail.endswith("}")):
        return None
    return head or "/"


def build_resource_pairs(operations: list[TargetOperation]) -> list[ResourcePair]:
    """Infer (write, read) pairs from an operation set. Best-effort, spec-driven."""
    gets = {op.path: op for op in operations if op.method == "GET"}
    pairs: list[ResourcePair] = []

    for op in operations:
        if op.method in _MUTATING:
            # item update: a GET on the exact same path reads the object back.
            read = gets.get(op.path)
            if read is not None and read.path_params:
                pairs.append(ResourcePair(write=op, read=read, kind="update"))
        elif op.method == "POST":
            # create: the item GET is the collection path + one path segment.
            item = next(
                (
                    g
                    for g in gets.values()
                    if collection_of(g.path) == op.path and len(g.path_params) == 1
                ),
                None,
            )
            if item is not None:
                pairs.append(ResourcePair(write=op, read=item, kind="create"))

    return pairs


# ---- building a write ---------------------------------------------------------


def schema_of(op: TargetOperation, name: str) -> dict[str, Any]:
    """The declared schema facts for one of an operation's parameters."""
    for p in op.params:
        if p.get("name") == name:
            return p.get("schema") or {}
    return {}


def resource_key(name: str) -> str:
    """Normalize ``merchantId`` / ``merchant_id`` / ``merchants`` to a map key."""
    value = re.sub(r"[^a-z0-9]", "", name.lower())
    for suffix in ("uuid", "guid", "id"):
        if value.endswith(suffix) and len(value) > len(suffix):
            value = value[: -len(suffix)]
            break
    return value.rstrip("s")


#: Path parameter names that say "an id" without saying of what.
_BARE_ID_KEYS = frozenset({"id", "uuid", "guid"})


def param_resource_name(path: str, name: str) -> str:
    """The name that identifies which resource path parameter ``name`` holds.

    A named parameter names itself (``{monitor_id}``). A bare ``{id}`` /
    ``{uuid}`` / ``{guid}`` does not, so it takes the static segment right
    before it: ``/monitors/{id}`` holds a monitor, ``/incidents/{id}/ack`` an
    incident. Without that every bare-id route shared one key, a seeded monitor
    id was rendered into ``/incidents/{id}``, and no collection ever matched.
    Callers normalise the result with their own key function.
    """
    if re.sub(r"[^a-z0-9]", "", name.lower()) not in _BARE_ID_KEYS:
        return name
    parts = [p for p in path.split("/") if p]
    token = "{" + name + "}"
    for index, part in enumerate(parts):
        if part != token:
            continue
        previous = parts[index - 1] if index else ""
        if previous and not previous.startswith("{") and resource_key(previous):
            return previous
        break
    return name


def path_param_key(path: str, name: str) -> str:
    """The ``ctx.resource_ids`` key for path parameter ``name`` of template ``path``."""
    return resource_key(param_resource_name(path, name))


def resource_id_for(path: str, name: str, resource_ids: dict[str, str]) -> str | None:
    """The known id for one path parameter, or None.

    The bare-name lookup is a fallback for ids keyed on the parameter itself —
    a user-supplied ``{"id": "..."}`` predates per-resource bare-id keys.
    """
    found = resource_ids.get(path_param_key(path, name))
    return found if found is not None else resource_ids.get(resource_key(name))


def path_values(
    op: TargetOperation, resource_ids: dict[str, str] | None = None
) -> dict[str, str]:
    """Spec-valid baseline values for every path parameter of an operation."""
    supplied = resource_ids or {}
    values: dict[str, str] = {}
    for name in op.path_params:
        found = resource_id_for(op.path, name, supplied)
        values[name] = found if found is not None else base_value(schema_of(op, name))
    return values


def build_body(op: TargetOperation, field_name: str, value: Any) -> dict[str, Any]:
    """Required body params filled with spec-valid baselines, ``field_name`` set.

    ``field_name`` need not be declared: the mass-assignment check deliberately
    sends a field the request schema does *not* mention, which is the whole
    point of that probe.
    """
    body: dict[str, Any] = {}
    for p in op.params:
        if p.get("in") == "body" and p.get("name") and p.get("required"):
            body[p["name"]] = base_value(p.get("schema") or {})
    body[field_name] = value
    return body


def json_object(text: str) -> dict[str, Any] | None:
    """A response body as a JSON object, or None when it is not one."""
    try:
        data = json.loads(text)
    except (ValueError, TypeError, RecursionError):
        return None
    return data if isinstance(data, dict) else None


# JSON keys a create response commonly uses to name the new object's id.
_ID_KEYS = ("id", "sid", "uuid", "_id")


def mutable_body_field(op: TargetOperation) -> dict[str, Any] | None:
    """A body field a string canary can be written into (string / untyped, no enum).

    Shared by every write-side check: the write oracle carries the canary as a
    cross-identity marker, mass assignment as the client-writable proof, and the
    seeded-BOLA check as the object marker it reads back as another identity.
    """
    fields = [p for p in op.params if p.get("in") == "body" and p.get("name")]
    for p in fields:
        schema = p.get("schema") or {}
        if not schema.get("enum") and schema.get("type") in (None, "string"):
            return p
    return fields[0] if fields else None


def created_id(headers: dict[str, str], text: str, read_op: TargetOperation) -> str | None:
    """Resolve the new object's id from a create response (Location or JSON)."""
    loc = headers.get("location")
    if loc:
        seg = loc.rstrip("/").rsplit("/", 1)[-1]
        if seg:
            return seg
    data = json_object(text)
    if data is None:
        return None
    for key in (*read_op.path_params, *_ID_KEYS):
        val = data.get(key)
        if isinstance(val, str | int):
            return str(val)
    return None
