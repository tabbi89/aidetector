"""Read-only object-id seeding: real ids for path templates, before checks run.

A default scan never writes, so resource setup (``resource_bootstrap``) never
ran and every check rendered ``/accounts/{account_id}`` as ``/accounts/1``. On
a real API that is a 404, and everything downstream of it went blind without
saying so: the header sweep sampled an error envelope instead of the object, so
``data_exposure`` and ``potential_secrets`` never read an item body; a forged
token that got past auth still hit a missing object, so ``broken_auth`` saw a
4xx; injection baselines were not 2xx, so the point was marked blocked.

This pass reads the target's own collection endpoints — ``GET /accounts`` for
``account_id``, ``GET /projects/{project_id}/items`` for ``item_id`` once a
project id is known — and records the first object id each returns in
``ctx.resource_ids``, which checks render paths through
(``resource_map.path_values``). It never overwrites an id resource setup created
or the user supplied.

Bounded and read-only: GET only, through the scan's probe (so it is budgeted
and traced), at most ``SEED_MAX_READS`` requests. Ids are target data and are
substituted into a URL unencoded, so a value must look like an identifier and
nothing else; and no id is ever put into a note, an event or a finding.
"""
from __future__ import annotations

import json
import re
from typing import Any

from app.engine.base import ScanContext, TargetOperation, render_path
from app.engine.resource_map import path_param_key, resource_id_for, resource_key
from app.engine.spec_values import base_value

SEED_MAX_READS = 12
_MAX_ROUNDS = 3
_LIST_KEYS = ("items", "data", "results", "rows", "records", "list", "entries")
_SAFE_ID = re.compile(r"^[A-Za-z0-9._:~@+-]{1,64}$")
_NAME_NORM = re.compile(r"[^a-z0-9]")


def _needed_keys(ctx: ScanContext) -> list[str]:
    keys: list[str] = []
    for op in ctx.operations:
        for name in op.path_params:
            if resource_id_for(op.path, name, ctx.resource_ids) is not None:
                continue  # supplied or set up already, under its own key or the bare name
            key = path_param_key(op.path, name)
            if key and key not in keys:
                keys.append(key)
    return keys


def _last_static_segment(path: str) -> str | None:
    """The final segment of a collection path; None when it ends in ``{var}``."""
    parts = [p for p in path.rstrip("/").split("/") if p]
    if not parts or (parts[-1].startswith("{") and parts[-1].endswith("}")):
        return None
    return parts[-1]


def _readers(ctx: ScanContext, key: str) -> list[TargetOperation]:
    found = [
        op
        for op in ctx.operations
        if op.method.upper() == "GET"
        and (segment := _last_static_segment(op.path)) is not None
        and resource_key(segment) == key
    ]
    return sorted(found, key=lambda op: len(op.path_params))


def _records(body: Any) -> list[Any]:
    if isinstance(body, list):
        return body
    if not isinstance(body, dict):
        return []
    for name in _LIST_KEYS:
        if isinstance(body.get(name), list):
            return list(body[name])
    for value in body.values():
        if isinstance(value, list):
            return value
    return [body]


def _safe_id(value: Any) -> str | None:
    if isinstance(value, bool) or not isinstance(value, str | int):
        return None
    text = str(value).strip()
    if not _SAFE_ID.match(text) or ".." in text or text == ".":
        return None
    return text


def _first_id(text: str, key: str) -> str | None:
    """The first record's own id. Other ``*_id`` fields name another resource."""
    try:
        body = json.loads(text)
    except (ValueError, TypeError, RecursionError):
        return None
    preferred = ("id", "uuid", "guid", f"{key}id", f"{key}uuid", f"{key}guid")
    for record in _records(body):
        if not isinstance(record, dict):
            continue
        fields = {_NAME_NORM.sub("", str(k).lower()): v for k, v in record.items()}
        for name in preferred:
            if name in fields:
                return _safe_id(fields[name])
    return None


def seed_read_only_ids(ctx: ScanContext, *, max_reads: int = SEED_MAX_READS) -> list[str]:
    """Resolve path resources from collection reads; return notes (never ids)."""
    needed = _needed_keys(ctx)
    if not needed:
        return []
    headers = ctx.primary_headers()
    notes: list[str] = []
    reads = 0
    tried: set[str] = set()
    missing = [k for k in needed if k not in ctx.resource_ids]

    for _ in range(_MAX_ROUNDS):
        progress = False
        for key in list(missing):
            for reader in _readers(ctx, key):
                parents = {
                    name: resource_id_for(reader.path, name, ctx.resource_ids)
                    for name in reader.path_params
                }
                if any(v is None for v in parents.values()):
                    continue  # a later round may resolve the parent
                path = render_path(reader.path, parents)
                if path in tried:
                    continue
                if reads >= max_reads:
                    return [*notes, _summary(needed, missing, reads)]
                tried.add(path)
                params = {
                    p["name"]: base_value(p.get("schema") or {})
                    for p in reader.params
                    if p.get("in") == "query" and p.get("required") and p.get("name")
                } or None
                response = ctx.probe.send("GET", path, headers=headers, params=params)
                reads += 1
                if response is None:
                    return [*notes, _summary(needed, missing, reads)]
                if not 200 <= response.status < 300:
                    continue
                try:
                    oid = _first_id(response.text or "", key)
                except Exception:  # noqa: BLE001 — a malformed body never fails the seed
                    oid = None
                if oid is None:
                    continue
                ctx.resource_ids[key] = oid
                ctx.seeded_resource_keys.add(key)
                missing.remove(key)
                notes.append(f"seeded '{key}' id from GET {reader.path}")
                progress = True
                break
        if not progress or not missing:
            break
    return [*notes, _summary(needed, missing, reads)]


def _summary(needed: list[str], missing: list[str], reads: int) -> str:
    return (
        f"read-only id seeding: {len(needed) - len(missing)} of {len(needed)} "
        f"path resources resolved in {reads} request(s)"
    )
