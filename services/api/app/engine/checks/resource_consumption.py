"""Unbounded resource consumption (API4): a client-controlled page size.

Rate limiting is only half of API4. The other half is a single request that
forces an unbounded *response* — ``GET /records?limit=100000`` returning the
whole table, so one caller drives arbitrary serialisation and transfer cost.
``enumeration`` and ``advanced_rate_limit`` test request *rate*; this tests
response *volume*, which is orthogonal.

Spec-driven, so the signal is grounded in the API's own contract rather than
guessed: only a collection endpoint that *declares* a page-size query parameter
is probed. The oracle is a comparison, not a single big number — two probes at
two sizes both well past a normal page (1000, 5000). If the returned record
count **tracks** the requested size (grows across the two) and is large in
absolute terms, there is no effective cap. A server capped at, say, 100 returns
100 for both sizes: no growth, no finding. That comparison is exactly what
separates an unbounded list from a correctly capped one, so a hardened endpoint
stays quiet.

Read-only (GET only), so no ``mutate`` gate. Heuristic: response volume infers
consumption rather than measuring the server's real cost.
"""
from __future__ import annotations

import re
from typing import Any

from app.domain.enums import Confidence, Severity
from app.engine.base import EngineFinding, ProbeResult, ScanContext, render_path
from app.engine.resource_map import path_values
from app.engine.spec_values import base_value

#: A query parameter whose name means "how many records to return".
_SIZE_PARAM = re.compile(
    r"^(limit|per[_-]?page|page[_-]?size|pagesize|count|size|top|max"
    r"|max[_-]?results|rows|length|first|take)$",
    re.I,
)
#: Keys a paginated payload commonly wraps its list under, tried before the
#: fallback of "any top-level list value".
_LIST_KEYS = ("items", "data", "results", "rows", "records", "list", "entries")

#: Two request sizes, both past a normal page cap, so a capped server returns
#: the same count for both and only an uncapped one grows between them.
_SMALL = 1000
_LARGE = 5000
#: The large probe must return at least this many records to be worth flagging —
#: a growing-but-tiny list is not a consumption problem.
_MIN_LARGE = 500
#: ...and must have grown by at least this factor from the small probe, which is
#: what rules out an effective server cap.
_GROWTH = 1.5

_MAX_OPS = 3


def _record_count(result: ProbeResult) -> int | None:
    """Number of records in a JSON list/collection response, or None.

    Returns None when the body is not JSON or carries no list — the check needs
    a countable collection to compare, and refuses to guess from byte length
    (a large object is not the same weakness as a large list)."""
    try:
        import json

        body: Any = json.loads(result.text or "")
    except (ValueError, TypeError):
        return None
    if isinstance(body, list):
        return len(body)
    if isinstance(body, dict):
        for key in _LIST_KEYS:
            value = body.get(key)
            if isinstance(value, list):
                return len(value)
        for value in body.values():  # fallback: the first list-valued field
            if isinstance(value, list):
                return len(value)
    return None


class ResourceConsumptionCheck:
    key = "resource_consumption"

    def inapplicable(self, ctx: ScanContext) -> str | None:
        if not any(self._size_param(op) for op in self._collections(ctx)):
            return "no collection endpoint declares a page-size/limit parameter"
        return None

    def _collections(self, ctx: ScanContext) -> list[Any]:
        """GET endpoints that read a collection (path does not end in a param)."""
        return [
            op
            for op in ctx.operations
            if op.method.upper() == "GET" and not op.path.rstrip("/").endswith("}")
        ]

    def _size_param(self, op: Any) -> str | None:
        for p in op.params:
            if p.get("in") == "query" and _SIZE_PARAM.match(str(p.get("name", ""))):
                return str(p["name"])
        return None

    def run(self, ctx: ScanContext) -> list[EngineFinding]:
        headers = ctx.primary_headers()
        findings: list[EngineFinding] = []
        candidates: list[tuple[Any, str]] = []
        for op in self._collections(ctx):
            size_param = self._size_param(op)
            if size_param:
                candidates.append((op, size_param))

        for op, size_param in candidates[:_MAX_OPS]:
            url = render_path(op.path, path_values(op, ctx.resource_ids))
            base_params = {
                p["name"]: base_value(p.get("schema") or {})
                for p in op.params
                if p.get("in") == "query"
                and p.get("required")
                and p["name"] != size_param
            }

            small = ctx.probe.send(
                op.method, url, headers=headers, params={**base_params, size_param: _SMALL}
            )
            if small is None:
                break  # budget spent
            large = ctx.probe.send(
                op.method, url, headers=headers, params={**base_params, size_param: _LARGE}
            )
            if large is None:
                break
            if small.status >= 400 or large.status >= 400:
                continue

            n_small = _record_count(small)
            n_large = _record_count(large)
            if n_small is None or n_large is None:
                continue  # not a countable collection response
            if n_large < _MIN_LARGE:
                continue  # never large enough to matter
            if n_large < n_small * _GROWTH:
                continue  # count did not track the requested size: an effective cap

            findings.append(self._finding(op, size_param, n_small, n_large))
        return findings

    def _finding(
        self, op: Any, size_param: str, n_small: int, n_large: int
    ) -> EngineFinding:
        return EngineFinding(
            check=self.key,
            confidence=Confidence.heuristic,
            owasp_id="API4:2023",
            severity=Severity.medium,
            title=f"Unbounded page size on {op.method} {op.path} ('{size_param}')",
            description=(
                f"Requesting '{size_param}={_SMALL}' returned {n_small} records and "
                f"'{size_param}={_LARGE}' returned {n_large}: the response tracks the "
                "client-requested size with no effective server cap. One request "
                "can extract the whole collection and force unbounded serialisation "
                "and transfer cost — the response-volume half of unrestricted "
                "resource consumption, independent of any per-request rate limit."
            ),
            evidence={
                "method": op.method,
                "path": op.path,
                "param": size_param,
                "small_size": _SMALL,
                "small_count": n_small,
                "large_size": _LARGE,
                "large_count": n_large,
            },
            operation_id=op.id,
        )
