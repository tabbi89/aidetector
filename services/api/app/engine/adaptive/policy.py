"""Pure endpoint selection, valid controls and bounded payload revisions."""
from __future__ import annotations

import math
import re
from dataclasses import dataclass
from dataclasses import field as dc_field
from typing import Any
from urllib.parse import quote

from app.domain.privilege import is_privileged
from app.engine.adaptive.contracts import TestTrace
from app.engine.base import TargetOperation, render_path
from app.engine.spec_values import base_value

_NAMES = re.compile(r"^[A-Za-z_][A-Za-z0-9_]{0,63}$")
_ROUTE = re.compile(r"^/[A-Za-z0-9_./{}-]*$")
_MISSING = object()
_MUTATING = frozenset({"POST", "PUT", "PATCH"})


def valid(schema: dict, value: Any) -> bool:
    if schema.get("adaptive_unsupported"):
        return False
    kind = schema.get("type", "string")
    if kind == "string":
        if not isinstance(value, str) or len(value) > 512:
            return False
        if not schema.get("minLength", 0) <= len(value) <= schema.get("maxLength", 512):
            return False
    elif kind in {"integer", "number"}:
        if (
            isinstance(value, bool)
            or not isinstance(value, int | float)
            or not math.isfinite(value)
        ):
            return False
        if kind == "integer" and not isinstance(value, int):
            return False
        if value < schema.get("minimum", -1e9) or value > schema.get("maximum", 1e9):
            return False
        if isinstance(schema.get("exclusiveMinimum"), bool) and schema["exclusiveMinimum"]:
            if value <= schema.get("minimum", -1e9):
                return False
        if isinstance(schema.get("exclusiveMaximum"), bool) and schema["exclusiveMaximum"]:
            if value >= schema.get("maximum", 1e9):
                return False
    elif kind == "boolean":
        if not isinstance(value, bool):
            return False
    else:
        return False
    return not schema.get("enum") or value in schema["enum"]


def baseline(schema: dict) -> Any:
    if schema.get("enum"):
        value = schema["enum"][0]
    elif schema.get("type") in {"integer", "number"}:
        value = max(1, schema.get("minimum", 1))
        if schema.get("exclusiveMinimum") is True:
            value += 1
        if "maximum" in schema:
            value = min(value, schema["maximum"] - (schema.get("exclusiveMaximum") is True))
    elif schema.get("type") == "boolean":
        value = True
    else:
        value = base_value(schema) if schema.get("format") else "aidx"
        if not schema.get("format"):
            value = (value + "x" * min(256, schema.get("minLength", 0)))[
                : schema.get("maxLength", 256)
            ]
    if not valid(schema, value):
        raise ValueError("unsupported baseline")
    return value


@dataclass
class Candidate:
    op: TargetOperation
    field: str
    location: str
    rule: str
    schema: dict
    bases: dict[str, dict] = dc_field(default_factory=dict)
    pair: Any = None
    delete: TargetOperation | None = None
    priority: int = 0

    def trace(self) -> TestTrace:
        return TestTrace(operation_id=self.op.id, method=self.op.method, route=self.op.path,
                         field=self.field, location=self.location, rule=self.rule,
                         priority=self.priority, rationale=(
                             "Server-owned field with read-back control"
                             if self.rule == "server_owned"
                             else "Declared constraint on an authenticated or sensitive endpoint"
                         ))

    def payload(self, variant: str, seed: int) -> Any:
        n = {"v1": 1, "v2": 2, "v3": 3}[variant]
        marker = f"aidx{seed:x}v{n}"
        if self.rule == "server_owned":
            return marker + ("_probe" * (n - 1))
        if self.rule == "max_length":
            length = self.schema["maxLength"] + n
            return (marker + "x" * length)[:length]
        if self.rule == "minimum":
            return self.schema["minimum"] - n
        if self.rule == "maximum":
            return self.schema["maximum"] + n
        if self.rule == "enum":
            return marker
        if self.rule == "type":
            return marker
        if self.rule == "required":
            return _MISSING
        raise ValueError("unsupported rule")

    def request(
        self, value: Any = _MISSING, *, control: bool = False
    ) -> tuple[str, dict, dict | None]:
        values = {loc: dict(params) for loc, params in self.bases.items()}
        if not control:
            if value is _MISSING:
                values[self.location].pop(self.field, None)
            else:
                values[self.location][self.field] = value
        # Parameters cannot turn a route segment into a URL, traversal or query.
        path = render_path(self.op.path, {k: quote(str(v), safe="")
                                        for k, v in values["path"].items()})
        return path, values["query"], values["body"] or None


def _rules(schema: dict, *, required: bool) -> list[tuple[int, str]]:
    """Return the supported, value-free constraint probes for one scalar field."""
    rules: list[tuple[int, str]] = []
    if isinstance(schema.get("maxLength"), int) and 0 <= schema["maxLength"] <= 256:
        rules.append((70, "max_length"))
    if schema.get("enum") and schema.get("type", "string") == "string":
        rules.append((65, "enum"))
    for rule, bound in (("minimum", "minimum"), ("maximum", "maximum")):
        if isinstance(schema.get(bound), int | float) and not isinstance(schema[bound], bool):
            if abs(schema[bound]) < 1e6:
                rules.append((60, rule))
    if schema.get("type") in {"integer", "number"}:
        rules.append((50, "type"))
    if required:
        rules.append((40, "required"))
    return rules


def select_tests(operations: list[TargetOperation], *, mutate: bool, spec: dict | None,
                 limit: int) -> tuple[list[Candidate], list[TestTrace]]:
    candidates, skipped = [], []
    for op in operations:
        trace = TestTrace(operation_id=op.id, method=op.method, route=op.path)
        try:
            if not _ROUTE.fullmatch(op.path) or ".." in op.path or op.path.startswith("//"):
                raise ValueError("unsafe_route")
            # GET query/path validation is read-only. JSON body validation is a
            # separate, explicit mutation-gated branch because even a valid
            # control can create or update target state.
            if op.method != "GET" and op.method not in _MUTATING:
                raise ValueError("unsupported_method")
            if op.method in _MUTATING and not mutate:
                raise ValueError("mutation_disabled")
            pair = None
            delete = None
            bases: dict[str, dict] = {"query": {}, "path": {}, "body": {}}
            choices: list[tuple[int, str, str, str, dict]] = []
            for p in op.params:
                name, loc, schema = p.get("name", ""), p.get("in"), p.get("schema") or {}
                if not _NAMES.fullmatch(name) or loc not in bases:
                    if p.get("required"):
                        raise ValueError("unsupported_required_parameter")
                    continue
                if loc == "body" and not (op.method in _MUTATING and mutate):
                    if p.get("required"):
                        raise ValueError("unsupported_required_parameter")
                    continue
                if p.get("required") or loc == "path":
                    bases[loc][name] = baseline(schema)
                if loc not in {"query", "body"} or schema.get("adaptive_unsupported"):
                    continue
                for score, rule in _rules(schema, required=bool(p.get("required"))):
                    baseline(schema)
                    choices.append((score, name, loc, rule, schema))
            if not choices:
                raise ValueError("no_supported_constraint")
            score, name, loc, rule, schema = max(choices, key=lambda c: c[0])
            if rule != "server_owned":
                bases[loc][name] = baseline(schema)
            score += 20 * bool(op.auth_scope) + 30 * is_privileged(op.path, op.auth_scope)
            candidates.append(Candidate(op, name, loc, rule, schema, bases, pair, delete, score))
        except (ValueError, TypeError, OverflowError):
            trace.stop_reason = "unsupported_or_unsafe"
            if op.method in _MUTATING and not mutate:
                trace.stop_reason = "mutation_disabled"
            skipped.append(trace)
    candidates.sort(key=lambda c: -c.priority)
    for candidate in candidates[limit:]:
        trace = candidate.trace()
        trace.stop_reason = "endpoint_limit"
        skipped.append(trace)
    return candidates[:limit], skipped
