"""Bounded GraphQL field-suggestion and alternative-form authorization checks.

Premium and read-only. Mutation examples are never replayed because the scanner
cannot infer a safe cleanup from a GraphQL document. Alias/batch support alone
is not reported: a verified finding needs owner success plus anonymous and
attacker denial for the normal query, followed by attacker success with the
equivalent alternative form.
"""
from __future__ import annotations

import json
import re
import time
from dataclasses import dataclass
from typing import Any

from app.domain.enums import Confidence, Severity
from app.engine.base import EngineFinding, ProbeResult, ScanContext, TargetOperation, render_path
from app.engine.checks.graphql_introspection import _graphql_targets
from app.engine.resource_map import path_values
from app.specs.parser import spec_operation

MAX_TARGETS = 2
MAX_QUERY_BYTES = 512
MAX_QUERY_DEPTH = 4
MAX_SUGGESTION_REQUESTS = 3
MAX_ALIASES = 1
MAX_BATCH_SIZE = 2
MAX_ENDPOINT_SECONDS = 1.5

_SUGGESTION_QUERIES = ("{ usre }", "{ viwer }", "{ serach }")
_SUGGESTED_FIELD = re.compile(
    r"(?:Did you mean|suggestions?\s*:?)\s+(?:the field\s+)?[\"'`]?([_A-Za-z][_0-9A-Za-z]*)",
    re.IGNORECASE,
)
_ROOT_FIELD = re.compile(
    r"(\{\s*)([_A-Za-z][_0-9A-Za-z]*)(?=\s*(?:\(|\{|@|\}))"
)


@dataclass(frozen=True)
class _GraphqlResult:
    success: bool
    denied: bool
    value: Any = None


def _safe_query(query: str) -> bool:
    stripped = query.strip()
    if not stripped or len(stripped.encode("utf-8", "replace")) > MAX_QUERY_BYTES:
        return False
    if re.match(r"^(?:mutation|subscription)\b", stripped, re.IGNORECASE):
        return False
    if "fragment " in stripped.lower() or "$" in stripped:
        return False
    depth = 0
    maximum = 0
    for char in stripped:
        if char == "{":
            depth += 1
            maximum = max(maximum, depth)
        elif char == "}":
            depth -= 1
            if depth < 0:
                return False
    return depth == 0 and 0 < maximum <= MAX_QUERY_DEPTH


def _known_queries(
    spec: dict[str, Any] | None, op: TargetOperation, target_base_url: str | None = None
) -> list[str]:
    """Read at most one safe query example/default from the OpenAPI operation."""
    if not isinstance(spec, dict):
        return []
    raw = spec_operation(spec, op.method, op.path, target_base_url)
    if raw is None:
        return []
    candidates: list[Any] = []
    body = raw.get("requestBody")
    content = body.get("content") if isinstance(body, dict) else None
    if isinstance(content, dict):
        for media in content.values():
            if not isinstance(media, dict):
                continue
            candidates.append(media.get("example"))
            examples = media.get("examples")
            if isinstance(examples, dict):
                candidates.extend(
                    example.get("value") if isinstance(example, dict) else example
                    for example in examples.values()
                )
            schema = media.get("schema")
            properties = schema.get("properties") if isinstance(schema, dict) else None
            query = properties.get("query") if isinstance(properties, dict) else None
            if isinstance(query, dict):
                candidates.extend((query.get("example"), query.get("default")))
    for candidate in candidates:
        query = candidate.get("query") if isinstance(candidate, dict) else candidate
        if isinstance(query, str) and _safe_query(query):
            return [query]
    return []


def _alias_query(query: str) -> str | None:
    if MAX_ALIASES < 1:
        return None
    aliased, count = _ROOT_FIELD.subn(r"\1aidxAlias: \2", query, count=1)
    return aliased if count == 1 and len(aliased.encode()) <= MAX_QUERY_BYTES else None


def _parse_result(response: ProbeResult, *, alias: str | None = None) -> _GraphqlResult:
    if response.status in (401, 403):
        return _GraphqlResult(False, True)
    if response.status >= 400:
        return _GraphqlResult(False, False)
    try:
        payload = json.loads(response.text)
    except (TypeError, ValueError):
        return _GraphqlResult(False, False)
    if not isinstance(payload, dict):
        return _GraphqlResult(False, False)
    data = payload.get("data")
    errors = payload.get("errors")
    if isinstance(data, dict) and data:
        if alias and alias in data:
            return _GraphqlResult(True, False, data[alias])
        return _GraphqlResult(True, False, next(iter(data.values())))
    return _GraphqlResult(False, bool(errors) or data is None)


def _batch_result(response: ProbeResult) -> _GraphqlResult:
    if response.status in (401, 403):
        return _GraphqlResult(False, True)
    if response.status >= 400:
        return _GraphqlResult(False, False)
    try:
        payload = json.loads(response.text)
    except (TypeError, ValueError):
        return _GraphqlResult(False, False)
    if not isinstance(payload, list) or not payload or len(payload) > MAX_BATCH_SIZE:
        return _GraphqlResult(False, False)
    for item in payload:
        synthetic = ProbeResult(response.status, {}, json.dumps(item), response.elapsed_ms)
        parsed = _parse_result(synthetic)
        if parsed.success:
            return parsed
    return _GraphqlResult(False, True)


class GraphQLBehaviorCheck:
    key = "graphql_behavior"
    # Its findings need the scan's identities; a run that left one out could
    # not have re-found them, so the diff must not call them fixed.
    needs_identities = True
    premium = True

    def run(self, ctx: ScanContext) -> list[EngineFinding]:
        if not ctx.premium:
            return []
        findings: list[EngineFinding] = []
        for op in _graphql_targets(ctx)[:MAX_TARGETS]:
            started = time.monotonic()
            path = render_path(op.path, path_values(op, ctx.resource_ids))
            suggestion = self._field_suggestion(ctx, op, path, started)
            if suggestion is not None:
                findings.append(suggestion)
            if time.monotonic() - started > MAX_ENDPOINT_SECONDS:
                continue
            queries = _known_queries(ctx.spec, op, ctx.base_url)
            if queries:
                findings.extend(self._authorization(ctx, op, path, queries[0], started))
        return findings

    def _field_suggestion(
        self, ctx: ScanContext, op: TargetOperation, path: str, started: float
    ) -> EngineFinding | None:
        for query in _SUGGESTION_QUERIES[:MAX_SUGGESTION_REQUESTS]:
            if time.monotonic() - started > MAX_ENDPOINT_SECONDS:
                break
            response = ctx.probe.send("POST", path, headers={}, json={"query": query})
            if response is None or response.status >= 500:
                break
            suggestions = self._suggestions(response.text)
            if suggestions:
                return EngineFinding(
                    check=self.key,
                    confidence=Confidence.heuristic,
                    owasp_id="API8:2023",
                    severity=Severity.low,
                    title=f"GraphQL field suggestions exposed on POST {op.path}",
                    description=(
                        f"POST {op.path} suggested schema field names to an anonymous "
                        "invalid query. This is bounded schema-information exposure, "
                        "not an authorization bypass."
                    ),
                    evidence={
                        "method": "POST",
                        "route": op.path,
                        "issue": "field_suggestion",
                        "suggested_fields": suggestions,
                    },
                    operation_id=op.id,
                )
        return None

    @staticmethod
    def _suggestions(body: str) -> list[str]:
        try:
            payload = json.loads(body)
        except (TypeError, ValueError):
            return []
        errors = payload.get("errors") if isinstance(payload, dict) else None
        if not isinstance(errors, list):
            return []
        found: list[str] = []
        for error in errors[:4]:
            message = error.get("message") if isinstance(error, dict) else None
            if not isinstance(message, str):
                continue
            for match in _SUGGESTED_FIELD.finditer(message[:500]):
                field = match.group(1)[:64]
                if field not in found:
                    found.append(field)
        return found[:4]

    def _authorization(
        self,
        ctx: ScanContext,
        op: TargetOperation,
        path: str,
        query: str,
        started: float,
    ) -> list[EngineFinding]:
        pair = ctx.identity_pair()
        if pair is None:
            return []
        owner = ctx.probe.send(
            "POST", path, headers=pair.owner.headers(), json={"query": query}
        )
        anonymous = ctx.probe.send("POST", path, headers={}, json={"query": query})
        attacker = ctx.probe.send(
            "POST", path, headers=pair.attacker.headers(), json={"query": query}
        )
        if owner is None or anonymous is None or attacker is None:
            return []
        owner_result = _parse_result(owner)
        anonymous_result = _parse_result(anonymous)
        attacker_result = _parse_result(attacker)
        if (
            not owner_result.success
            or not anonymous_result.denied
            or not attacker_result.denied
            or time.monotonic() - started > MAX_ENDPOINT_SECONDS
        ):
            return []

        findings: list[EngineFinding] = []
        aliased = _alias_query(query)
        if aliased:
            response = ctx.probe.send(
                "POST", path, headers=pair.attacker.headers(), json={"query": aliased}
            )
            if response is None or response.status >= 500:
                return findings
            result = _parse_result(response, alias="aidxAlias")
            if result.success and result.value == owner_result.value:
                findings.append(self._auth_finding(op, "alias_auth_bypass", response.status))

        if time.monotonic() - started > MAX_ENDPOINT_SECONDS:
            return findings
        batch = [{"query": query} for _ in range(MAX_BATCH_SIZE)]
        response = ctx.probe.send("POST", path, headers=pair.attacker.headers(), json=batch)
        if response is None or response.status >= 500:
            return findings
        result = _batch_result(response)
        if result.success and result.value == owner_result.value:
            findings.append(self._auth_finding(op, "batch_auth_bypass", response.status))
        return findings

    def _auth_finding(
        self, op: TargetOperation, bypass_class: str, status: int
    ) -> EngineFinding:
        form = "alias" if bypass_class.startswith("alias") else "batch"
        return EngineFinding(
            check=self.key,
            confidence=Confidence.verified,
            owasp_id="API2:2023",
            severity=Severity.high,
            title=f"GraphQL {form} authorization bypass on POST {op.path}",
            description=(
                f"POST {op.path} denied the same normal query to anonymous and "
                f"low-privilege callers while the owner succeeded, but the "
                f"low-privilege {form} form returned equivalent data. This is an "
                "authorization bypass, not merely alternative-form support."
            ),
            evidence={
                "method": "POST",
                "route": op.path,
                "issue": bypass_class,
                "bypass_class": bypass_class,
                "owner_control": "success",
                "anonymous_control": "denied",
                "attacker_control": "denied",
                "alternative_status": status,
            },
            operation_id=op.id,
        )
