"""Bounded schema-driven request generation and response-contract validation.

Schemathesis generates both positive and negative cases from the uploaded
OpenAPI document. Cases are sent exactly once through :class:`HttpProbe`, so
they share the scan's request ceiling, rate limiting and coverage accounting.
The collected response is then checked in memory for documented status,
content type, required/typed headers and response-body schema conformance.

The evidence model is deliberately split: a 5xx directly demonstrates
unhandled input, while response-contract mismatches are heuristic drift
findings because the service or the uploaded document may be stale.

No response body, response header value or generated request value is retained.
Finding identity is method + route + rule + structural response location.

Opt-in and bounded: this check no-ops unless ``ctx.fuzz_cases > 0``. GET is
eligible by default; POST/PUT/PATCH remain behind ``allow_mutation``. Generator
or validation failures are isolated to the affected operation/mode.
"""
from __future__ import annotations

import json
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

from app.domain.enums import Confidence, Severity
from app.engine.base import EngineFinding, ScanContext
from app.specs.parser import SpecError, join_route, route_prefixes

_MUTATING = ("POST", "PUT", "PATCH")


@dataclass(frozen=True)
class _Candidate:
    operation: Any
    method: str
    operation_id: str | None
    # The runtime route the parser stored for this operation: the spec key with
    # its server/basePath prefix joined on. ``operation.path`` is the bare key.
    route: str = ""
    # The declared server/basePath, normalised as ``join_route`` normalises it,
    # and how many leading characters of ``prefix + spec key`` it dropped
    # because the target base URL already carries them.
    prefix: str = ""
    cut: int = 0

    def runtime_path(self, concrete: str) -> str:
        """``concrete`` (the key with values filled in) at the runtime route."""
        return (self.prefix + concrete)[self.cut:] or "/"


def _candidate(
    operation: Any,
    method: str,
    prefixes: dict[tuple[str, str], str],
    target_base_url: str,
    id_by_key: dict[tuple[str, str], str | None],
) -> _Candidate:
    """Place a Schemathesis operation on the route ``parse_operations`` stored.

    Schemathesis yields the bare ``paths`` key (``/monitors``) and leaves the
    server/basePath to its own HTTP client, which this check does not use. The
    rest of the engine sends to the parsed route (``/api/v1/monitors``), so the
    prefix is joined here exactly as the parser joined it.
    """
    key = operation.path
    prefix = (prefixes.get((method, key)) or "").strip().rstrip("/")
    try:
        route = join_route(prefix, key, target_base_url)
    except SpecError:  # the parser refuses this spec too; fall back to the key
        prefix, route = "", key
    cut = max(0, len(prefix) + len(key) - len(route))
    return _Candidate(operation, method, id_by_key.get((method, route)), route, prefix, cut)


@dataclass(frozen=True)
class _Violation:
    rule: str
    location: str
    status: int | None = None


def _case_allocation(operation_count: int, total: int) -> list[tuple[int, int]]:
    """Return exact ``(positive, negative)`` allowances in fair operation order.

    One allowance reaches every eligible operation before any operation gets a
    second. Modes alternate across an operation round and flip on the next
    round, so both modes receive cases without letting either one monopolise a
    small global allowance. The sum never exceeds ``total``.
    """
    if operation_count <= 0 or total <= 0:
        return []
    allocation = [[0, 0] for _ in range(operation_count)]
    for index in range(total):
        round_number, operation_index = divmod(index, operation_count)
        mode_index = (round_number + operation_index) % 2
        allocation[operation_index][mode_index] += 1
    return [(positive, negative) for positive, negative in allocation]


def _is_json_media_type(media_type: Any) -> bool:
    value = str(media_type or "").split(";", 1)[0].strip().lower()
    return value == "application/json" or value.endswith("+json")


def _failure_leaves(exc: BaseException) -> list[BaseException]:
    children = getattr(exc, "exceptions", None)
    if not isinstance(children, tuple | list):
        return [exc]
    leaves: list[BaseException] = []
    for child in children:
        if isinstance(child, BaseException):
            leaves.extend(_failure_leaves(child))
    return leaves or [exc]


def _structural_path(prefix: str, path: Any) -> str:
    """Bound and normalise a validator path without copying response values."""
    if not isinstance(path, list | tuple):
        return prefix
    parts = [prefix]
    for raw in path[:12]:
        if isinstance(raw, int):
            part = "[]"
        else:
            # A schema/property name is useful structural context, but it must
            # not become an unbounded diagnostic channel.
            part = str(raw).replace("~", "~0").replace("/", "~1")[:64]
        if part:
            parts.append(part)
    return "/".join(parts)


def _locations(rule: str, exc: BaseException) -> list[str]:
    locations: list[str] = []
    for failure in _failure_leaves(exc):
        if rule == "headers":
            missing = getattr(failure, "missing_headers", None)
            if isinstance(missing, list):
                locations.extend(
                    f"response.headers/{str(name).lower()[:64]}" for name in missing
                )
                continue
            locations.append("response.headers")
        elif rule == "schema":
            locations.append(
                _structural_path("response.body", getattr(failure, "instance_path", None))
            )
        elif rule == "content_type":
            locations.append("response.headers/content-type")
        else:
            locations.append("response.status")
    return locations or ["response"]


class SchemaFuzzCheck:
    key = "schema_fuzz"

    @staticmethod
    def inapplicable(ctx: ScanContext) -> str | None:
        if ctx.fuzz_cases <= 0:
            return "schema fuzzing is off (run at the Standard level, or pass --fuzz)"
        if ctx.spec is None:
            return "no parsed spec to generate cases from"
        return None
    serial_when_mutating = True

    def run(self, ctx: ScanContext) -> list[EngineFinding]:
        if ctx.spec is None or ctx.fuzz_cases <= 0:
            return []
        try:
            import schemathesis
            from hypothesis import HealthCheck, given, settings
            from schemathesis.core import NOT_SET
            from schemathesis.core.failures import FailureGroup
            from schemathesis.generation import GenerationMode
            from schemathesis.specs.openapi.checks import (
                content_type_conformance,
                response_headers_conformance,
                response_schema_conformance,
                status_code_conformance,
            )
        except Exception:  # noqa: BLE001 - optional dependency; degrade cleanly
            return []
        try:
            schema = schemathesis.openapi.from_dict(ctx.spec)
        except Exception:  # noqa: BLE001 - an unparseable spec skips fuzzing
            return []

        candidates = self._eligible_operations(schema, ctx)
        allocations = _case_allocation(len(candidates), ctx.fuzz_cases)
        validators = (
            ("status", status_code_conformance),
            ("content_type", content_type_conformance),
            ("headers", response_headers_conformance),
            ("schema", response_schema_conformance),
        )
        headers = ctx.primary_headers()
        findings: list[EngineFinding] = []
        for candidate, (positive, negative) in zip(candidates, allocations, strict=True):
            violations: dict[tuple[str, str], _Violation] = {}
            for mode, allowance in (
                (GenerationMode.POSITIVE, positive),
                (GenerationMode.NEGATIVE, negative),
            ):
                if allowance <= 0:
                    continue
                self._generate(
                    ctx,
                    candidate,
                    allowance,
                    mode,
                    headers,
                    validators,
                    NOT_SET,
                    (AssertionError, FailureGroup),
                    violations,
                    given,
                    settings,
                    HealthCheck,
                )
            findings.extend(self._findings(candidate, violations.values()))
        return findings

    @staticmethod
    def _eligible_operations(schema: Any, ctx: ScanContext) -> list[_Candidate]:
        id_by_key = {(op.method.upper(), op.path): op.id for op in ctx.operations}
        order = {key: index for index, key in enumerate(id_by_key)}
        prefixes = route_prefixes(ctx.spec or {})
        candidates: list[tuple[int, int, _Candidate]] = []
        for schema_index, result in enumerate(schema.get_all_operations()):
            try:
                operation = result.ok()
            except Exception:  # noqa: BLE001 - isolate one malformed operation
                continue
            if operation is None:
                continue
            method = operation.method.upper()
            if method != "GET" and not (
                method in _MUTATING and ctx.allow_mutation
            ):
                continue
            candidate = _candidate(operation, method, prefixes, ctx.base_url, id_by_key)
            candidates.append(
                (
                    order.get((method, candidate.route), len(order) + schema_index),
                    schema_index,
                    candidate,
                )
            )
        # Preserve AI risk ordering from ctx.operations when planning is enabled;
        # schema-only leftovers retain document order behind parsed operations.
        candidates.sort(key=lambda item: (item[0], item[1]))
        return [candidate for _, _, candidate in candidates]

    @staticmethod
    def _generate(
        ctx: ScanContext,
        candidate: _Candidate,
        allowance: int,
        mode: Any,
        headers: dict[str, str],
        validators: tuple[tuple[str, Callable[..., Any]], ...],
        not_set: Any,
        failure_types: tuple[type[BaseException], ...],
        violations: dict[tuple[str, str], _Violation],
        given: Any,
        settings: Any,
        HealthCheck: Any,
    ) -> None:
        operation = candidate.operation
        try:
            strategy = operation.as_strategy(generation_mode=mode)

            @given(case=strategy)
            @settings(
                max_examples=allowance,
                deadline=None,
                database=None,
                suppress_health_check=list(HealthCheck),
            )
            def run_case(case: Any) -> None:
                path = candidate.runtime_path(
                    getattr(case, "formatted_path", None) or operation.path
                )
                params = dict(case.query or {})
                request_headers = dict(headers)
                content = None
                if candidate.method in _MUTATING and ctx.allow_mutation:
                    body = getattr(case, "body", not_set)
                    media_type = getattr(case, "media_type", None)
                    if body is not not_set:
                        if media_type:
                            request_headers["content-type"] = media_type
                        if isinstance(body, bytes):
                            content = body
                        elif isinstance(body, str) and not _is_json_media_type(media_type):
                            content = body.encode("utf-8", "replace")
                        elif _is_json_media_type(media_type):
                            try:
                                content = json.dumps(body, separators=(",", ":")).encode()
                            except (TypeError, ValueError):
                                content = None
                response = ctx.probe.send(
                    candidate.method,
                    path,
                    headers=request_headers,
                    params=params,
                    content=content,
                )
                if response is None:
                    return
                if 500 <= response.status < 600:
                    violation = _Violation("server_error", "response.status", response.status)
                    violations.setdefault((violation.rule, violation.location), violation)
                wrapped = SchemaFuzzCheck._response(case, response)
                for rule, validate in validators:
                    try:
                        validate(None, wrapped, case)
                    except BaseException as exc:
                        # Schemathesis uses an ExceptionGroup subclass that is
                        # intentionally outside Exception. Do not swallow an
                        # operator interrupt while isolating contract failures.
                        if isinstance(exc, KeyboardInterrupt | SystemExit):
                            raise
                        if not isinstance(exc, failure_types):
                            continue
                        for location in _locations(rule, exc):
                            violation = _Violation(
                                rule,
                                location,
                                response.status if rule == "status" else None,
                            )
                            violations.setdefault((rule, location), violation)

            run_case()
        except Exception:  # noqa: BLE001 - isolate generator/Hypothesis failures
            return

    @staticmethod
    def _response(case: Any, response: Any) -> Any:
        """Build Schemathesis's in-memory response wrapper; no extra request."""
        import requests
        from schemathesis.core.transport import Response

        request = requests.Request(
            method=case.method,
            url="http://schema-fuzz.invalid/",
        ).prepare()
        content = response.content or response.text.encode("utf-8", "replace")
        return Response(
            status_code=response.status,
            headers={name: [value] for name, value in response.headers.items()},
            content=content,
            request=request,
            elapsed=response.elapsed_ms / 1000,
            verify=True,
        )

    def _findings(self, candidate: _Candidate, violations: Any) -> list[EngineFinding]:
        return [self._finding(candidate, violation) for violation in violations]

    def _finding(self, candidate: _Candidate, violation: _Violation) -> EngineFinding:
        route = candidate.route or candidate.operation.path
        evidence: dict[str, Any] = {
            "method": candidate.method,
            "route": route,
            "rule": violation.rule,
            "location": violation.location,
        }
        if violation.status is not None:
            evidence["status"] = violation.status

        if violation.rule == "server_error":
            return EngineFinding(
                check=self.key,
                confidence=Confidence.verified,
                owasp_id="API8:2023",
                severity=Severity.medium,
                title=f"Server error on generated input to {candidate.method} {route}",
                description=(
                    f"A generated input caused {candidate.method} {route} to return a 5xx. "
                    "That directly evidences unhandled input or missing error handling "
                    "(CWE-20); the response body and generated value were not retained."
                ),
                evidence=evidence,
                operation_id=candidate.operation_id,
            )

        labels = {
            "status": "Undocumented response status",
            "content_type": "Response Content-Type violates the contract",
            "headers": "Response headers violate the contract",
            "schema": "Response body violates the declared schema",
        }
        return EngineFinding(
            check=self.key,
            confidence=Confidence.heuristic,
            owasp_id=None,
            severity=Severity.low,
            title=f"{labels[violation.rule]} on {candidate.method} {route}",
            description=(
                f"The response from {candidate.method} {route} did not match the uploaded "
                f"OpenAPI contract at {violation.location}. This is observed contract drift, "
                "not proof of a security weakness: either the implementation or the spec may "
                "be stale. No response or generated request values were retained."
            ),
            evidence=evidence,
            operation_id=candidate.operation_id,
        )
