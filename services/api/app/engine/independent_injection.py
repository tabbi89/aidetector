"""Small, opt-in execution sample that does not depend on reflection leads.

Two different arithmetic results, a repeat, a non-template control and stable
surrounding output are required. No timing, filesystem or command payloads.
"""

from __future__ import annotations

import random
import re

from app.domain.enums import Confidence, Severity
from app.engine.base import EngineFinding
from app.engine.request_shapes import control_value, points, request

_RISK = re.compile(r"template|render|search|filter|query|expression|preview|message", re.I)


def confirm_independently(ctx) -> list[EngineFinding]:
    if not ctx.confirm:
        return []
    candidates = [
        (op, point)
        for op in ctx.operations
        for point in points(ctx, op)
        if isinstance(control_value(point), str)
    ]
    candidates.sort(
        key=lambda pair: (
            not bool(_RISK.search(pair[0].path + " " + pair[1].name)),
            pair[0].method,
            pair[0].path,
            pair[1].location,
            pair[1].name,
            pair[1].variant,
        )
    )
    findings = []
    for op, point in candidates[:4]:
        label = f"independent:{op.method}:{op.path}:{point.location}:{point.name}"
        with ctx.probe.test_case(5, label=label) as case:
            if case is None:
                break
            rng = random.Random(f"{ctx.seed}:{label}")
            a, b, c = rng.sample(range(111, 997), 3)
            first, second = str(a * b), str(a * c)
            expression = f"{{{{{a}*{b}}}}}"
            alternate = f"{{{{{a}*{c}}}}}"
            values = [control_value(point), expression, alternate, expression, f"{a}*{b}"]
            responses = []
            for index, value in enumerate(values):
                path, kwargs = request(ctx, op, point, value, ctx.primary_headers())
                response = ctx.probe.send(op.method, path, **kwargs)
                if index == 0:
                    case["baseline_valid"] = bool(response and 200 <= response.status < 300)
                if response is None or not 200 <= response.status < 300:
                    case["outcome"] = "blocked"
                    break
                responses.append(response.text)
            if len(responses) != 5:
                continue
            baseline, one, two, repeat, literal = responses
            case["outcome"] = "passed"
            if not (
                first in one
                and second in two
                and one == repeat
                and one.replace(first, "RESULT") == two.replace(second, "RESULT")
                and first not in baseline + literal
                and second not in baseline + literal
                and expression not in one
                and alternate not in two
            ):
                continue
            case["outcome"] = "finding"
            findings.append(
                EngineFinding(
                    check="reflected_injection",
                    confidence=Confidence.verified,
                    severity=Severity.high,
                    owasp_id="CWE-1336",
                    title=f"Template expression evaluated on {op.method} {op.path}",
                    description="Two arithmetic expressions produced distinct expected results, "
                    "with repeatable output and a negative literal control.",
                    evidence={
                        "method": op.method,
                        "route": op.path,
                        "path": op.path,
                        "param": point.name,
                        "location": point.location,
                        "family": "ssti",
                        "signal": "independent_arithmetic",
                        "variant": point.variant,
                        "controls": 5,
                        "reflected": False,
                    },
                    operation_id=op.id,
                )
            )
    return findings


def sample_sql_targets(ctx, limit: int = 2) -> list[dict]:
    """Preflight a small high-risk GET/query sample before the main budget is spent.

    Templates remain in memory and retain the credential/companion parameters.
    They are passed only to the configured sqlmap adapter, never to the archive.
    """
    candidates = [(op, point) for op in ctx.operations if op.method == "GET"
                  for point in points(ctx, op) if point.location == "query"]
    candidates.sort(
        key=lambda pair: (
            not bool(
                re.search(r"search|query|filter|sort|order|id", pair[0].path + pair[1].name, re.I)
            ),
            pair[0].path,
            pair[1].name,
        )
    )
    selected = []
    for op, point in candidates[:limit]:
        with ctx.probe.test_case(1, label=f"sqlmap-control:{op.path}:{point.name}") as case:
            if case is None:
                break
            path, kwargs = request(ctx, op, point, control_value(point), ctx.primary_headers())
            response = ctx.probe.send("GET", path, **kwargs)
            case["baseline_valid"] = bool(response and 200 <= response.status < 300)
            case["outcome"] = "ready_for_confirmation" if case["baseline_valid"] else "blocked"
            if case["baseline_valid"]:
                selected.append({"path": path, "param": point.name, "operation_id": op.id,
                                 "source_check": "independent_sample", "request": kwargs,
                                 "case": case})
    return selected
