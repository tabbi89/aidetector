"""Explicit business invariants from x-runpentests-workflows.

No policy is inferred from a route name. Each scenario uses a fresh fixture,
requires a successful normal workflow, observes persisted state, and tears down
in finally. All requests must match enabled spec operations and named identities.
"""

from __future__ import annotations

import json
import re
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field

from app.domain.enums import Confidence, Severity
from app.engine.base import EngineFinding, render_path
from app.engine.cleanup import cleanup_request


class Step(BaseModel):
    model_config = ConfigDict(extra="forbid")
    method: Literal["GET", "POST", "PUT", "PATCH", "DELETE"]
    path: str = Field(max_length=512)
    identity: str = Field(max_length=100)
    body: dict[str, Any] | None = None
    save: dict[str, str] = Field(default_factory=dict, max_length=8)


class Scenario(BaseModel):
    model_config = ConfigDict(extra="forbid")
    kind: Literal["skip", "replay", "cross_identity"]
    index: int = Field(ge=0, le=7)
    identity: str | None = Field(default=None, max_length=100)
    forbidden: str | int | bool


class Workflow(BaseModel):
    model_config = ConfigDict(extra="forbid")
    name: str = Field(pattern=r"^[A-Za-z0-9_-]{1,64}$")
    setup: list[Step] = Field(min_length=1, max_length=4)
    transitions: list[Step] = Field(min_length=1, max_length=8)
    observe: Step
    pointer: str = Field(pattern=r"^/", max_length=256)
    expected: str | int | bool
    cleanup: list[Step] = Field(min_length=1, max_length=4)
    tests: list[Scenario] = Field(min_length=1, max_length=8)


def read_pointer(value: Any, pointer: str) -> Any:
    for part in pointer.removeprefix("/").split("/"):
        part = part.replace("~1", "/").replace("~0", "~")
        value = value[int(part)] if isinstance(value, list) else value[part]
    return value


def configured(ctx) -> list[Workflow]:
    raw = (ctx.spec or {}).get("x-runpentests-workflows", [])
    if not isinstance(raw, list):
        return []
    workflows = []
    for item in raw[:4]:
        try:
            workflow = Workflow.model_validate(item)
            ops = {(op.method, op.path) for op in ctx.operations}
            names = {cred.name for cred in ctx.credentials}
            steps = [*workflow.setup, *workflow.transitions, workflow.observe, *workflow.cleanup]
            if any(
                (step.method, step.path) not in ops or step.identity not in names for step in steps
            ):
                continue
            if workflow.observe.method != "GET":
                continue
            if any(step.method == "DELETE" for step in [*workflow.setup, *workflow.transitions]):
                continue
            if any(
                test.index >= len(workflow.transitions)
                or (
                    test.kind == "cross_identity"
                    and (
                        test.identity not in names
                        or test.identity == workflow.transitions[test.index].identity
                    )
                )
                for test in workflow.tests
            ):
                continue
            workflows.append(workflow)
        except Exception:
            continue
    return workflows


def _substitute(value, variables):
    if isinstance(value, dict):
        return {k: _substitute(v, variables) for k, v in value.items()}
    if isinstance(value, list):
        return [_substitute(v, variables) for v in value]
    if isinstance(value, str) and value.startswith("${") and value.endswith("}"):
        return variables[value[2:-1]]
    return value


def _send(ctx, step: Step, variables: dict, *, cleaning=False):
    op = next(op for op in ctx.operations if (op.method, op.path) == (step.method, step.path))
    credential = next(c for c in ctx.credentials if c.name == step.identity)
    if any(param not in variables for param in op.path_params):
        raise ValueError("workflow path variable not captured")
    path = render_path(step.path, variables)
    kwargs = {"headers": credential.headers(), "json": _substitute(step.body, variables)}
    if cleaning:
        return cleanup_request(ctx, op, path, **kwargs)
    response = ctx.probe.send(step.method, path, **kwargs)
    if response is None:
        raise ValueError("workflow budget exhausted")
    if 200 <= response.status < 300:
        for key, pointer in step.save.items():
            value = str(read_pointer(json.loads(response.text), pointer))
            # Captured target data can only fill a path segment, never redirect a
            # request or inject query delimiters. Keep it out of archived evidence.
            if not re.fullmatch(r"[A-Za-z0-9_-]{1,256}", value):
                raise ValueError("unsafe workflow variable")
            variables[key] = value
    return response


def run_workflows(ctx) -> list[EngineFinding]:
    if not ctx.allow_mutation:
        return []
    findings = []
    workflows = configured(ctx)
    if (ctx.spec or {}).get("x-runpentests-workflows") and not workflows:
        ctx.probe.test_cases.append(
            {
                "check": "business_flow",
                "label": "workflow configuration",
                "outcome": "unsupported",
                "baseline_valid": None,
            }
        )
    for workflow in workflows:
        for scenario in workflow.tests:
            label = f"workflow:{workflow.name}:{scenario.kind}:{scenario.index}"
            # Two fresh fixtures: successful normal control, then altered sequence.
            active = 2 * (len(workflow.setup) + len(workflow.transitions) + 2) + 1
            cleanups = 2 * len(workflow.cleanup)
            with ctx.probe.test_case(active + cleanups, cleanup=cleanups, label=label) as case:
                if case is None:
                    continue
                confirmed = False
                for altered in (False, True):
                    variables: dict[str, str] = {}
                    try:
                        if any(
                            not 200 <= _send(ctx, s, variables).status < 300 for s in workflow.setup
                        ):
                            case["outcome"] = "blocked"
                            break
                        before = _send(ctx, workflow.observe, variables)
                        if not 200 <= before.status < 300:
                            case["outcome"] = "blocked"
                            break
                        initial = read_pointer(json.loads(before.text), workflow.pointer)
                        if initial == scenario.forbidden:
                            case["outcome"] = "inconclusive"
                            break
                        sequence = list(workflow.transitions)
                        if altered:
                            if scenario.kind == "skip":
                                del sequence[scenario.index]
                            elif scenario.kind == "replay":
                                sequence.insert(scenario.index + 1, sequence[scenario.index])
                            else:
                                sequence[scenario.index] = sequence[scenario.index].model_copy(
                                    update={"identity": scenario.identity}
                                )
                        statuses = [_send(ctx, s, variables).status for s in sequence]
                        after = _send(ctx, workflow.observe, variables)
                        if not 200 <= after.status < 300:
                            case["outcome"] = "blocked"
                            break
                        state = read_pointer(json.loads(after.text), workflow.pointer)
                        if not altered:
                            case["baseline_valid"] = (
                                all(200 <= s < 300 for s in statuses) and state == workflow.expected
                            )
                            if not case["baseline_valid"]:
                                case["outcome"] = "blocked"
                                break
                        else:
                            confirmed = state == scenario.forbidden
                            case["outcome"] = "finding" if confirmed else "passed"
                    except Exception:
                        case["outcome"] = "error"
                        break
                    finally:
                        for step in reversed(workflow.cleanup):
                            try:
                                _send(ctx, step, variables, cleaning=True)
                            except Exception:
                                ctx.probe.cleanup_results.append(False)
                                ctx.cleanup_failures.append(
                                    f"{step.method} {step.path}: workflow cleanup unavailable"
                                )
                if confirmed:
                    findings.append(
                        EngineFinding(
                            check="business_flow",
                            severity=Severity.high,
                            confidence=Confidence.verified,
                            owasp_id="API6:2023",
                            title=f"Business invariant violated: {workflow.name} ({scenario.kind})",
                            description="A normal workflow succeeded. A fresh fixture reached the "
                            "explicitly forbidden persisted state after a changed transition.",
                            evidence={
                                "method": workflow.observe.method,
                                "path": workflow.observe.path,
                                "param": label,
                                "workflow": workflow.name,
                                "kind": scenario.kind,
                                "transition": scenario.index,
                                "state_pointer": workflow.pointer,
                            },
                        )
                    )
    return findings
