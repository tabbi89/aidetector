"""Premium adaptive validation pass with a hard, model-independent envelope."""
from __future__ import annotations

import time
from typing import Any

from app.domain.enums import Confidence, Severity
from app.engine.adaptive.contracts import AdaptiveHistory, AdaptiveSettings, Attempt
from app.engine.adaptive.policy import select_tests
from app.engine.base import EngineFinding, ScanContext
from app.engine.resource_map import resource_id_for


def _safe_response(response: Any) -> dict[str, Any]:
    if response is None:
        return {"status": None}
    return {
        "status": response.status,
        "content_type": response.headers.get("content-type", "")[:80],
        "body_bytes": min(len(response.content or b""), 65536),
        "elapsed_ms": min(int(response.elapsed_ms), 120000),
    }


def _ai_refine(
    planner: Any, payload: dict[str, Any]
) -> tuple[dict[str, Any] | None, list[Any]]:
    """Call only the optional structured planner hook; failures are a stop reason.

    Returns the proposal and the call's usage: the provider was paid even when
    the proposal is rejected, so the caller must meter what came back.
    """
    if planner is None or not callable(getattr(planner, "refine", None)):
        return None, []
    try:
        value = planner.refine(payload)
    except Exception:  # noqa: BLE001 — optional AI cannot fail a scan
        return None, []
    usages: list[Any] = []
    # A planner may return (proposal, usages) or the bare proposal; accepting
    # both keeps the engine's minimal test doubles working.
    if isinstance(value, tuple):
        value, raw_usages = value[0], value[1] if len(value) > 1 else []
        if isinstance(raw_usages, list):
            usages = raw_usages
    if not isinstance(value, dict):
        return None, usages
    action = value.get("action")
    variant = value.get("variant")
    assessment = value.get("assessment")
    if action not in {"refine", "schema", "stop"}:
        return None, usages
    if variant not in {"v1", "v2", "v3", None}:
        return None, usages
    if assessment not in {"accepted", "rejected", "ignored", "uncertain", "constraint_mismatch"}:
        return None, usages
    return (
        {"action": action, "variant": variant, "assessment": assessment},
        usages,
    )


def run_adaptive(
    ctx: ScanContext,
    *,
    planner: Any = None,
    settings: AdaptiveSettings | None = None,
    emit: Any = None,
    cancelled: Any = lambda: False,
    on_ai_usage: Any = None,
) -> tuple[list[EngineFinding], dict[str, Any]]:
    """Run selected bounded validation tests; all limits are enforced here.

    GET query/path probes are read-only. JSON body probes are available only
    with the existing explicit ``mutate`` authorization and are still limited
    to scalar, spec-shaped variants; the optional planner cannot create a new
    request shape or escape the worker's envelope.
    """
    settings = settings or AdaptiveSettings()
    history = AdaptiveHistory(enabled=True, settings=settings)
    started = time.monotonic()
    candidates, skipped = select_tests(
        ctx.operations, mutate=ctx.allow_mutation, spec=ctx.spec, limit=settings.endpoints
    )
    for candidate in candidates:
        for name in candidate.op.path_params:
            identifier = resource_id_for(candidate.op.path, name, ctx.resource_ids)
            if identifier is not None:
                candidate.bases["path"][name] = identifier
    history.tests.extend(skipped)
    schema_context = ctx.schema_context
    schema_status = "available" if schema_context is not None else "not_configured"
    findings: list[EngineFinding] = []
    if emit:
        emit("adaptive", ctx.seed % 90, f"adaptive validation selected {len(candidates)} endpoints")
    for candidate in candidates:
        if cancelled():
            history.stop_reason = "cancelled"
            break
        if time.monotonic() - started >= settings.seconds:
            history.stop_reason = "deadline"
            break
        trace = candidate.trace()
        trace.schema_status = schema_status
        baseline_path, baseline_query, baseline_body = candidate.request(control=True)
        control = ctx.probe.send(candidate.op.method, baseline_path,
                                 headers=ctx.primary_headers(), params=baseline_query,
                                 json=baseline_body)
        history.requests += 1
        if control is None:
            trace.stop_reason = "request_budget"
            history.tests.append(trace)
            history.stop_reason = "request_budget"
            break
        attempt_no = 0
        previous = _safe_response(control)
        variants = [f"v{n}" for n in range(1, settings.attempts + 1)]
        used_variants: set[str] = set()
        next_variant: str | None = variants[0] if variants else None
        trace.stop_reason = "attempt_limit"
        while next_variant is not None:
            variant = next_variant
            used_variants.add(variant)
            if cancelled():
                trace.stop_reason = "cancelled"
                history.stop_reason = "cancelled"
                break
            if time.monotonic() - started >= settings.seconds:
                trace.stop_reason = "deadline"
                history.stop_reason = "deadline"
                break
            if history.requests >= settings.requests:
                trace.stop_reason = "request_budget"
                history.stop_reason = "request_budget"
                break
            attempt_no += 1
            try:
                value = candidate.payload(variant, ctx.seed)
                path, query, body = candidate.request(value)
            except (ValueError, KeyError, TypeError):
                trace.stop_reason = "unsafe_proposal"
                break
            response = ctx.probe.send(candidate.op.method, path, headers=ctx.primary_headers(),
                                      params=query, json=body)
            history.requests += 1
            if response is None:
                trace.stop_reason = "request_budget"
                history.stop_reason = "request_budget"
                break
            observed = _safe_response(response)
            accepted = response.status < 400
            outcome = "suspected_gap" if accepted else "rejected"
            attempt = Attempt(number=attempt_no, variant=variant, status=response.status,
                              outcome=outcome, assessment="engine_observed")
            trace.attempts.append(attempt)
            if accepted and control.status < 400:
                findings.append(EngineFinding(
                    check="adaptive_validation",
                    owasp_id="API8:2023",
                    severity=Severity.medium,
                    confidence=Confidence.heuristic,
                    title=(
                        f"Validation gap lead: {candidate.op.method} "
                        f"{candidate.op.path} {candidate.rule}"
                    ),
                    description=(
                        "A controlled validation variant was accepted after a valid "
                        "baseline. This is a heuristic lead; the response did not prove "
                        "that the value was persisted or used by the application."
                    ),
                    evidence={
                        "method": candidate.op.method,
                        "route": candidate.op.path,
                        "field": candidate.field,
                        "location": candidate.location,
                        "issue": candidate.rule,
                        "baseline": control.status,
                        "variant": variant,
                        "response": observed,
                    },
                    operation_id=candidate.op.id,
                ))
                trace.outcome = "suspected_gap"
            previous = observed
            proposal, usages = _ai_refine(planner, {
                "method": candidate.op.method, "route": candidate.op.path,
                "field": candidate.field, "rule": candidate.rule,
                "location": candidate.location,
                "mutation_enabled": ctx.allow_mutation,
                "attempt": attempt_no, "previous": previous, "control": _safe_response(control),
                "schema_status": trace.schema_status,
                "schema": schema_context,
            })
            if usages and on_ai_usage is not None:
                on_ai_usage(usages)
            if proposal is None:
                # AI refinement is advisory. Keep the deterministic bounded
                # sequence moving when the optional runtime is unavailable.
                suggested = None
            elif proposal["action"] == "stop":
                trace.stop_reason = "ai_stop"
                break
            else:
                suggested = proposal.get("variant")
            if suggested in variants and suggested not in used_variants:
                next_variant = suggested
            else:
                next_variant = next((v for v in variants if v not in used_variants), None)
        history.tests.append(trace)
    if not history.stop_reason or history.stop_reason == "disabled":
        history.stop_reason = "completed"
    history.elapsed_ms = int((time.monotonic() - started) * 1000)
    history.requests = ctx.probe.count
    history.cost_estimated = False
    if emit:
        emit("adaptive_done", min(99, ctx.seed % 90 + 5),
             f"adaptive validation complete · {len(history.tests)} tests")
    return findings, history.model_dump(mode="json")
