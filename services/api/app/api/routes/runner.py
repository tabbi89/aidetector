"""Local-runner ingest API — the CLI heavy lane's server side.

A scan can be executed on the machine running the ``aidetector`` CLI instead of
the server's Celery worker, so its traffic originates where that machine can
reach (internal hosts) and it can read the project's source for whitebox
analysis. The results still land here, graded and fingerprinted by the server.

Two surfaces:

- ``POST /scans/{id}/local-runs`` — the **claim**. Authenticated by the tenant
  API key, it answers the same authorization gate, target guard and
  active-scan 409 as a normal run, opens a ``ScanRun`` already ``running``,
  issues a per-run bearer token (hash stored, clear token returned once), and
  hands back everything the runner needs to build a ScanContext *except*
  credential secrets — those stay on the CLI machine.
- ``POST /runner/runs/{run_id}/{events,heartbeat,plan,complete,fail}`` — authenticated
  by that per-run token only (the container never holds the API key). The
  server validates the uploaded bundle, then persists it through its own
  ``append_finding`` so identity, remediation and redaction are the server's,
  not the runner's.

Safety invariants (see CLAUDE.md): the authorization gate and target guard are
answered at claim; the engine request budget and cadence are *issued* by the
server and an upload over budget is refused; the heavy/AI passes are refused at
claim (except the plan and the design review, which send no target traffic); and
the per-run token dies when the run ends, so a late or leaked token cannot post
to a finished run or any other run.
"""
from __future__ import annotations

import logging
import uuid
from datetime import UTC, datetime
from typing import Annotated

from fastapi import APIRouter, Depends, Header, HTTPException
from sqlalchemy.orm import Session

from app.agent.sandbox import SANDBOX_CHECK_KEYS
from app.ai.security_review import SecurityReview
from app.api import schemas
from app.api.routes.scans import _require_run_authorization, _require_runnable
from app.core.auth import ScanWriteDep
from app.core.config import settings
from app.core.db import get_db
from app.core.jsonsafe import jsonb_safe
from app.core.redact import Redactor
from app.db_schema.contracts import accept_upload
from app.engine import ai_phases
from app.engine.base import EngineFinding
from app.engine.checks import ALL_CHECKS
from app.engine.journal import MAX_FAILURE_REASON
from app.engine.operations import TargetOperation
from app.engine.run_record import append_finding, build_findings_snapshot
from app.engine.runner import DEFAULT_MAX_REQUESTS
from app.models.event import ScanEvent
from app.models.scan import Scan, ScanRun, ScanStatus
from app.scans import agent_memory, local_runs, service, workspace
from app.scans.operations import retarget_operations
from app.scans.run_levels import LOCAL_REFUSED
from app.scans.run_token import new_run_token, token_matches

router = APIRouter(tags=["runner"])
log = logging.getLogger("runpentests.runner.ingest")

#: Passes a local run cannot perform; the claim refuses them when asked for
#: explicitly (a scan level already leaves them out). Shared with the level
#: expansion so the two can never disagree — see ``app.scans.run_levels``.
_LOCAL_REFUSED = LOCAL_REFUSED


def _now() -> datetime:
    return datetime.now(UTC)


def _enabled_or_404() -> None:
    if not settings.local_runner_enabled:
        raise HTTPException(status_code=404, detail="local runner is not enabled")


@router.post(
    "/scans/{scan_id}/local-runs",
    response_model=schemas.LocalRunConfig,
    status_code=201,
)
def claim_local_run(
    scan_id: uuid.UUID,
    body: schemas.RunRequest,
    principal: ScanWriteDep,
    db: Session = Depends(get_db),
) -> schemas.LocalRunConfig:
    """Claim a scan to run on the CLI machine. Mirrors the run endpoint's gates."""
    _enabled_or_404()
    scan = service.get_scan(db, scan_id, principal.tenant)
    if scan is None:
        raise HTTPException(status_code=404, detail="scan not found")
    body = _require_run_authorization(body, principal.tenant, db, lane="local")
    # A local run egresses from the CLI machine, not the server, so a private
    # target here is the tenant reaching their own network — allowed regardless
    # of the server's egress flag. Cloud metadata stays blocked, and a public
    # target still needs its ownership proof (see _require_target_allowed).
    clearance = _require_runnable(scan, db, allow_private=True)
    refused = [name for name in _LOCAL_REFUSED if getattr(body, name, False)]
    if refused:
        raise HTTPException(
            status_code=422,
            detail="these passes cannot run on the local runner: " + ", ".join(refused),
        )
    # Answered after the request's own refusals: an admission is recorded only
    # for a run that goes on to be claimed. A local run is a run: the same
    # concurrency/queue/daily admission applies, or a second lane could start
    # work the workspace allowance forbids.
    try:
        workspace.admit_run(db, principal.tenant, scan_id=scan.id, source="local")
    except workspace.RunLimit as exc:
        raise HTTPException(
            status_code=429, detail=f"run limit reached: {exc.reason}"
        ) from exc

    opts = body.to_options()
    requested_rate = (
        body.requests_per_second
        if body.requests_per_second is not None
        else scan.requests_per_second
    )
    rate = min(int(settings.engine_requests_per_second), requested_rate)
    if body.requests_per_second is not None:
        scan.requests_per_second = body.requests_per_second

    clear, token_hash = new_run_token()
    run = ScanRun(
        run_number=len(scan.runs) + 1,
        status="running",
        # Archive what was authorized, not what the upload later claims.
        options=opts.archived(),
        executor={
            "kind": "local_runner",
            "max_requests": DEFAULT_MAX_REQUESTS,
            "ai_call_budget": settings.runner_ai_call_budget,
        },
        config_source=body.config_source.model_dump() if body.config_source else {},
        run_token_hash=token_hash,
    )
    scan.runs.append(run)
    # Open the run: a run replaces the scan's live findings and events.
    scan.status = ScanStatus.running
    scan.progress = 0
    scan.failure_reason = None
    scan.cancel_requested = False
    scan.heartbeat_at = _now()
    # The daily admission allowance counts accepted admissions from this stamp,
    # whether or not a ScanRun row exists yet.
    scan.queued_at = _now()
    scan.findings.clear()
    scan.events.clear()
    # The claim hands the runner each operation's route. Re-derive them first
    # (see the server run's twin in engine.runner), after the reset so the
    # event that says routes moved survives into this run.
    retarget_operations(scan, scan.target_base_url)
    db.flush()  # assign run.id
    workspace.record_audit(
        db,
        principal,
        "run.local_claimed",
        "scan",
        scan.id,
        {"run_number": run.run_number},
    )
    scan.events.append(
        ScanEvent(
            stage="local_run_claimed",
            pct=0,
            message=f"local runner claimed run {run.run_number}",
        )
    )
    db.commit()

    return schemas.LocalRunConfig(
        run_id=run.id,
        run_number=run.run_number,
        token=clear,
        options=run.options,
        max_requests=DEFAULT_MAX_REQUESTS,
        requests_per_second=rate,
        target_base_url=scan.target_base_url,
        spec_text=scan.spec_text,
        operations=[
            schemas.OperationOut.model_validate(op) for op in scan.operations if op.enabled
        ],
        credentials=[
            schemas.CredentialOut.model_validate(cp) for cp in scan.credential_profiles
        ],
        target_policy=schemas.TargetPolicy(**clearance.runner_policy()),
        oast=(
            schemas.OastConfig(
                server=settings.runner_oast_server, token=settings.runner_oast_token or None
            )
            if settings.runner_oast_server
            else None
        ),
        adjunct_budget_seconds=settings.adjunct_budget_seconds,
    )


@router.post(
    "/scans/{scan_id}/auth-checks",
    response_model=schemas.AuthCheckConfig,
)
def claim_auth_check(
    scan_id: uuid.UUID,
    body: schemas.AuthCheckRequest,
    principal: ScanWriteDep,
    db: Session = Depends(get_db),
) -> schemas.AuthCheckConfig:
    """Let the CLI check its identities against the target before a full scan.

    The same consent and target rules as a run — ``authorized`` per call, the
    egress guard and the ownership proof — but no run is opened and nothing is
    archived: the runner sends a few GETs per identity and prints its verdict on
    the CLI machine. The routes are chosen here (GET only) and the request
    count is bounded, so this can never become a scan.
    """
    from app.api.routes.scans._shared import _require_target_allowed
    from app.engine.auth_probe import MAX_REQUESTS, pick_routes

    _enabled_or_404()
    scan = service.get_scan(db, scan_id, principal.tenant)
    if scan is None:
        raise HTTPException(status_code=404, detail="scan not found")
    if not body.authorized:
        raise HTTPException(
            status_code=403,
            detail="authorized must be true: an auth check sends live requests to the target",
        )
    if not scan.operations:
        raise HTTPException(status_code=400, detail="upload a spec before checking credentials")
    clearance = _require_target_allowed(scan, db, allow_private=True)
    enabled = [schemas.OperationOut.model_validate(op) for op in scan.operations if op.enabled]
    chosen_ids = {
        str(op["id"]) for op in pick_routes([o.model_dump(mode="json") for o in enabled])
    }
    routes = [op for op in enabled if str(op.id) in chosen_ids]
    if not routes:
        raise HTTPException(
            status_code=400,
            detail="the scan has no enabled GET operation to check credentials against",
        )
    workspace.record_audit(
        db, principal, "auth_check.claimed", "scan", scan.id, {"routes": len(routes)}
    )
    db.commit()
    return schemas.AuthCheckConfig(
        target_base_url=scan.target_base_url,
        operations=routes,
        credentials=[schemas.CredentialOut.model_validate(cp) for cp in scan.credential_profiles],
        target_policy=schemas.TargetPolicy(**clearance.runner_policy()),
        max_requests=MAX_REQUESTS,
        requests_per_second=min(int(settings.engine_requests_per_second), 5),
    )


def load_running_local_run(
    run_id: uuid.UUID,
    x_run_token: Annotated[str | None, Header()] = None,
    db: Session = Depends(get_db),
) -> ScanRun:
    """The running local run named in the path, authenticated by its per-run token."""
    _enabled_or_404()
    run = db.get(ScanRun, run_id)
    if run is None or (run.executor or {}).get("kind") != "local_runner":
        raise HTTPException(status_code=404, detail="local run not found")
    # Refuse before the token check leaks nothing: a run that already ended has
    # no token hash, so token_matches would fail anyway; the clearer 409 helps a
    # runner that raced a cancel/reap.
    if run.status != "running":
        raise HTTPException(status_code=409, detail="run is not accepting uploads")
    if not token_matches(x_run_token, run.run_token_hash):
        raise HTTPException(status_code=401, detail="invalid or missing run token")
    return run


RunningRun = Annotated[ScanRun, Depends(load_running_local_run)]


@router.post("/runner/runs/{run_id}/events", response_model=schemas.RunnerHeartbeatOut)
def runner_events(
    body: schemas.RunnerEventBatch,
    run: RunningRun,
    db: Session = Depends(get_db),
) -> schemas.RunnerHeartbeatOut:
    """Append progress events and stamp liveness; returns the cancel flag."""
    scan: Scan = run.scan
    for ev in body.events:
        scan.events.append(ScanEvent(stage=ev.stage[:60], pct=ev.pct, message=ev.message))
        scan.progress = ev.pct
    scan.heartbeat_at = _now()
    db.commit()
    return schemas.RunnerHeartbeatOut(cancel=scan.cancel_requested)


@router.post("/runner/runs/{run_id}/heartbeat", response_model=schemas.RunnerHeartbeatOut)
def runner_heartbeat(
    run: RunningRun, db: Session = Depends(get_db)
) -> schemas.RunnerHeartbeatOut:
    """Stamp liveness and learn whether a cancel was requested from the web."""
    scan: Scan = run.scan
    scan.heartbeat_at = _now()
    db.commit()
    return schemas.RunnerHeartbeatOut(cancel=scan.cancel_requested)


@router.post("/runner/runs/{run_id}/plan", response_model=schemas.RunnerPlanOut)
def runner_plan(run: RunningRun, db: Session = Depends(get_db)) -> schemas.RunnerPlanOut:
    """The AI pre-scan plan for a local run: the claim's operations, riskiest first.

    Only a run that claimed ``plan`` may ask — the options archived at claim are
    what was authorized and priced. Asking again returns the stored plan rather
    than spending twice. Every AI failure is a ``plan_skipped`` event and the
    spec order, exactly as on a server run.
    """
    scan: Scan = run.scan
    if not (run.options or {}).get("plan"):
        raise HTTPException(status_code=409, detail="this run did not request an AI plan")
    ops = [
        TargetOperation(
            id=str(op.id),
            method=op.method,
            path=op.path,
            params=op.params or [],
            auth_scope=op.auth_scope,
        )
        for op in scan.operations
        if op.enabled
    ]
    if run.plan:
        stored = [str(row.get("operation_id")) for row in run.plan if isinstance(row, dict)]
        return schemas.RunnerPlanOut(operation_ids=stored, events=[])

    events: list[schemas.RunnerEvent] = []

    def emit(stage: str, pct: int, message: str) -> None:
        events.append(schemas.RunnerEvent(stage=stage[:60], pct=pct, message=message[:2000]))

    ai_phases.plan_order(db, scan, ops, run, None, emit)
    scan.heartbeat_at = _now()
    db.commit()
    return schemas.RunnerPlanOut(operation_ids=[str(op.id) for op in ops], events=events)


@router.get("/runner/runs/{run_id}/memory", response_model=schemas.RunnerMemoryOut)
def runner_memory(run: RunningRun, db: Session = Depends(get_db)) -> schemas.RunnerMemoryOut:
    """Recall what prior heavy runs found on this target, for this tenant.

    Token-scoped like every other runner call, so the runner reaches only the
    memory of the scan it is executing. Episodic memory steers the agent; it is
    never authoritative — a recalled weakness still has to be re-confirmed, and
    the engine grades whatever the agent produces.
    """
    scan: Scan = run.scan
    rows = agent_memory.recall(db, scan.tenant_id, scan.target_base_url)
    return schemas.RunnerMemoryOut(
        memories=[schemas.AgentMemoryRow(**row) for row in rows]
    )


#: In-loop AI passes a local run may ask the service to run (no target traffic;
#: the planner and the ledger are here). Resource refinement is wired; the other
#: two (genai_payloads/adaptive) use the same endpoint once their engine passes
#: run in the runner.
#: AI mode → the run option that authorizes it. A run may call a mode only when
#: it asked for that pass, so one requested AI pass cannot unlock the others.
_RUNNER_AI_MODES = {
    "propose_resource": "resource_refine",
    "payloads": "genai_payloads",
    "adaptive": "adaptive",
}


@router.post("/runner/runs/{run_id}/ai", response_model=schemas.RunnerAiOut)
def runner_ai(
    body: schemas.RunnerAiIn,
    run: RunningRun,
    db: Session = Depends(get_db),
) -> schemas.RunnerAiOut:
    """Run one planner call for a local run, priced here, capped per run.

    Only a run that asked for an in-loop AI pass may call, and only for a known
    mode. Every failure degrades to an empty result so the runner falls back to
    its deterministic path — an AI problem never fails a local run.
    """
    scan: Scan = run.scan
    options = run.options or {}
    required = _RUNNER_AI_MODES.get(body.mode)
    if required is None:
        raise HTTPException(status_code=422, detail=f"unknown AI mode: {body.mode}")
    if not options.get(required):
        raise HTTPException(
            status_code=409, detail=f"this run did not request the {required} pass"
        )
    executor = dict(run.executor or {})
    budget = int(executor.get("ai_call_budget", 0))
    if int(executor.get("ai_calls", 0)) >= budget:
        # The cap is spent: refuse without spending more, the runner degrades.
        return schemas.RunnerAiOut(result={})
    # Count the call before making it, so a hang cannot be retried past the cap.
    executor["ai_calls"] = int(executor.get("ai_calls", 0)) + 1
    run.executor = executor
    scan.heartbeat_at = _now()
    db.commit()

    from app.ai.planner import OpusPlanner, PlannerUnavailable
    from app.engine.ai_phases import write_ledger

    planner = OpusPlanner()
    try:
        if body.mode == "propose_resource":
            out, usages = planner.propose_resource(body.payload)
            result = {"proposal": out}
        elif body.mode == "payloads":
            families = body.payload.get("families") or []
            out, usages = planner.generate_payloads(families)
            result = {"payloads": out}
        else:  # "adaptive"
            out, usages = planner.refine(body.payload)
            result = {"proposal": out}
    except PlannerUnavailable:
        return schemas.RunnerAiOut(result={})
    except Exception:  # noqa: BLE001 — never fail a run on an AI problem
        log.warning("runner AI call failed for run %s", run.id, exc_info=True)
        return schemas.RunnerAiOut(result={})
    if usages:
        write_ledger(scan, usages)
        db.commit()
    return schemas.RunnerAiOut(result=result)


@router.post("/runner/runs/{run_id}/complete", response_model=schemas.RunAccepted)
def runner_complete(
    body: schemas.RunnerComplete,
    run: RunningRun,
    db: Session = Depends(get_db),
) -> schemas.RunAccepted:
    """Validate and persist an uploaded result bundle, then finish the run."""
    scan: Scan = run.scan
    budget = int((run.executor or {}).get("max_requests", DEFAULT_MAX_REQUESTS))
    if body.requests > budget:
        raise HTTPException(
            status_code=422,
            detail=f"reported {body.requests} requests over the issued budget of {budget}",
        )
    # Engine-tier keys plus the curated set the heavy-lane sandbox may emit
    # (each has a remediation catalogue entry). Nothing else is accepted: a
    # runner cannot invent a check key the product does not know.
    valid_keys = (
        {getattr(c, "key", None) for c in ALL_CHECKS}
        | set(SANDBOX_CHECK_KEYS) | {"source_runtime_cve"}
    )
    op_ids = {str(op.id) for op in scan.operations}
    # Pattern-only second pass — the runner already redacted with the secrets it
    # holds; this is defence in depth over what crossed the wire.
    redactor = Redactor()
    # The run's request trace, redacted again before it is stored, and read
    # before the findings so each one links to the rows behind it.
    trace = [jsonb_safe(redactor.value(row.model_dump(by_alias=True))) for row in body.trace]
    for rf in body.findings:
        if rf.check not in valid_keys:
            raise HTTPException(status_code=422, detail=f"unknown check key: {rf.check}")
        if rf.operation_id is not None and str(rf.operation_id) not in op_ids:
            raise HTTPException(
                status_code=422, detail="a finding references an operation not in this scan"
            )
        append_finding(
            scan,
            EngineFinding(
                check=rf.check,
                owasp_id=rf.owasp_id,
                severity=rf.severity,
                title=rf.title,
                description=rf.description,
                evidence=rf.evidence,
                operation_id=str(rf.operation_id) if rf.operation_id else None,
                confidence=rf.confidence,
                remediation=rf.remediation,
            ),
            redactor,
            trace,
        )

    run.requests = body.requests
    run.coverage = body.coverage
    # Set now so the run row is accurate during any analysing window;
    # finish_local_run re-takes the snapshot after AI verdicts land.
    run.findings_count = len(scan.findings)
    run.findings_snapshot = build_findings_snapshot(scan)
    run.mutations = trace
    run.manifest = redactor.value(body.manifest)
    # Keep only the shape the diff reads. The runner is trusted to report what
    # it did, not to inject arbitrary keys into the run record.
    not_run = body.gaps.get("not_run")
    missing = body.gaps.get("identities_missing")
    run.gaps = {
        "not_run": sorted({str(t)[:40] for t in not_run[:20]}) if isinstance(not_run, list) else [],
        "budget_exhausted": body.gaps.get("budget_exhausted") is True,
        "source_audit_complete": body.gaps.get("source_audit_complete") is True,
    }
    if isinstance(missing, list) and missing:
        run.gaps["identities_missing"] = sorted({str(n)[:120] for n in missing[:50]})
    # Registered check keys only: an unknown name would match nothing, and the
    # run record is not a place for the runner to write free text.
    known = {getattr(c, "key", None) for c in ALL_CHECKS}
    for gap in ("skipped_checks", "failed_checks"):
        keys = body.gaps.get(gap)
        if isinstance(keys, list) and keys:
            accepted = sorted({k for k in keys[:100] if isinstance(k, str) and k in known})
            if accepted:
                run.gaps[gap] = accepted
    if body.schema_context is not None:
        # Structure only, re-validated here; an unacceptable snapshot is stored
        # as an ``invalid_upload`` attempt, never a refused run.
        run.schema_context = accept_upload(body.schema_context, _now().isoformat())
    run.executor = {
        **(run.executor or {}),
        "version": body.runner_version,
        "engine_digest": body.engine_digest,
    }
    run.run_token_hash = None  # the runner's part is over; the token dies here
    if not local_runs.wants_analysis(run):
        local_runs.finish_local_run(db, scan, run)
        db.commit()
        return schemas.RunAccepted(scan_id=scan.id, status=scan.status)

    # The AI passes need no target traffic, so they run here, where the AI
    # budget and ledger are, before the run completes — the server lane's order.
    run.status = local_runs.ANALYSING
    scan.progress = 95
    scan.heartbeat_at = _now()
    if (run.options or {}).get("security_review"):
        run.security_review = SecurityReview(
            status="running", model=settings.executor_model
        ).model_dump()
    scan.events.append(ScanEvent(
        stage="analysing", pct=95, message="results uploaded · AI analysis on the service",
    ))
    db.commit()
    # Queued after commit so the worker reads what this upload stored.
    from app.workers.tasks import analyze_local_run

    try:
        analyze_local_run.delay(str(run.id))
    except Exception:  # noqa: BLE001 — the upload is accepted; only the AI is lost
        log.warning("could not queue the AI analysis for run %s", run.id)
        if run.security_review:
            run.security_review = SecurityReview(
                status="unavailable", model=settings.executor_model
            ).model_dump()
        scan.events.append(ScanEvent(
            stage="ai_skipped",
            pct=95,
            message="AI analysis unavailable: it could not be queued",
        ))
        local_runs.finish_local_run(db, scan, run)
        db.commit()
    return schemas.RunAccepted(scan_id=scan.id, status=scan.status)


@router.post("/runner/runs/{run_id}/fail", response_model=schemas.RunAccepted)
def runner_fail(
    body: schemas.RunnerFail,
    run: RunningRun,
    db: Session = Depends(get_db),
) -> schemas.RunAccepted:
    """Mark the run failed (the runner crashed or could not finish)."""
    scan: Scan = run.scan
    run.finished_at = _now()
    run.run_token_hash = None
    if body.cancelled:
        run.status = "cancelled"
        scan.status = ScanStatus.cancelled
        scan.cancel_requested = False
        scan.events.append(
            ScanEvent(stage="cancelled", pct=scan.progress, message="local run cancelled")
        )
    else:
        run.status = "failed"
        scan.status = ScanStatus.failed
        # The reason is the runner's own sentence, not an exception: no class-name
        # prefix, redacted for anything credential-shaped, and kept short.
        scan.failure_reason = (
            Redactor().text(body.reason)[:MAX_FAILURE_REASON] if body.reason else None
        )
        scan.events.append(
            ScanEvent(stage="failed", pct=scan.progress, message="local run failed")
        )
        from app.notifications.events import run_failed_event

        run_failed_event(db, scan)
    db.commit()
    return schemas.RunAccepted(scan_id=scan.id, status=scan.status)
