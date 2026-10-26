from __future__ import annotations

from datetime import UTC, datetime

from fastapi import APIRouter, Depends, HTTPException, Query
from kombu.exceptions import OperationalError as BrokerUnavailable
from sqlalchemy import cast, func, select
from sqlalchemy.dialects.postgresql import JSONPATH
from sqlalchemy.orm import Session, defer

from app.api import schemas
from app.core.db import get_db
from app.models.event import ScanEvent
from app.models.scan import Scan, ScanRun, ScanStatus
from app.scans import diff, workspace
from app.scans.run_options import (
    RunOptions,
    descoped,
    dropped_passes,
    required_passes,
    unperformed,
)
from app.workers.tasks import run_scan_task

from ._shared import (
    _ACTIVE,
    SCAN_ROUTER_KWARGS,
    LightScanDep,
    ScanDep,
    ScanWriteDep,
    _latest_run,
    _require_run_authorization,
    _require_runnable,
)

router = APIRouter(**SCAN_ROUTER_KWARGS)


@router.post("/{scan_id}/run", response_model=schemas.RunAccepted, status_code=202)
def run(
    body: schemas.RunRequest,
    scan: ScanDep,
    principal: ScanWriteDep,
    db: Session = Depends(get_db),
) -> schemas.RunAccepted:
    """Queue the scan as a background job. Poll the scan / events for progress."""
    body = _require_run_authorization(body, principal.tenant, db)
    _require_runnable(scan, db)
    try:
        admission = workspace.admit_run(
            db, principal.tenant, scan_id=scan.id, source="manual"
        )
    except workspace.RunLimit as exc:
        raise HTTPException(
            status_code=429, detail=f"run limit reached: {exc.reason}"
        ) from exc

    previous_status = scan.status
    scan.status = ScanStatus.queued
    scan.failure_reason = None
    scan.progress = 0
    scan.cancel_requested = False
    # Liveness starts at queue time: a message the broker loses leaves the scan
    # queued with no worker, and the reaper needs a clock to notice that by.
    scan.heartbeat_at = datetime.now(UTC)
    scan.queued_at = datetime.now(UTC)
    scan.claimed_at = None
    if body.requests_per_second is not None:
        scan.requests_per_second = body.requests_per_second
    db.commit()

    # One named argument, not eight positional booleans: the queue message stays
    # readable and survives the option set changing between deploys.
    try:
        options = body.to_options().to_dict()
        if body.config_source is not None:
            # Inside the options dict, not a task argument of its own: a worker
            # that predates it drops the unknown key (RunOptions.from_dict) and
            # runs the scan, where an unknown keyword would fail the task.
            options["config_source"] = body.config_source.model_dump()
        run_scan_task.delay(str(scan.id), options=options)
    except BrokerUnavailable:
        # Nothing was queued; leaving `queued` behind would lock the scan until
        # the reaper's queued window expired. Nor was anything executed, so the
        # admission is withdrawn: an outage must not spend the daily allowance.
        scan.status = previous_status
        if admission is not None:
            db.delete(admission)
        db.commit()
        raise HTTPException(
            status_code=503, detail="scan queue unavailable; try again"
        ) from None
    workspace.record_audit(db, principal, "scan.queued", "scan", scan.id)
    db.commit()
    return schemas.RunAccepted(scan_id=scan.id, status=scan.status)


@router.post("/{scan_id}/cancel", response_model=schemas.ScanSummary)
def cancel(
    scan: ScanDep, principal: ScanWriteDep, db: Session = Depends(get_db)
) -> Scan:
    """Cooperatively cancel a running scan; the runner stops between checks.

    Deliberately not EditableScanDep — cancelling is the one write that *needs*
    the scan to be running.
    """
    if scan.status not in _ACTIVE:
        raise HTTPException(status_code=409, detail="scan is not running")
    scan.cancel_requested = True
    workspace.record_audit(db, principal, "scan.cancelled", "scan", scan.id)
    db.commit()
    return scan


@router.get("/{scan_id}/events", response_model=list[schemas.ScanEventOut])
def list_events(
    scan: LightScanDep,
    limit: int = Query(default=500, ge=1, le=2000),
    offset: int = Query(default=0, ge=0),
    db: Session = Depends(get_db),
):
    """The latest events, returned oldest-first for the activity log.

    The detail read no longer ships every event the scan ever emitted; a
    long-running scan's log is bounded by ``limit``.
    """
    rows = list(
        db.scalars(
            select(ScanEvent)
            .where(ScanEvent.scan_id == scan.id)
            .order_by(ScanEvent.seq.desc())
            .limit(limit)
            .offset(offset)
        )
    )
    return list(reversed(rows))


#: Trace rows per page. Large enough that one request usually covers the log a
#: reviewer scrolls, small enough that the response stays well under a megabyte.
_TRACE_PAGE = 100


@router.get("/{scan_id}/runs", response_model=list[schemas.ScanRunOut])
def list_runs(
    scan: LightScanDep,
    limit: int = Query(default=50, ge=1, le=200),
    offset: int = Query(default=0, ge=0),
    db: Session = Depends(get_db),
):
    """Run history, newest first — re-runs replace live findings, not history.

    ``trace_count`` is computed in SQL; the run's full trace JSONB is not
    loaded just to count it.
    """
    rows = db.execute(
        select(
            ScanRun,
            func.jsonb_array_length(ScanRun.mutations).label("trace_count"),
        )
        .where(ScanRun.scan_id == scan.id)
        .order_by(ScanRun.run_number.desc())
        .limit(limit)
        .offset(offset)
        # The entity would otherwise select the full trace JSONB as well as the
        # array-length count: up to 50 blobs on the wire per default request.
        .options(defer(ScanRun.mutations))
    ).all()
    result = []
    for run, trace_count in rows:
        out = schemas.ScanRunOut.model_validate(run)
        out.trace_count = int(trace_count or 0)
        result.append(out)
    return result


@router.get("/{scan_id}/runs/{run_number}", response_model=schemas.ScanRunOut)
def get_run(
    scan: LightScanDep,
    run_number: int,
    db: Session = Depends(get_db),
) -> schemas.ScanRunOut:
    """One archived run by its number.

    A run number never changes once issued, so a pipeline can name the run it
    gates on (or the baseline it compares against) instead of whichever run
    happens to be the newest by the time it asks.
    """
    row = db.execute(
        select(
            ScanRun,
            func.jsonb_array_length(ScanRun.mutations).label("trace_count"),
        )
        .where(ScanRun.scan_id == scan.id, ScanRun.run_number == run_number)
        .options(defer(ScanRun.mutations))
    ).first()
    if row is None:
        raise HTTPException(status_code=404, detail="no such run for this scan")
    run, trace_count = row
    out = schemas.ScanRunOut.model_validate(run)
    out.trace_count = int(trace_count or 0)
    return out


@router.get("/{scan_id}/runs/{run_number}/trace", response_model=schemas.RunTraceOut)
def run_trace(
    scan: LightScanDep,
    run_number: int,
    offset: int = Query(default=0, ge=0),
    limit: int = Query(default=_TRACE_PAGE, ge=1, le=500),
    db: Session = Depends(get_db),
) -> schemas.RunTraceOut:
    """One page of a run's request/response trace, sliced in SQL."""
    where = (
        ScanRun.scan_id == scan.id,
        ScanRun.run_number == run_number,
    )
    exists = db.scalar(select(ScanRun.id).where(*where).limit(1))
    if exists is None:
        raise HTTPException(status_code=404, detail="no such run for this scan")
    total = db.scalar(
        select(func.jsonb_array_length(ScanRun.mutations)).where(*where)
    )
    end = offset + limit - 1
    rows = (
        db.scalar(
            select(
                func.jsonb_path_query_array(
                    ScanRun.mutations,
                    cast(f"$[{offset} to {end}]", JSONPATH),
                )
            ).where(*where)
        )
        or []
    )
    return schemas.RunTraceOut(
        run_number=run_number,
        total=int(total or 0),
        offset=offset,
        rows=[schemas.MutationRow.model_validate(row) for row in rows],
    )


@router.get("/{scan_id}/diff", response_model=schemas.RunDiffOut)
def diff_runs(
    scan: ScanDep,
    from_run: int | None = None,
    to_run: int | None = None,
) -> schemas.RunDiffOut:
    """What changed between two runs — new, fixed, still there.

    Defaults to the two most recent runs, which is the question people actually
    ask ("what changed since last time"). Needs two runs: a scan with one has
    nothing to compare against, and saying so beats reporting every finding as
    new.
    """
    runs = {r.run_number: r for r in scan.runs}
    if len(runs) < 2:
        raise HTTPException(
            status_code=409, detail="a diff needs two runs of this scan"
        )
    ordered = sorted(runs)
    newer = to_run if to_run is not None else ordered[-1]
    if newer not in runs:
        raise HTTPException(status_code=404, detail=f"run {newer} not found")
    if from_run is not None:
        older = from_run
    else:
        # "The run before this one" — not the second-newest overall, which is
        # the newer run itself once a later run exists.
        earlier = [n for n in ordered if n < newer]
        if not earlier:
            raise HTTPException(
                status_code=409, detail=f"run {newer} is this scan's first run"
            )
        older = earlier[-1]
    if older not in runs:
        raise HTTPException(status_code=404, detail=f"run {older} not found")
    if older >= newer:
        # A diff is directional ("older → newer"); reversing or collapsing the
        # pair would silently invert the added/resolved split, so refuse it.
        raise HTTPException(
            status_code=422, detail="from_run must be older than to_run"
        )

    # A finding only an opt-in pass produces is "not re-tested", not "fixed", when
    # the newer run left that pass off (a manual mutate:true run vs a scheduled
    # read-only one). Runs recorded before options were archived compare as
    # all-off, which is the old behaviour.
    # Likewise a check the newer run's scope left out (a headers-only run after a
    # full one) was never looked at again.
    dropped = dropped_passes(runs[older].options, runs[newer].options)
    older_options, newer_options = runs[older].options, runs[newer].options
    scoped = bool(RunOptions.from_dict(newer_options).checks)
    # What the newer run was asked to do but did not — a tool that never ran, or
    # a request budget spent — is not a retest either.
    gaps = runs[newer].gaps or {}
    # An endpoint the newer run reached but never got a 2xx from (wrong auth,
    # a 404 id, a target that stopped answering) was not tested again, so a
    # finding on it that is now missing is not fixed. Only an explicit
    # ``exercised: false`` counts: rows archived before the field are unknown.
    unexercised = diff.unexercised_operations(
        runs[newer].coverage or [],
        frozenset(str(op.id) for op in scan.operations),
    )
    result = diff.diff_snapshots(
        runs[older].findings_snapshot or [],
        runs[newer].findings_snapshot or [],
        not_retested=(
            (
                lambda row: bool(
                    required_passes(str(row.get("check", "")), row.get("method")) & dropped
                )
                or descoped(str(row.get("check", "")), older_options, newer_options)
                or unperformed(str(row.get("check", "")), gaps)
                or unexercised.hides(str(row.get("check", "")), row.get("operation_id"))
            )
            if dropped or scoped or gaps or unexercised
            else None
        ),
    )
    def _executor_kind(run: ScanRun) -> str:
        return str((run.executor or {}).get("kind") or "server")

    def _config_key(run: ScanRun) -> tuple[str, str] | None:
        # The commit is for a reader; the file's own digest decides "changed".
        src = run.config_source or {}
        return (str(src["path"]), str(src["digest"])) if src.get("digest") else None

    return schemas.RunDiffOut(
        from_run=older,
        to_run=newer,
        options_changed=(
            RunOptions.from_dict(runs[older].options) != RunOptions.from_dict(runs[newer].options)
        ),
        executor_changed=_executor_kind(runs[older]) != _executor_kind(runs[newer]),
        config_changed=_config_key(runs[older]) != _config_key(runs[newer]),
        added=[schemas.RunFindingOut.model_validate(r) for r in result.added],
        resolved=[schemas.RunFindingOut.model_validate(r) for r in result.resolved],
        not_retested=[schemas.RunFindingOut.model_validate(r) for r in result.not_retested],
        unchanged=[schemas.RunFindingOut.model_validate(r) for r in result.unchanged],
        unmatchable=result.unmatchable,
    )


@router.get("/{scan_id}/coverage", response_model=list[schemas.CoverageRow])
def get_coverage(
    scan: ScanDep, run: int | None = Query(default=None, ge=1)
) -> list[schemas.CoverageRow]:
    """Per-endpoint activity for one run (default: the latest): requests, checks, findings.

    Empty until the scan has finished a run. Shows every operation, so a row with
    ``requests: 0`` means the endpoint was in scope but no check exercised it (or
    it was excluded — see ``enabled``). ``run`` names an archived run, so a gate
    reads the run it is judging even after a later one started.
    """
    if run is None:
        chosen = _latest_run(scan)
        if chosen is None:
            return []
    else:
        chosen = next((r for r in scan.runs if r.run_number == run), None)
        if chosen is None:
            raise HTTPException(status_code=404, detail="no such run for this scan")
    return [schemas.CoverageRow.model_validate(row) for row in (chosen.coverage or [])]
