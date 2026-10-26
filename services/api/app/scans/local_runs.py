"""Finishing a local run on the service.

A local run's traffic ends when the runner uploads. What follows happens here:
the AI passes that need no target traffic (adjudication and the security design
review), then the completion a server run gets — triage, the findings snapshot,
episodic memory and notifications — in the same order, so a person's verdict
still outranks the model's and the snapshot carries both.

While the AI works the run is ``analysing`` and the scan stays ``running``, so
nothing can start a new run over it, the CLI waits for the verdicts, and the
reaper fails it if the worker goes quiet.
"""
from __future__ import annotations

import logging
from datetime import UTC, datetime
from typing import Any

from sqlalchemy.orm import Session

from app.engine.run_record import apply_triage, build_findings_snapshot
from app.models.event import ScanEvent
from app.models.scan import Scan, ScanRun, ScanStatus
from app.scans import agent_memory

log = logging.getLogger("runpentests.local_runs")

#: AI passes a local run performs on the service after its upload.
POST_UPLOAD_AI: tuple[str, ...] = ("adjudicate", "security_review")

#: A local run whose results are stored and whose AI passes are still running.
ANALYSING = "analysing"


def wants_analysis(run: ScanRun) -> bool:
    """Whether this run asked for an AI pass that runs after the upload."""
    options: dict[str, Any] = run.options or {}
    return any(bool(options.get(name)) for name in POST_UPLOAD_AI)


def finish_local_run(db: Session, scan: Scan, run: ScanRun) -> None:
    """Complete a local run whose findings are stored (and judged, if asked)."""
    # Last before the snapshot, as on a server run: a remembered human verdict
    # re-applies to this run's findings and outranks the model's.
    apply_triage(scan)
    run.findings_count = len(scan.findings)
    run.findings_snapshot = build_findings_snapshot(scan)
    run.status = "completed"
    run.finished_at = datetime.now(UTC)
    scan.status = ScanStatus.completed
    scan.progress = 100
    # Episodic memory: remember this run's findings (fingerprints are stamped)
    # so the next run against the same target can recall them. Best-effort.
    try:
        agent_memory.remember(db, scan)
    except Exception:  # noqa: BLE001 — a memory failure never fails a run
        log.warning("could not write agent memory for scan %s", scan.id)
    scan.events.append(
        ScanEvent(
            stage="done",
            pct=100,
            message=f"local run complete · {len(scan.findings)} findings",
        )
    )
    # The same outcome events the server lane emits: a local run that found
    # something new (or recovered a previously failed target) notifies too.
    from app.notifications.events import completed_run_events

    completed_run_events(db, scan, run)
