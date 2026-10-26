"""The ORM-backed :class:`~app.engine.journal.RunJournal`.

The one place a run's findings and events reach the database. It owns the
``Session``, the ``Scan``, the ``ScanRun`` history row and the ``Redactor``, so
the runner and the engine tier pass one object where they used to thread five.

Redaction happens here rather than in any check, for the same reason
remediation does: the target's own reflected secrets and users' PII must never
reach the database, and that is not a rule seventeen checks should each have to
remember.
"""
from __future__ import annotations

import logging

from sqlalchemy.orm import Session

from app.core.redact import Redactor
from app.engine import run_record
from app.engine.contracts import EngineFinding
from app.engine.journal import describe_failure
from app.engine.probe import HttpProbe, budget_exhausted_message
from app.models.event import ScanEvent
from app.models.finding import Finding
from app.models.scan import Scan, ScanRun, ScanStatus

log = logging.getLogger("runpentests.engine")

#: External tools whose ``<tool>_skipped`` event means a requested pass did not
#: run. Recorded on the run so the diff cannot count its findings as fixed.
ADJUNCT_TOOLS = frozenset({"zap", "kali", "testssl", "sqlmap", "dalfox", "commix", "tplmap"})
class SqlRunJournal:
    """Records a run against the database.

    ``probe`` is bound at construction because the run archive counts the
    requests it made; a journal without one could not close a run.
    """

    def __init__(
        self,
        db: Session,
        scan: Scan,
        run: ScanRun,
        redactor: Redactor,
        probe: HttpProbe,
    ) -> None:
        self._db = db
        self._scan = scan
        self._run = run
        self._redactor = redactor
        self._probe = probe

    # ---- RunJournal ----------------------------------------------------

    @property
    def progress(self) -> int:
        return self._scan.progress

    def event(self, stage: str, pct: int, message: str) -> None:
        self._scan.progress = pct
        self._scan.events.append(ScanEvent(stage=stage, pct=pct, message=message))
        tool = stage.removesuffix("_skipped")
        if tool != stage and tool in ADJUNCT_TOOLS:
            self._gap("not_run", tool)
        self._db.commit()

    def _gap(self, key: str, tool: str | None = None) -> None:
        gaps = dict(self._run.gaps or {})
        if tool is None:
            gaps[key] = True
        else:
            gaps[key] = sorted({*gaps.get(key, []), tool})
        self._run.gaps = gaps  # reassigned: JSONB changes are not tracked in place

    def note_skipped(self, checks: list[str]) -> None:
        """Record the checks this run skipped, so the diff cannot call them fixed."""
        for key in checks:
            self._gap("skipped_checks", key)
        self._db.commit()

    def note_failed(self, checks: list[str]) -> None:
        """Record the checks that did not finish, so the diff cannot call them fixed."""
        for key in checks:
            self._gap("failed_checks", key)
        self._db.commit()

    def note_budget(self) -> None:
        """Say once, as it happens, that the request budget ran out."""
        if not self._probe.refused or (self._run.gaps or {}).get("budget_exhausted"):
            return
        self._gap("budget_exhausted")
        self.event("budget_exhausted", self.progress, budget_exhausted_message(self._probe))

    def record(self, finding: EngineFinding) -> None:
        # The probe goes along so the finding carries the trace rows behind it.
        run_record.append_finding(self._scan, finding, self._redactor, self._probe.mutations)

    def cancelled(self) -> bool:
        # Re-read from the DB: the cancel request comes from the API session
        # while this run is in progress.
        self._db.refresh(self._scan, ["cancel_requested"])
        return self._scan.cancel_requested

    # ---- run lifecycle -------------------------------------------------

    def begin(self) -> None:
        """Open the run: replace live results, keeping the history row."""
        self._scan.status = ScanStatus.running
        self._scan.failure_reason = None
        self._scan.findings.clear()   # re-running replaces prior findings
        self._scan.events.clear()

    def complete(self) -> list[Finding]:
        self.note_budget()
        self._scan.status = ScanStatus.completed
        run_record.finish_run(self._run, "completed", self._scan, self._probe)
        self.event(
            "done",
            100,
            f"complete · {len(self._scan.findings)} findings · "
            f"{self._probe.count} requests",
        )
        self._db.commit()
        return list(self._scan.findings)

    def cancel(self) -> list[Finding]:
        self.note_budget()
        self._scan.status = ScanStatus.cancelled
        run_record.finish_run(self._run, "cancelled", self._scan, self._probe)
        self.event("cancelled", self.progress, "scan cancelled")
        return list(self._scan.findings)

    def fail(self, exc: BaseException | None = None) -> None:
        self._scan.status = ScanStatus.failed
        reason = describe_failure(exc, self._redactor) if exc is not None else None
        self._scan.failure_reason = reason
        run_record.finish_run(self._run, "failed", self._scan, self._probe)
        self.event("error", self.progress, f"scan failed — {reason}" if reason else "scan failed")

    def apply_triage(self) -> None:
        """Re-apply remembered human verdicts. Runs last, after adjudication.

        A person outranks the model on a finding both have judged. Triage is
        re-read from the database first, for the same reason ``cancelled`` is:
        someone may have dismissed a finding while this run was queued.
        """
        try:
            self._db.refresh(self._scan, ["triage"])
        except Exception:  # noqa: BLE001 — a stale read must not fail a scan
            log.warning("could not refresh triage; using the loaded value", exc_info=True)
        carried = run_record.apply_triage(self._scan)
        if carried:
            self.event(
                "triage", self.progress, f"carried {carried} triaged verdicts forward"
            )

    # ---- accessors the adjunct phase still needs ------------------------

    @property
    def scan(self) -> Scan:
        """The scan row.

        The adjunct passes take a ``Scan`` and a ``Session`` directly — they
        drive external tools that manage their own requests, and several read
        persisted findings back to pick their targets. Exposing them here beats
        threading the pair through the runner alongside the journal.
        """
        return self._scan

    @property
    def db(self) -> Session:
        return self._db

    @property
    def run_row(self) -> ScanRun:
        """The history row this run archives into — the AI plan is stored on it."""
        return self._run

    @property
    def redactor(self) -> Redactor:
        return self._redactor
