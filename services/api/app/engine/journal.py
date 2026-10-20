"""What a run needs from persistence, as five verbs.

The engine used to take a SQLAlchemy ``Session`` and ORM rows directly, so the
run-level invariants it exists to guarantee — a cancel lands at a stage
boundary, discovery only runs under ``kali``, triage applies after adjudication
— could only be exercised through a full run against Postgres. In an
environment without a database those tests *skipped* rather than failed, which
left the safety properties the runner is responsible for as the ones least
covered.

This is the seam. ``app/scans/journal.py`` implements it over the ORM;
``tests/fakes.py`` implements it over two lists, which is what makes those
invariants unit-testable.

Deliberately narrow. Adjudication is not behind this port: its work is
genuinely persistence-shaped (a cache query keyed on fingerprint, ledger rows
priced per model), and hiding that behind a generic verb would make the port
bigger than the thing it abstracts. ``ai_phases`` still takes a session, and
should.
"""
from __future__ import annotations

from typing import Any, Protocol

from app.core.redact import Redactor
from app.engine.contracts import EngineFinding


class RunJournal(Protocol):
    """Where a run reports what it found, what it is doing, and whether to stop."""

    @property
    def progress(self) -> int:
        """Percent complete, for events that carry the current value."""
        ...

    def event(self, stage: str, pct: int, message: str) -> None:
        """Record a progress event. Visible to the UI while the scan runs."""
        ...

    def record(self, finding: EngineFinding) -> None:
        """Persist one finding — redacted, fingerprinted and given remediation."""
        ...

    def cancelled(self) -> bool:
        """Whether a cancel has been requested since the last check.

        Read fresh each time: the request arrives from another session while
        this run is in progress.
        """
        ...


class RunRecorder(RunJournal, Protocol):
    """The orchestrator's wider view of the same port.

    The persistence-free port above stays narrow so a list-backed fake stays
    cheap to write. The runner additionally needs the run's collaborators and
    the lifecycle verbs, so they are declared here. The ORM-bound members are
    deliberately typed ``Any``: this module must import without SQLAlchemy (see
    ``tests/test_layering.py``), and the runner already owns that boundary.
    """

    @property
    def db(self) -> Any:
        """The run's session. ``Any`` keeps SQLAlchemy out of this module."""
        ...

    @property
    def scan(self) -> Any:
        """The scan being run, as the ORM row."""
        ...

    @property
    def run_row(self) -> Any:
        """This run's history row."""
        ...

    @property
    def redactor(self) -> Redactor:
        """The secret-aware redactor the run is using."""
        ...

    def note_budget(self) -> None:
        """Record, once, that the request ceiling refused a request."""
        ...

    def note_skipped(self, checks: list[str]) -> None:
        """Record engine checks that declared themselves inapplicable this run."""
        ...

    def note_failed(self, checks: list[str]) -> None:
        """Record engine checks that raised before they finished this run."""
        ...

    def cancel(self) -> list[Any]:
        """Close a cancelled run and return its findings."""
        ...

    def complete(self) -> list[Any]:
        """Close a completed run and return its findings."""
        ...

    def fail(self, exc: BaseException | None = None) -> None:
        """Close a failed run with a redacted reason."""
        ...

    def apply_triage(self) -> None:
        """Re-apply remembered human verdicts after AI adjudication."""
        ...


MAX_FAILURE_REASON = 300


def describe_failure(exc: BaseException, redactor: Redactor | None = None) -> str:
    """A short, redacted reason for a failed run.

    An exception message can carry a target URL, a header or a token, so it goes
    through the run's redactor (or a pattern-only one) before it is stored.
    """
    message = " ".join(str(exc).split())
    text = (redactor or Redactor()).text(message) if message else ""
    reason = f"{type(exc).__name__}: {text}" if text else type(exc).__name__
    return reason[:MAX_FAILURE_REASON]
