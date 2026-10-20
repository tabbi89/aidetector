"""The adjunct phase on the server: the DB-free core plus database persistence.

The execution core — the pass lifecycle, the wall-clock sequencer and the
individual passes — lives in :mod:`app.engine.adjunct_run` and depends on no
model, so the local runner reuses it. This module is the server's lane: it
records findings into the scan and commits, through :class:`_DbSink`, and keeps
the ``(db, scan, emit, …)`` entry points the worker and the tests call.
"""
from __future__ import annotations

from collections.abc import Callable, Iterator, Sequence
from dataclasses import dataclass
from typing import Any

from sqlalchemy.orm import Session

from app.core.redact import Redactor
from app.engine import adjunct_run
from app.engine.adjunct_run import (
    KALI_PASSES,
    AdjunctUnavailable,
    Emit,
    Produce,
    _reported,
)
from app.engine.base import EngineFinding
from app.engine.operations import TargetOperation
from app.models.scan import Scan

__all__ = [
    "KALI_PASSES",
    "AdjunctPhase",
    "AdjunctUnavailable",
    "Emit",
    "Produce",
    "append_findings",
    "confirm_passes",
    "require_binary",
    "run_adjunct",
    "run_kali",
    "run_testssl",
    "run_zap",
    "_reported",
]


def append_findings(
    scan: Scan, efs: Sequence[EngineFinding], redactor: Redactor | None = None
) -> None:
    """Append engine findings to the scan, redacting secrets/PII first."""
    from app.engine.run_record import append_finding

    for ef in efs:
        append_finding(scan, ef, redactor)


@dataclass
class _DbSink:
    """An :class:`adjunct_run.AdjunctSink` backed by the scan and its session.

    ``record`` appends the findings and commits, exactly as the passes did
    before the core was split out, so the server's behaviour is unchanged.
    ``db`` is optional for the sequencer and the binary check, which never
    record.
    """

    db: Session | None
    scan: Scan
    emit: Emit
    redactor: Redactor | None = None

    @property
    def progress(self) -> int:
        return self.scan.progress

    @property
    def target_base_url(self) -> str:
        return self.scan.target_base_url

    @property
    def operations(self) -> Sequence[TargetOperation]:
        return self.scan.operations  # type: ignore[return-value]

    @property
    def findings(self) -> Sequence[Any]:
        return self.scan.findings

    def record(self, findings: Sequence[EngineFinding]) -> None:
        append_findings(self.scan, findings, self.redactor)
        if self.db is not None:
            self.db.commit()

    def event(self, stage: str, pct: int, message: str) -> None:
        self.emit(stage, pct, message)


def run_adjunct(
    db: Session,
    scan: Scan,
    emit: Emit,
    *,
    tool: str,
    start_message: str,
    produce: Produce,
    redactor: Redactor | None = None,
    done_message: Callable[[int], str] | None = None,
) -> None:
    adjunct_run.run_adjunct(
        _DbSink(db, scan, emit, redactor),
        tool=tool,
        start_message=start_message,
        produce=produce,
        done_message=done_message,
    )


def require_binary(scan: Scan, emit: Emit, tool: str, bin_path: str) -> bool:
    return adjunct_run.require_binary(_DbSink(None, scan, emit), tool, bin_path)


def run_zap(
    db: Session,
    scan: Scan,
    emit: Emit,
    redactor: Redactor | None = None,
    spec_urls: Sequence[str] = (),
) -> None:
    adjunct_run.run_zap(_DbSink(db, scan, emit, redactor), spec_urls=spec_urls)


def run_testssl(db: Session, scan: Scan, emit: Emit, redactor: Redactor | None = None) -> None:
    adjunct_run.run_testssl(_DbSink(db, scan, emit, redactor))


def run_kali(
    db: Session,
    scan: Scan,
    emit: Emit,
    redactor: Redactor | None = None,
    spec_urls: Sequence[str] = (),
    rate_limit: int = 10,
    *,
    should_stop: Callable[[], bool] | None = None,
) -> None:
    adjunct_run.run_kali(
        _DbSink(db, scan, emit, redactor),
        spec_urls=spec_urls,
        rate_limit=rate_limit,
        should_stop=should_stop,
    )


def confirm_passes(
    db: Session,
    scan: Scan,
    emit: Emit,
    *,
    deadline: float | None,
    should_stop: Callable[[], bool],
    redactor: Redactor | None = None,
    independent_targets: list[dict[str, Any]] | None = None,
) -> Iterator[tuple[str, Callable[[], None]]]:
    yield from adjunct_run.confirm_passes(
        _DbSink(db, scan, emit, redactor),
        deadline=deadline,
        should_stop=should_stop,
        independent_targets=independent_targets,
    )


class AdjunctPhase:
    """Server-lane :class:`adjunct_run.AdjunctPhase`, built from the scan."""

    def __init__(
        self,
        scan: Scan,
        emit: Emit,
        *,
        budget_seconds: float,
        cancelled: Callable[[], bool],
        drift: Callable[[], str | None] | None = None,
    ) -> None:
        self._inner = adjunct_run.AdjunctPhase(
            _DbSink(None, scan, emit),
            budget_seconds=budget_seconds,
            cancelled=cancelled,
            drift=drift,
        )

    @property
    def deadline(self) -> float:
        return self._inner.deadline

    @property
    def expired(self) -> bool:
        return self._inner.expired

    def add(self, name: str, fn: Callable[[], None]) -> None:
        self._inner.add(name, fn)

    def run(self) -> bool:
        return self._inner.run()
