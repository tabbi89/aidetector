"""What the scans index shows per row: severity counts, last run, schedule.

The index lists every scan an account has, so its numbers have to come from
grouped queries over the page — and they have to be *live*: a false positive
someone dismissed must not keep a scan looking alarming.
"""
from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta

from sqlalchemy import event
from sqlalchemy.engine import Engine

from app.domain.enums import Severity, Verdict
from app.models.finding import Finding
from app.models.scan import Scan, ScanRun


def _finding(scan: Scan, severity: Severity, verdict: Verdict = Verdict.unreviewed) -> Finding:
    return Finding(
        scan_id=scan.id,
        check="bola",
        severity=severity,
        title=f"{severity.value} finding",
        verdict=verdict,
    )


def _counts(**overrides: int) -> dict[str, int]:
    counts = dict(critical=0, high=0, medium=0, low=0, info=0)
    counts.update(overrides)
    return counts


def _summary(client, scan_id: uuid.UUID) -> dict:
    rows = client.get("/scans").json()
    return next(row for row in rows if row["id"] == str(scan_id))


def _when(iso: str) -> datetime:
    return datetime.fromisoformat(iso.replace("Z", "+00:00"))


def _selects(client, engine: Engine) -> int:
    """How many SELECTs one GET /scans costs."""
    statements: list[str] = []

    def record(conn, cursor, statement, parameters, context, executemany):
        statements.append(statement)

    event.listen(engine, "before_cursor_execute", record)
    try:
        assert client.get("/scans").status_code == 200, "list request failed"
    finally:
        event.remove(engine, "before_cursor_execute", record)
    return sum(1 for s in statements if s.lstrip().upper().startswith("SELECT"))


def test_counts_are_live_findings_by_severity(client, make_scan, db_session):
    scan = make_scan()
    db_session.add_all(
        [
            _finding(scan, Severity.critical),
            _finding(scan, Severity.high),
            _finding(scan, Severity.high, Verdict.dismissed),
            _finding(scan, Severity.info, Verdict.dismissed),
        ]
    )
    db_session.commit()

    assert _summary(client, scan.id)["finding_counts"] == _counts(critical=1, high=1)


def test_counts_are_per_scan(client, make_scan, db_session):
    """One scan's findings must not land on another's row."""
    mine, other = make_scan(), make_scan()
    db_session.add_all(
        [
            _finding(mine, Severity.critical),
            _finding(other, Severity.low),
            _finding(other, Severity.low),
        ]
    )
    db_session.commit()

    assert _summary(client, mine.id)["finding_counts"] == _counts(critical=1)
    assert _summary(client, other.id)["finding_counts"] == _counts(low=2)


def test_a_scan_that_never_ran_has_zeroes_and_no_last_run(client, make_scan):
    scan = make_scan()

    row = _summary(client, scan.id)
    assert row["finding_counts"] == _counts()
    assert row["last_run_at"] is None
    assert row["schedule_minutes"] is None


def test_last_run_is_the_newest_run(client, make_scan, db_session):
    scan = make_scan()
    older = datetime.now(UTC) - timedelta(days=1)
    newer = datetime.now(UTC) - timedelta(minutes=5)
    db_session.add_all(
        [
            ScanRun(
                scan_id=scan.id,
                run_number=1,
                status="completed",
                started_at=older,
                finished_at=older + timedelta(seconds=30),
            ),
            ScanRun(scan_id=scan.id, run_number=2, status="failed", started_at=newer),
        ]
    )
    db_session.commit()

    assert _when(_summary(client, scan.id)["last_run_at"]) == newer


def test_schedule_minutes_are_reported(client, make_scan, db_session):
    scan = make_scan()
    scan.schedule_minutes = 60
    db_session.commit()

    assert _summary(client, scan.id)["schedule_minutes"] == 60


def test_the_page_costs_a_fixed_number_of_queries(client, make_scan, db_engine):
    """The counts and last-run stamps are grouped, not one query per scan.

    A per-scan count still returns the right numbers, so only the query count
    proves it — and it is the property that keeps the index survivable for an
    account with hundreds of scans.
    """
    make_scan()
    few = _selects(client, db_engine)
    for _ in range(4):
        make_scan()

    assert _selects(client, db_engine) == few
