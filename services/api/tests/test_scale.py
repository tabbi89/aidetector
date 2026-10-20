"""Scale guards: bounded list reads and correct page order."""
from __future__ import annotations

from datetime import UTC, datetime, timedelta

from app.domain.enums import Severity
from app.models.event import ScanEvent
from app.models.finding import Finding


def test_scan_list_honours_limit_and_offset(client, db_session, make_scan):
    scans = []
    base = datetime.now(UTC)
    for index in range(3):
        scan = make_scan()
        scan.created_at = base - timedelta(minutes=index)
        db_session.commit()
        scans.append(scan)

    first = client.get("/scans?limit=2&offset=0").json()
    assert [row["id"] for row in first] == [str(scans[0].id), str(scans[1].id)]

    second = client.get("/scans?limit=2&offset=2").json()
    assert [row["id"] for row in second] == [str(scans[2].id)]


def test_events_are_bounded_and_oldest_first(client, db_session, make_scan):
    scan = make_scan()
    base = datetime.now(UTC)
    for index in range(3):
        db_session.add(
            ScanEvent(
                scan_id=scan.id,
                stage=f"stage-{index}",
                pct=index,
                message=f"event {index}",
                created_at=base + timedelta(seconds=index),
            )
        )
    db_session.commit()

    rows = client.get(f"/scans/{scan.id}/events?limit=2").json()

    assert [row["stage"] for row in rows] == ["stage-1", "stage-2"]


def test_findings_honour_limit_and_offset(client, db_session, make_scan):
    scan = make_scan()
    for index in range(3):
        db_session.add(
            Finding(
                scan_id=scan.id,
                check="bola",
                severity=Severity.medium,
                title=f"finding {index}",
                fingerprint=f"fp-{index}",
            )
        )
    db_session.commit()

    first = client.get(f"/scans/{scan.id}/findings?limit=2&offset=0")
    second = client.get(f"/scans/{scan.id}/findings?limit=2&offset=2")

    assert first.status_code == 200
    assert len(first.json()) == 2
    assert len(second.json()) == 1
