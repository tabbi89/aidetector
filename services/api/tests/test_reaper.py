"""Recovering scans whose worker is gone: the heartbeat, the reaper, the queue stamp.

A crashed worker used to leave a scan ``running`` forever. Every guard refuses to
touch an active scan — edit, delete, re-run, the scheduler — and nothing else
would ever change it, so one OOM-killed process locked a scan for good.
"""
from __future__ import annotations

import time
from datetime import UTC, datetime, timedelta
from unittest.mock import Mock

import pytest

from app.models.scan import Scan, ScanRun, ScanStatus
from app.scans.reaper import StaleLimits, reap_stale

LIMITS = StaleLimits(running_seconds=300, queued_seconds=3600)


def _age(scan: Scan, db, *, status: ScanStatus, seconds_ago: int | None) -> Scan:
    scan.status = status
    scan.heartbeat_at = (
        None if seconds_ago is None else datetime.now(UTC) - timedelta(seconds=seconds_ago)
    )
    db.commit()
    return scan


def _recent(stamp: datetime | None) -> bool:
    return stamp is not None and stamp > datetime.now(UTC) - timedelta(seconds=60)


# ---- the reaper -----------------------------------------------------------------

def test_a_running_scan_whose_worker_went_quiet_is_failed_and_says_why(db_session, make_scan):
    scan = make_scan()
    scan.runs.append(ScanRun(run_number=1, status="running"))
    scan.cancel_requested = True
    _age(scan, db_session, status=ScanStatus.running, seconds_ago=600)

    assert reap_stale(db_session, datetime.now(UTC), LIMITS) == [str(scan.id)]

    db_session.refresh(scan)
    assert scan.status == ScanStatus.failed
    assert scan.cancel_requested is False
    assert scan.runs[0].status == "failed" and scan.runs[0].finished_at is not None
    assert scan.events[-1].stage == "worker_lost"
    # The scan itself says why, so the page need not dig through the log.
    assert scan.failure_reason == scan.events[-1].message


def test_a_stale_local_run_is_failed_its_token_cleared_and_named(db_session, make_scan):
    scan = make_scan()
    scan.runs.append(
        ScanRun(
            run_number=1,
            status="running",
            executor={"kind": "local_runner", "max_requests": 500},
            run_token_hash="a" * 64,
        )
    )
    _age(scan, db_session, status=ScanStatus.running, seconds_ago=600)

    assert reap_stale(db_session, datetime.now(UTC), LIMITS) == [str(scan.id)]

    db_session.refresh(scan)
    assert scan.status == ScanStatus.failed
    assert scan.runs[0].status == "failed"
    # The dead run's token must not authenticate a late upload.
    assert scan.runs[0].run_token_hash is None
    # The message names the local runner, not "the worker".
    assert "the local runner" in scan.events[-1].message


def test_a_running_scan_that_never_stamped_is_reaped(db_session, make_scan):
    scan = _age(make_scan(), db_session, status=ScanStatus.running, seconds_ago=None)
    assert reap_stale(db_session, datetime.now(UTC), LIMITS) == [str(scan.id)]


def test_a_live_running_scan_is_left_alone(db_session, make_scan):
    scan = _age(make_scan(), db_session, status=ScanStatus.running, seconds_ago=30)
    assert reap_stale(db_session, datetime.now(UTC), LIMITS) == []
    db_session.refresh(scan)
    assert scan.status == ScanStatus.running


def test_a_queued_scan_no_worker_claimed_is_failed(db_session, make_scan):
    scan = _age(make_scan(), db_session, status=ScanStatus.queued, seconds_ago=7200)
    assert reap_stale(db_session, datetime.now(UTC), LIMITS) == [str(scan.id)]
    db_session.refresh(scan)
    assert scan.status == ScanStatus.failed
    assert scan.events[-1].stage == "queue_lost"


def test_a_scan_waiting_in_a_busy_queue_is_not_reaped(db_session, make_scan):
    """A backlog is not a lost message: queued gets a far longer window than running."""
    _age(make_scan(), db_session, status=ScanStatus.queued, seconds_ago=600)
    assert reap_stale(db_session, datetime.now(UTC), LIMITS) == []


@pytest.mark.parametrize(
    "status",
    [ScanStatus.draft, ScanStatus.completed, ScanStatus.failed, ScanStatus.cancelled],
)
def test_inactive_scans_are_never_reaped(db_session, make_scan, status):
    _age(make_scan(), db_session, status=status, seconds_ago=99_999)
    assert reap_stale(db_session, datetime.now(UTC), LIMITS) == []


def test_a_reaped_scan_is_no_longer_locked(client, db_session, make_scan):
    scan = _age(make_scan(), db_session, status=ScanStatus.running, seconds_ago=600)
    assert client.delete(f"/scans/{scan.id}").status_code == 409

    reap_stale(db_session, datetime.now(UTC), LIMITS)
    assert client.delete(f"/scans/{scan.id}").status_code == 200


# ---- the heartbeat --------------------------------------------------------------

def test_a_heartbeat_stamps_only_a_running_scan(db_session, make_scan):
    from app.workers.tasks import stamp_heartbeat

    running = _age(make_scan(), db_session, status=ScanStatus.running, seconds_ago=600)
    done = _age(make_scan(), db_session, status=ScanStatus.completed, seconds_ago=600)
    before = done.heartbeat_at

    stamp_heartbeat(running.id)
    stamp_heartbeat(done.id)

    db_session.refresh(running)
    db_session.refresh(done)
    assert _recent(running.heartbeat_at)
    assert done.heartbeat_at == before


def test_the_heartbeat_thread_keeps_a_quiet_run_from_being_reaped(db_session, make_scan):
    """A long adjunct or AI stage emits no events; the timer is what proves life."""
    from app.workers.tasks import Heartbeat

    scan = _age(make_scan(), db_session, status=ScanStatus.running, seconds_ago=600)
    with Heartbeat(scan.id, interval=0.05):
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline:
            db_session.refresh(scan)
            if _recent(scan.heartbeat_at):
                break
            time.sleep(0.05)
    assert _recent(scan.heartbeat_at)
    assert reap_stale(db_session, datetime.now(UTC), LIMITS) == []


def test_claiming_a_queued_scan_starts_its_heartbeat(db_session, make_scan, monkeypatch):
    from app.workers import tasks

    scan = _age(make_scan(), db_session, status=ScanStatus.queued, seconds_ago=7200)
    seen: dict = {}

    def fake_run(db, claimed, *, options):
        seen["status"], seen["heartbeat_at"] = claimed.status, claimed.heartbeat_at
        return []

    monkeypatch.setattr(tasks, "run_scan", fake_run)
    assert tasks.run_scan_task(str(scan.id))["findings"] == 0
    assert seen["status"] == ScanStatus.running
    assert _recent(seen["heartbeat_at"])


# ---- the run route --------------------------------------------------------------

def test_queueing_a_run_starts_the_reaper_clock(client, scan_with_spec, db_session, monkeypatch):
    from app.workers import tasks

    monkeypatch.setattr(tasks.run_scan_task, "delay", Mock())
    sid = scan_with_spec()
    assert client.post(f"/scans/{sid}/run", json={"authorized": True}).status_code == 202

    scan = db_session.get(Scan, sid)
    assert scan.status == ScanStatus.queued
    assert _recent(scan.heartbeat_at)


def test_a_broker_outage_does_not_leave_the_scan_locked_as_queued(
    client, scan_with_spec, db_session, monkeypatch
):
    from kombu.exceptions import OperationalError

    from app.workers import tasks

    monkeypatch.setattr(
        tasks.run_scan_task, "delay", Mock(side_effect=OperationalError("broker down"))
    )
    sid = scan_with_spec()
    r = client.post(f"/scans/{sid}/run", json={"authorized": True})
    assert r.status_code == 503

    assert db_session.get(Scan, sid).status == ScanStatus.draft
    assert client.delete(f"/scans/{sid}").status_code == 200
