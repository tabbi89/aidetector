"""Broker serialization, independent-session cancellation and duplicate delivery."""
import json
from dataclasses import fields

import pytest
from sqlalchemy import select

from app.models.scan import Operation, Scan, ScanStatus
from app.scans.run_options import RunOptions


def new_scan(worker, *, wait=False):
    with worker.sessions() as db:
        scan = Scan(target_base_url='http://testserver', status=ScanStatus.queued)
        scan.operations = [Operation(method='GET', path='/search',
                                     params=[{'name': 'q', 'in': 'query'}])]
        db.add(scan)
        db.commit()
        sid = str(scan.id)
        worker.scan_ids.append(scan.id)
    if wait:
        worker.store.set(worker.prefix + sid + ':wait', '1', ex=120)
    return sid


def dispatch(worker, sid, options=None):
    return worker.app.send_task(
        'run_scan', args=[sid], kwargs={'options': options}, queue=worker.queue
    )


def test_worker_roundtrips_all_options_and_persists_findings(worker):
    sid = new_scan(worker)
    # Every bool on, and every non-bool field at a valid non-default value, so a
    # field the queue drops cannot pass by decoding back to its default.
    flags = [f.name for f in fields(RunOptions) if f.type in ('bool', bool)]
    assert flags, 'no bool flags found on RunOptions'
    enabled = RunOptions(
        **dict.fromkeys(flags, True),
        adaptive_attempts=2,
        resource_attempts=2,
        predefined_resource_ids={'merchant': 'merchant_1'},
    )
    options = enabled.to_dict()
    assert all(options[name] is True for name in flags)
    result = dispatch(worker, sid, options).get(timeout=25)
    assert result['status'] == 'completed'
    assert result['findings'] > 0
    assert json.loads(worker.store.get(worker.prefix + sid + ':options')) == options
    with worker.sessions() as db:
        scan = db.get(Scan, sid)
        assert scan.progress == 100
        assert scan.findings
        assert len(scan.runs) == 1
        assert scan.runs[0].findings_snapshot
        assert scan.events[-1].stage == 'done'


@pytest.mark.parametrize('cancel', [False, True])
def test_separate_session_cancel_and_duplicate_delivery(worker, cancel):
    # Imports support code, never another test module.
    from integration_tests.support import wait_for

    sid = new_scan(worker, wait=True)
    first = dispatch(worker, sid)
    wait_for(worker.store, worker.prefix + sid + ':entered')
    try:
        duplicate = dispatch(worker, sid).get(timeout=10)
        assert duplicate['duplicate'] is True
        assert duplicate['status'] == 'running'
        with worker.sessions() as db:
            scan = db.execute(select(Scan).where(Scan.id == sid)).scalar_one()
            assert scan.status == ScanStatus.running
            if cancel:
                scan.cancel_requested = True
                db.commit()
    finally:
        worker.store.rpush(worker.prefix + sid + ':release', '1')
    result = first.get(timeout=25)
    expected = 'cancelled' if cancel else 'completed'
    assert result['status'] == expected
    again = dispatch(worker, sid).get(timeout=10)
    assert again['duplicate'] is True
    with worker.sessions() as db:
        scan = db.get(Scan, sid)
        assert len(scan.runs) == 1
        assert scan.status.value == expected
        assert scan.events[-1].stage == ('cancelled' if cancel else 'done')
