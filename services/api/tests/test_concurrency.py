"""Force overlapping work at the actual probe and runner boundaries."""
from concurrent.futures import ThreadPoolExecutor
from threading import Barrier, Lock, get_ident
from types import SimpleNamespace

import httpx

from app.engine import execution, runner
from app.engine.base import HttpProbe
from app.engine.checks.misconfig import sweep_headers
from tests.factories import operation, scan_context
from tests.fakes import FakeJournal


def test_concurrent_budget_and_thread_local_attribution():
    workers = 12
    barrier = Barrier(workers, timeout=5)
    sent = []
    lock = Lock()

    class Client:
        def request(self, method, path, **kwargs):
            with lock:
                sent.append((path, get_ident()))
            return httpx.Response(200, json={})

    ops = [operation('GET', f'/items/{i}') for i in range(workers)]
    probe = HttpProbe(Client(), max_requests=37, operations=ops)

    def exercise(i):
        probe.check_context = f'check-{i}'
        barrier.wait()
        return sum(probe.send('GET', ops[i].path) is not None for _ in range(20))

    with ThreadPoolExecutor(max_workers=workers) as pool:
        accepted = list(pool.map(exercise, range(workers)))
    assert sum(accepted) == len(sent) == probe.count == 37
    for i, count in enumerate(accepted):
        assert probe.coverage.get(ops[i].id, {}) == (
            {f'check-{i}': count} if count else {}
        )
        assert count <= 10  # independent per-operation cap


def test_header_sweep_is_single_flight():
    barrier = Barrier(3, timeout=5)
    calls = []

    class Client:
        def request(self, method, path, **kwargs):
            calls.append(path)
            return httpx.Response(200, json={})

    ops = [operation('GET', '/one'), operation('HEAD', '/two')]
    ctx = scan_context(ops, client=Client())

    def sweep(_):
        barrier.wait()
        return sweep_headers(ctx)

    with ThreadPoolExecutor(max_workers=3) as pool:
        results = list(pool.map(sweep, range(3)))
    assert len(calls) == 2
    assert all(result is results[0] for result in results)


def test_runner_finishes_parallel_reads_before_serial_writes(monkeypatch):
    barrier = Barrier(2, timeout=5)
    finished = set()
    active = set()
    lock = Lock()
    caller = get_ident()
    writes = []

    def read(ctx, key):
        with lock:
            active.add(key)
        barrier.wait()
        with lock:
            active.remove(key)
            finished.add(key)
        return []

    def write(ctx, key):
        with lock:
            assert finished == {'read-a', 'read-b'}
            assert not active
            active.add(key)
        assert get_ident() == caller
        writes.append(key)
        with lock:
            active.remove(key)
        return []

    checks = [
        SimpleNamespace(key=key, mutates=mutates,
                        run=lambda ctx, key=key, fn=fn: fn(ctx, key))
        for key, mutates, fn in [
            ('write-a', True, write), ('read-a', False, read),
            ('write-b', True, write), ('read-b', False, read),
        ]
    ]
    monkeypatch.setattr(execution, 'ALL_CHECKS', checks)
    runner._run_engine_checks(scan_context([], allow_mutation=True), FakeJournal(), max_workers=2)
    assert writes == ['write-a', 'write-b']
