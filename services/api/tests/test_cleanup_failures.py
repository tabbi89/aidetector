"""Faults can happen after the server commits a write."""
from contextlib import contextmanager
from copy import deepcopy

import httpx
import pytest

from app.engine import runner
from app.engine.checks.mass_assignment import MassAssignmentCheck
from app.engine.checks.seeded_bola import SeededBolaCheck
from app.engine.checks.write_oracle import WriteOracleCheck
from app.scans.run_options import RunOptions
from tests.factories import operation, scan_context
from tests.fakes import FakeJournal
from tests.vulnapp import _WIDGETS


def widget_ops(method):
    body = [{'name': 'name', 'in': 'body', 'schema': {'type': 'string'}}]
    return [operation('GET', '/widgets/{id}'),
            operation(method, '/widgets' if method == 'POST' else '/widgets/{id}', params=body),
            operation('DELETE', '/widgets/{id}')]


@pytest.mark.parametrize('check', [WriteOracleCheck, MassAssignmentCheck])
@pytest.mark.parametrize('fault', ['readback', 'write_response'])
def test_updates_restore_even_after_transport_failure(engine_client, check, fault):
    before = deepcopy(_WIDGETS)
    wrote = False
    failed = False

    class Client:
        def request(self, method, path, **kwargs):
            nonlocal wrote, failed
            if method == 'GET' and wrote and not failed and fault == 'readback':
                failed = True
                raise httpx.ReadError('response lost')
            response = engine_client.request(method, path, **kwargs)
            if method == 'PUT':
                wrote = True
                if not failed and fault == 'write_response':
                    failed = True
                    raise httpx.ReadError('write committed; response lost')
            return response

    ctx = scan_context(widget_ops('PUT'), client=Client(), allow_mutation=True)
    check().run(ctx)
    assert failed
    assert _WIDGETS == before
    assert not ctx.cleanup_failures


@pytest.mark.parametrize('check', [WriteOracleCheck, MassAssignmentCheck, SeededBolaCheck])
def test_creates_delete_child_when_readback_raises(engine_client, check):
    before = deepcopy(_WIDGETS)
    wrote = False

    class Client:
        def request(self, method, path, **kwargs):
            nonlocal wrote
            if method == 'GET' and wrote:
                raise httpx.ReadError('readback failed')
            response = engine_client.request(method, path, **kwargs)
            wrote |= method == 'POST'
            return response

    ctx = scan_context(widget_ops('POST'), client=Client(), allow_mutation=True)
    check().run(ctx)
    assert wrote
    assert _WIDGETS == before
    assert not ctx.cleanup_failures


@pytest.mark.parametrize('failure', ['budget', 'http', 'transport'])
def test_failed_cleanup_preserves_finding_and_emits_event(engine_client, monkeypatch, failure):
    puts = 0

    class Client:
        def request(self, method, path, **kwargs):
            nonlocal puts
            if method == 'PUT':
                puts += 1
                if puts == 2:
                    if failure == 'transport':
                        raise httpx.ReadError('sensitive server body')
                    if failure == 'http':
                        return httpx.Response(503)
            return engine_client.request(method, path, **kwargs)

    ctx = scan_context(widget_ops('PUT'), client=Client(), allow_mutation=True,
                       max_requests=3 if failure == 'budget' else 50)
    hits = WriteOracleCheck().run(ctx)
    if failure == 'budget':
        # Complete-case reservations refuse a write when the control, read-back,
        # and restoration cannot all fit. No target state is changed.
        assert hits == []
        assert ctx.probe.count == 0
        assert ctx.probe.test_cases[0]['outcome'] == 'budget_exhausted'
        return
    assert len(hits) == 1
    assert hits[0].evidence['cleanup'] == 'failed'
    assert len(ctx.cleanup_failures) == 1
    assert 'sensitive' not in ctx.cleanup_failures[0]
    assert ctx.probe.count <= (3 if failure == 'budget' else 50)
    journal = FakeJournal()

    @contextmanager
    def opened(*args, **kwargs):
        yield ctx, journal

    monkeypatch.setattr(runner, '_open_run', opened)
    monkeypatch.setattr(runner, '_stages', lambda *args: [runner.Stage('engine', lambda: None)])
    runner.run_scan(None, None, options=RunOptions())
    assert any(stage == 'cleanup_failed' for stage, _, _ in journal.events)


def test_partial_parent_chain_is_cleaned_after_next_create_raises(engine_client):
    from app.engine.sequence import seed_ancestors
    from tests.vulnapp import _PROJECTS

    body = [{'name': 'name', 'in': 'body', 'schema': {'type': 'string'}}]
    child = operation('POST', '/projects/{project_id}/items/{item_id}/notes', params=body)
    ops = [operation('POST', '/projects', params=body),
           operation('DELETE', '/projects/{project_id}'),
           operation('POST', '/projects/{project_id}/items', params=body), child]

    class Client:
        def request(self, method, path, **kwargs):
            if method == 'POST' and path.endswith('/items'):
                raise httpx.ReadError('nested producer unavailable')
            return engine_client.request(method, path, **kwargs)

    ctx = scan_context(ops, client=Client(), allow_mutation=True)
    with pytest.raises(httpx.ReadError):
        seed_ancestors(ctx, child, ctx.highest_priv())
    assert not _PROJECTS


def test_race_cleanup_continues_after_one_delete_fails():
    from app.engine.checks.race_condition import RaceConditionCheck

    attempts = []

    class Client:
        def request(self, method, path, **kwargs):
            attempts.append(path)
            if len(attempts) == 1:
                raise httpx.ReadError('one failed delete')
            return httpx.Response(204)

    ops = widget_ops('POST')
    ctx = scan_context(ops, client=Client(), allow_mutation=True)
    RaceConditionCheck()._cleanup(ctx, ops[0], ['1', '2', '3'], ctx.highest_priv())
    assert set(attempts) == {'/widgets/1', '/widgets/2', '/widgets/3'}
    assert len(ctx.cleanup_failures) == 1


@pytest.mark.parametrize('check', [WriteOracleCheck, MassAssignmentCheck, SeededBolaCheck])
def test_lost_create_response_reports_unknown_state(engine_client, check):
    class Client:
        def request(self, method, path, **kwargs):
            response = engine_client.request(method, path, **kwargs)
            if method == 'POST':
                raise httpx.ReadError('committed without response')
            return response

    ctx = scan_context(widget_ops('POST'), client=Client(), allow_mutation=True)
    check().run(ctx)
    assert any('create response lost; target state unknown' in f for f in ctx.cleanup_failures)


def test_cleanup_as_falls_back_and_records_one_failure_only_when_all_fail():
    from types import SimpleNamespace

    from app.engine.base import HttpProbe, TargetOperation
    from app.engine.cleanup import cleanup_as
    from tests import factories

    answers = {"creator-token": 403, "owner-token": 204}

    class Client:
        def request(self, method, url, **kwargs):
            status = answers.get(kwargs["headers"].get("Authorization"), 500)
            return SimpleNamespace(status_code=status, headers={}, text="", content=b"")

    op = TargetOperation(id="d", method="DELETE", path="/things/{id}", params=[])
    creator, owner = factories.credential("creator", "user"), factories.credential("owner", "admin")
    ctx = factories.scan_context([op], probe=HttpProbe(Client(), max_requests=10))
    assert cleanup_as(ctx, op, "/things/1", [creator, owner]) is True
    assert ctx.cleanup_failures == []

    answers["owner-token"] = 403
    assert cleanup_as(ctx, op, "/things/1", [creator, owner]) is False
    assert ctx.cleanup_failures == ["DELETE /things/{id}: HTTP 403, HTTP 403"]
