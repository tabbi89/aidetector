"""Schema context is local-only: read on the CLI machine, reused by the scan.

The server never holds a database password or opens a database socket. A local
run reads the schema with the bounded adapter (bound here to a fake catalog),
uploads the structure with its results, and every later consumer on the scan
reads the newest available snapshot.
"""
from __future__ import annotations

import io
import json
from types import SimpleNamespace
from unittest.mock import AsyncMock, Mock

import httpx
import pytest

from app.core.config import settings
from app.core.redact import Redactor
from app.db_schema import postgres
from app.db_schema.contracts import SchemaUnavailable, accept_upload
from app.engine.runner import run_scan
from app.engine.transport import AsyncHttpClientBridge
from app.runner import main as runner
from app.runner.main import EXIT_OK, ServerLink, execute
from app.runner.schema import read_local_schema
from app.scans.run_options import RunOptions

PASSWORD = "schema-password-sentinel"
SECRETS = {"alice": {"secret": "alice-token"}, "admin": {"secret": "admin-token"}}
BLOCK = {
    "host": "host.docker.internal",
    "port": 5432,
    "database": "app",
    "username": "schema_reader",
    "password": PASSWORD,
    "sslmode": "disable",
    "tables": [{"schema_name": "public", "table_name": "widgets"}],
}
TABLES = [
    {
        "schema_name": "public",
        "table_name": "widgets",
        "columns": [
            {"name": "id", "type_name": "int4", "nullable": False, "max_length": None},
            {"name": "title", "type_name": "varchar", "nullable": False, "max_length": 40},
        ],
        "constraints": [
            {"kind": "p", "columns": ["id"], "ref_schema": None, "ref_table": None,
             "ref_columns": []},
        ],
    }
]
SPEC = {
    "openapi": "3.0.3",
    "paths": {"/widgets": {"get": {"responses": {"200": {"description": "ok"}}}}},
}


@pytest.fixture(autouse=True)
def _enabled(monkeypatch):
    monkeypatch.setattr(settings, "local_runner_enabled", True)
    monkeypatch.setattr(settings, "premium_tenants", "*")


@pytest.fixture
def bridges(monkeypatch):
    from tests.vulnapp import vulnapp

    def factory(base_url, **kwargs):
        return AsyncHttpClientBridge(
            base_url,
            **{
                **kwargs,
                "requests_per_second": 10000,
                # Replaces the pinned network transport: the target is in-process.
                "transport": httpx.ASGITransport(app=vulnapp),
            },
        )

    monkeypatch.setattr(runner, "AsyncHttpClientBridge", factory)


@pytest.fixture
def catalog(monkeypatch):
    """The adapter, answered by a fake catalog: no database socket is opened."""
    read = AsyncMock(return_value={"tables": TABLES, "warnings": []})
    monkeypatch.setattr(postgres, "read_schema", read)
    return read


def _claim(client, scan, **flags):
    r = client.post(f"/scans/{scan.id}/local-runs", json={"authorized": True, **flags})
    assert r.status_code == 201, r.text
    return r.json()


def _go(client, claim, schema=None):
    cfg = {"server": "http://testserver", "run": claim, "secrets": SECRETS,
           "runner_version": "t1"}
    if schema is not None:
        cfg["schema"] = schema
    link = ServerLink("http://testserver", claim["run_id"], claim["token"], client=client)
    out = io.StringIO()
    return execute(cfg, link, out=out), out.getvalue()


def _context(client, scan):
    r = client.get(f"/scans/{scan.id}/schema-context")
    assert r.status_code == 200, r.text
    return r.json()


# --- the runner reads it, on the CLI machine ---------------------------------


def test_a_local_run_reads_the_schema_and_the_scan_keeps_its_structure(
    client, make_scan, bridges, catalog
):
    scan = make_scan(target_base_url="http://127.0.0.1")
    code, log = _go(client, _claim(client, scan), schema=BLOCK)
    assert code == EXIT_OK, log

    # The adapter got the CA path the CLI mounted (none here) and every table.
    kwargs = catalog.call_args.kwargs
    assert kwargs["sslrootcert"] is None
    assert [t.table_name for t in catalog.call_args.args[2]] == ["widgets"]

    context = _context(client, scan)
    assert context["latest"]["status"] == "available" and context["latest"]["run_number"] == 1
    assert context["snapshot"]["tables"] == [{
        "schema_name": "public", "table_name": "widgets",
        "column_count": 2, "constraint_count": 1,
    }]
    events = client.get(f"/scans/{scan.id}/events").json()
    assert any(e["stage"] == "schema_context" for e in events)


def test_the_database_password_never_reaches_the_server(client, make_scan, bridges, catalog):
    scan = make_scan(target_base_url="http://127.0.0.1")
    code, log = _go(client, _claim(client, scan), schema=BLOCK)
    assert code == EXIT_OK, log
    everything = json.dumps({
        "scan": client.get(f"/scans/{scan.id}").json(),
        "events": client.get(f"/scans/{scan.id}/events").json(),
        "runs": client.get(f"/scans/{scan.id}/runs").json(),
        "context": _context(client, scan),
        "stored": [run.schema_context for run in scan.runs],
    })
    assert PASSWORD not in everything
    assert PASSWORD not in log
    assert "host.docker.internal" not in everything  # nor where the database lives


@pytest.mark.parametrize(
    ("block", "failure", "reason"),
    [
        ({**BLOCK, "password": ""}, None, "password_missing"),
        ({**BLOCK, "sslmode": "prefer"}, None, "invalid_config"),
        (BLOCK, SchemaUnavailable("connection_unavailable"), "connection_unavailable"),
        (BLOCK, RuntimeError(PASSWORD), "unavailable"),
    ],
)
def test_a_failed_read_is_a_named_reason_never_a_failed_run(
    client, make_scan, bridges, monkeypatch, block, failure, reason
):
    monkeypatch.setattr(postgres, "read_schema", AsyncMock(side_effect=failure))
    scan = make_scan(target_base_url="http://127.0.0.1")
    code, log = _go(client, _claim(client, scan), schema=block)
    assert code == EXIT_OK, log
    assert client.get(f"/scans/{scan.id}").json()["status"] == "completed"
    context = _context(client, scan)
    assert context["latest"] == {**context["latest"], "status": "unavailable", "reason": reason}
    assert context["snapshot"] is None
    events = client.get(f"/scans/{scan.id}/events").json()
    assert any(e["stage"] == "schema_context_unavailable" for e in events)
    assert PASSWORD not in json.dumps(events) and PASSWORD not in log


def test_a_run_without_a_schema_block_records_nothing(client, make_scan, bridges, catalog):
    scan = make_scan(target_base_url="http://127.0.0.1")
    code, log = _go(client, _claim(client, scan))
    assert code == EXIT_OK, log
    catalog.assert_not_called()
    assert _context(client, scan) == {"latest": None, "snapshot": None}


def test_the_password_is_masked_before_the_read_can_fail(monkeypatch):
    monkeypatch.setattr(postgres, "read_schema", AsyncMock(side_effect=RuntimeError("boom")))
    redactor = Redactor()
    record, context = read_local_schema(BLOCK, redactor)
    assert context is None and record == {"status": "unavailable", "reason": "unavailable"}
    assert PASSWORD not in redactor.text(f"failed with {PASSWORD}")


# --- the server accepts structure only ----------------------------------------


@pytest.mark.parametrize(
    "raw",
    [
        "not an object",
        {"status": "available", "tables": []},
        {"status": "available", "tables": TABLES, "password": PASSWORD},
        {"status": "available", "tables": [{**TABLES[0], "rows": [["secret"]]}]},
        {"status": "unavailable", "reason": "Traceback: password=x"},
        {"status": "available", "tables": TABLES * 51},
    ],
)
def test_an_unacceptable_upload_is_recorded_not_stored(raw):
    stored = accept_upload(raw, "2026-10-18T00:00:00+00:00")
    assert stored["status"] == "unavailable" and stored["reason"] == "invalid_upload"
    assert stored["tables"] == [] and PASSWORD not in json.dumps(stored)


def test_a_bad_snapshot_never_costs_the_run_its_findings(client, make_scan):
    scan = make_scan(target_base_url="http://127.0.0.1")
    claim = _claim(client, scan)
    r = client.post(
        f"/runner/runs/{claim['run_id']}/complete",
        json={"requests": 1, "schema_context": {"status": "available", "tables": "x"}},
        headers={"X-Run-Token": claim["token"]},
    )
    assert r.status_code == 200, r.text
    assert client.get(f"/scans/{scan.id}").json()["status"] == "completed"
    assert _context(client, scan)["latest"]["reason"] == "invalid_upload"


# --- the scan reuses the newest snapshot --------------------------------------


def _local_run_with_snapshot(client, scan, bridges_ok=True):
    code, log = _go(client, _claim(client, scan), schema=BLOCK)
    assert code == EXIT_OK, log


def test_a_server_run_reuses_the_newest_local_snapshot(
    client, db_session, make_scan, bridges, catalog, engine_client
):
    scan = make_scan(target_base_url="http://127.0.0.1")
    scan.spec_text = json.dumps(SPEC)
    db_session.commit()
    _local_run_with_snapshot(client, scan)

    planner = SimpleNamespace(review_security=Mock(return_value=({"suggestions": []}, [])))
    db_session.expire_all()
    run_scan(db_session, scan, client=engine_client, planner=planner,
             options=RunOptions(security_review=True))
    payload = planner.review_security.call_args.args[0]
    assert payload["database"]["tables"][0]["table_name"] == "widgets"
    assert scan.runs[-1].security_review["schema_status"] == "available"
    assert any(
        e.stage == "schema_context" and "local run #1" in e.message for e in scan.events
    )


def test_a_server_run_without_a_snapshot_says_so(db_session, make_scan, engine_client):
    scan = make_scan()
    scan.spec_text = json.dumps(SPEC)
    db_session.commit()
    planner = SimpleNamespace(review_security=Mock(return_value=({"suggestions": []}, [])))
    run_scan(db_session, scan, client=engine_client, planner=planner,
             options=RunOptions(security_review=True))
    assert planner.review_security.call_args.args[0]["database"] is None
    assert scan.runs[-1].security_review["schema_status"] == "not_provided"
    assert any(e.stage == "schema_context_unavailable" for e in scan.events)


def test_a_failed_later_read_keeps_the_earlier_snapshot_in_use(
    client, make_scan, bridges, catalog, monkeypatch
):
    scan = make_scan(target_base_url="http://127.0.0.1")
    _local_run_with_snapshot(client, scan)
    monkeypatch.setattr(
        postgres, "read_schema", AsyncMock(side_effect=SchemaUnavailable("table_unavailable"))
    )
    code, log = _go(client, _claim(client, scan), schema=BLOCK)
    assert code == EXIT_OK, log
    context = _context(client, scan)
    assert context["latest"]["run_number"] == 2 and context["latest"]["status"] == "unavailable"
    assert context["snapshot"]["run_number"] == 1


def test_forgetting_clears_every_snapshot_but_not_while_running(
    client, make_scan, bridges, catalog
):
    scan = make_scan(target_base_url="http://127.0.0.1")
    _local_run_with_snapshot(client, scan)
    claim = _claim(client, scan)
    assert client.delete(f"/scans/{scan.id}/schema-context").status_code == 409
    code, log = _go(client, claim, schema=BLOCK)
    assert code == EXIT_OK, log
    r = client.delete(f"/scans/{scan.id}/schema-context")
    assert r.status_code == 200 and r.json() == {"removed": 2}
    assert _context(client, scan) == {"latest": None, "snapshot": None}


# --- a local run may ask for the security review ------------------------------


def test_a_local_run_gets_its_security_review_over_its_own_snapshot(
    client, db_session, make_scan, bridges, catalog, monkeypatch
):
    reviewed: list[dict] = []

    class FakeOpus:
        def review_security(self, payload):
            reviewed.append(payload)
            return {"suggestions": []}, []

    monkeypatch.setattr("app.ai.planner.OpusPlanner", FakeOpus)
    scan = make_scan(target_base_url="http://127.0.0.1")
    scan.spec_text = json.dumps(SPEC)
    db_session.commit()
    claim = _claim(client, scan, security_review=True)  # no longer refused
    code, log = _go(client, claim, schema=BLOCK)
    assert code == EXIT_OK, log

    # Celery is eager in tests: the review ran right after the upload.
    assert reviewed and reviewed[0]["database"]["tables"][0]["table_name"] == "widgets"
    run = client.get(f"/scans/{scan.id}/runs").json()[0]
    assert run["security_review"]["status"] == "completed"
    assert run["security_review"]["schema_status"] == "available"
    # Findings were the engine's alone; the review never adds one.
    assert not any(
        f["check"] == "security_review" for f in client.get(f"/scans/{scan.id}/findings").json()
    )



# --- the architect review's fixes ---------------------------------------------


def test_a_non_object_snapshot_is_recorded_not_refused(client, make_scan):
    scan = make_scan(target_base_url="http://127.0.0.1")
    claim = _claim(client, scan)
    r = client.post(
        f"/runner/runs/{claim['run_id']}/complete",
        json={"requests": 1, "schema_context": ["not", "an", "object"]},
        headers={"X-Run-Token": claim["token"]},
    )
    assert r.status_code == 200, r.text
    assert _context(client, scan)["latest"]["reason"] == "invalid_upload"


def test_an_unqueueable_review_settles_unavailable_and_keeps_the_upload(
    client, make_scan, monkeypatch
):
    from app.workers import tasks

    monkeypatch.setattr(
        tasks.analyze_local_run, "delay", Mock(side_effect=ConnectionError("broker down"))
    )
    scan = make_scan(target_base_url="http://127.0.0.1")
    claim = _claim(client, scan, security_review=True)
    r = client.post(
        f"/runner/runs/{claim['run_id']}/complete",
        json={"requests": 1},
        headers={"X-Run-Token": claim["token"]},
    )
    assert r.status_code == 200, r.text
    run = client.get(f"/scans/{scan.id}/runs").json()[0]
    assert run["status"] == "completed"
    assert run["security_review"]["status"] == "unavailable"
    events = client.get(f"/scans/{scan.id}/events").json()
    assert any(e["stage"] == "ai_skipped" for e in events)


def test_a_redelivered_analysis_does_not_run_twice(client, db_session, make_scan, monkeypatch):
    from app.workers import tasks

    calls: list[str] = []
    monkeypatch.setattr(tasks.analyze_local_run, "delay", lambda run_id: calls.append(run_id))
    scan = make_scan(target_base_url="http://127.0.0.1")
    claim = _claim(client, scan, security_review=True)
    client.post(
        f"/runner/runs/{claim['run_id']}/complete",
        json={"requests": 1},
        headers={"X-Run-Token": claim["token"]},
    )
    assert tasks.analyze_local_run(calls[0])["status"] == "completed"
    review = Mock(side_effect=AssertionError("the review must not run again"))
    monkeypatch.setattr("app.engine.security_review.review_security_design", review)
    assert tasks.analyze_local_run(calls[0])["status"] == "duplicate"


def test_a_review_left_running_after_its_run_reads_as_unavailable():
    from datetime import UTC, datetime, timedelta

    from app.api.schemas.runs import ScanRunOut

    base = {"id": "00000000-0000-0000-0000-000000000001", "run_number": 1,
            "status": "completed", "started_at": datetime.now(UTC) - timedelta(hours=2),
            "security_review": {"status": "running"}}
    stale = ScanRunOut.model_validate(
        {**base, "finished_at": datetime.now(UTC) - timedelta(hours=1)}
    )
    assert stale.security_review.status == "unavailable"
    fresh = ScanRunOut.model_validate({**base, "finished_at": datetime.now(UTC)})
    assert fresh.security_review.status == "running"


def test_schema_context_stays_a_premium_input(
    client, db_session, make_scan, bridges, catalog, engine_client, monkeypatch
):
    scan = make_scan(target_base_url="http://127.0.0.1")
    scan.spec_text = json.dumps(SPEC)
    db_session.commit()
    _local_run_with_snapshot(client, scan)
    monkeypatch.setattr(settings, "premium_tenants", "")
    planner = SimpleNamespace(review_security=Mock(return_value=({"suggestions": []}, [])))
    db_session.expire_all()
    run_scan(db_session, scan, client=engine_client, planner=planner,
             options=RunOptions(security_review=True))
    assert planner.review_security.call_args.args[0]["database"] is None
    assert not any(e.stage == "schema_context" for e in scan.events)
