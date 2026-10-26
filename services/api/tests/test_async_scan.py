"""Phase 3: async run, progress events, cancel, verdicts, export.

Celery runs eager in tests (see conftest), so POST /run executes inline and we
can assert on the completed state.
"""
from __future__ import annotations

import json

import pytest

from app.core.config import settings
from app.engine.runner import run_scan
from app.models.scan import ScanStatus
from app.scans.run_options import RunOptions

SPEC = json.dumps(
    {
        "openapi": "3.0.0",
        "info": {"title": "vulnbank", "version": "1"},
        "paths": {
            "/accounts/{account_id}": {
                "get": {
                    "parameters": [
                        {"name": "account_id", "in": "path", "required": True}
                    ]
                }
            },
            "/admin/users/{user_id}/promote": {
                "post": {
                    "parameters": [
                        {"name": "user_id", "in": "path", "required": True}
                    ]
                }
            },
            "/search": {
                "get": {"parameters": [{"name": "q", "in": "query", "required": False}]}
            },
        },
    }
)


def test_runner_emits_progress_events(db_session, make_scan, engine_client):
    scan = make_scan()
    run_scan(db_session, scan, client=engine_client)

    assert scan.status == ScanStatus.completed
    assert scan.progress == 100
    stages = [e.stage for e in scan.events]
    assert stages[0] == "start"
    assert stages[-1] == "done"
    assert "bola" in stages
    assert any(
        event.stage == "check_skipped" and event.message.startswith("bfla did not run:")
        for event in scan.events
    )
    # progress is monotonic
    pcts = [e.pct for e in scan.events]
    assert pcts == sorted(pcts)


def test_run_history_records_each_run(client, db_session, make_scan, engine_client):
    scan = make_scan()
    run_scan(db_session, scan, client=engine_client)
    run_scan(db_session, scan, client=engine_client)  # re-run replaces findings

    runs = sorted(scan.runs, key=lambda r: r.run_number)
    assert [r.run_number for r in runs] == [1, 2]
    assert all(r.status == "completed" for r in runs)
    assert runs[1].findings_count == len(scan.findings)
    assert runs[1].requests > 0
    assert runs[1].findings_snapshot  # past results stay inspectable
    assert runs[1].findings_snapshot[0]["severity"] in {
        "critical", "high", "medium", "low", "info",
    }

    # endpoint lists newest first
    body = client.get(f"/scans/{scan.id}/runs").json()
    assert [r["run_number"] for r in body] == [2, 1]


def test_run_records_per_endpoint_coverage(client, db_session, make_scan, engine_client):
    scan = make_scan()
    run_scan(db_session, scan, client=engine_client)

    run = max(scan.runs, key=lambda r: r.run_number)
    cov = {(r["method"], r["path"]): r for r in run.coverage}
    # every operation appears, whether or not it was touched
    assert ("GET", "/search") in cov
    assert ("GET", "/accounts/{account_id}") in cov
    # /search has a fuzzable query param → requests fired and checks recorded
    search = cov[("GET", "/search")]
    assert search["requests"] > 0
    assert "reflected_injection" in search["checks"]
    assert search["findings"] >= 1  # vulnapp reflects q

    # /search answers 200, so it was *exercised*, not merely reached.
    assert search["ok"] > 0
    assert search["responses"] >= search["ok"]
    assert search["exercised"] is True

    # the coverage endpoint serves the same rows, carrying the outcome fields
    api_cov = client.get(f"/scans/{scan.id}/coverage").json()
    assert {(r["method"], r["path"]) for r in api_cov} == set(cov)
    api_search = next(r for r in api_cov if (r["method"], r["path"]) == ("GET", "/search"))
    assert api_search["exercised"] is True


def test_coverage_marks_an_endpoint_reached_but_never_answered_as_unexercised():
    """An endpoint the engine hit but that only ever answered 4xx was probed with
    the wrong auth/path/body — its "0 findings" is inconclusive, and the report
    must say so (exercised=False) rather than reading as clean."""
    from dataclasses import dataclass

    from fastapi import FastAPI
    from fastapi.responses import JSONResponse
    from fastapi.testclient import TestClient

    from app.engine.base import HttpProbe, TargetOperation
    from app.engine.run_record import build_coverage

    app = FastAPI()

    @app.get("/locked")
    def locked():
        return JSONResponse({"detail": "forbidden"}, status_code=403)

    op = TargetOperation(id="op-locked", method="GET", path="/locked")
    probe = HttpProbe(TestClient(app), operations=[op])
    assert probe.send("GET", "/locked").status == 403

    @dataclass
    class _Op:
        id: str
        method: str
        path: str
        enabled: bool = True

    @dataclass
    class _ScanStub:
        operations: list
        findings: list

    rows = build_coverage(
        _ScanStub(operations=[_Op("op-locked", "GET", "/locked")], findings=[]),
        probe,
    )
    row = rows[0]
    assert row["requests"] >= 1
    assert row["responses"] >= 1
    assert row["ok"] == 0
    assert row["exercised"] is False


def test_confirm_tools_are_opt_in(db_session, monkeypatch, make_scan, engine_client):
    """The heavy confirm tools only run under confirm=True — a default scan skips
    them (so a normal scan can't hang in commix/sqlmap/etc)."""
    from app.core.config import settings
    from app.engine import adjunct_run, adjuncts  # noqa: F401

    # Configure all four binaries so the phase would queue every pass; the
    # opt-in flag, not the config, is what this test is about.
    for tool in ("sqlmap", "dalfox", "commix", "tplmap"):
        monkeypatch.setattr(settings, f"{tool}_bin", tool)

    ran: list[str] = []
    monkeypatch.setattr(
        adjunct_run, "_confirm_pass",
        lambda *a, tool, **k: ran.append(tool),
    )

    scan = make_scan()
    run_scan(db_session, scan, client=engine_client)  # default: no confirm
    assert ran == []

    scan2 = make_scan()
    run_scan(db_session, scan2, client=engine_client, options=RunOptions(confirm=True))
    assert set(ran) == {"sqlmap", "dalfox", "commix", "tplmap"}


def test_coverage_empty_before_first_run(client):
    sid = client.post("/scans", json={"target_base_url": "http://t"}).json()["id"]
    assert client.get(f"/scans/{sid}/coverage").json() == []


def test_cancel_stops_before_checks(db_session, make_scan, engine_client):
    scan = make_scan(cancel=True)
    findings = run_scan(db_session, scan, client=engine_client)

    assert scan.status == ScanStatus.cancelled
    assert findings == []
    assert scan.events[-1].stage == "cancelled"


@pytest.fixture
def worker_transport(monkeypatch):
    """Exercise eager Celery and the real async bridge against our ASGI target."""
    import httpx

    from app.engine import runner
    from app.engine.transport import AsyncHttpClientBridge
    from tests.vulnapp import vulnapp

    rates: list[float] = []

    def bridge(base_url, **kwargs):
        rates.append(kwargs["requests_per_second"])
        return AsyncHttpClientBridge(
            base_url, **{
                **kwargs,
                "requests_per_second": 10000,
                # Replaces the pinned network transport: the target is in-process.
                "transport": httpx.ASGITransport(app=vulnapp),
            },
        )

    monkeypatch.setattr(runner, "AsyncHttpClientBridge", bridge)
    return rates


def test_run_endpoint_queues_and_completes(client, worker_transport):
    sid = client.post(
        "/scans", json={"target_base_url": "http://testserver"}
    ).json()["id"]
    client.post(f"/scans/{sid}/spec", json={"content": SPEC})

    r = client.post(
        f"/scans/{sid}/run",
        json={"authorized": True, "requests_per_second": 2},
    )
    assert r.status_code == 202
    assert r.json()["scan_id"] == sid
    assert worker_transport == [2.0]

    # Eager Celery ran the production worker against the controlled ASGI target.
    detail = client.get(f"/scans/{sid}").json()
    assert detail["status"] == "completed"
    assert client.get(f"/scans/{sid}/findings").json()
    assert client.get(f"/scans/{sid}/events").json()  # events were recorded


def test_cancel_requires_running_scan(client):
    sid = client.post("/scans", json={"target_base_url": "http://t"}).json()["id"]
    r = client.post(f"/scans/{sid}/cancel")
    assert r.status_code == 409


def test_run_with_kali_flag_skips_when_service_unconfigured(client, monkeypatch, worker_transport):
    """kali:true flows schema → route → task → runner and degrades to a skip.

    Pins ``kali_base_url`` empty so the "unconfigured" premise holds regardless
    of the ambient environment (a local .env may legitimately configure Kali).
    """
    monkeypatch.setattr(settings, "kali_base_url", "")
    sid = client.post(
        "/scans", json={"target_base_url": "http://testserver"}
    ).json()["id"]
    client.post(f"/scans/{sid}/spec", json={"content": SPEC})

    r = client.post(f"/scans/{sid}/run", json={"authorized": True, "kali": True})
    assert r.status_code == 202

    detail = client.get(f"/scans/{sid}").json()
    assert detail["status"] == "completed"  # the scan survives the missing service
    stages = [e["stage"] for e in client.get(f"/scans/{sid}/events").json()]
    assert "kali_skipped" in stages


def test_verdict_marks_false_positive(client, db_session, make_scan, engine_client):
    scan = make_scan()
    run_scan(db_session, scan, client=engine_client)
    sid = str(scan.id)

    findings = client.get(f"/scans/{sid}/findings").json()
    assert findings
    fid = findings[0]["id"]
    assert findings[0]["verdict"] == "unreviewed"

    r = client.patch(f"/scans/{sid}/findings/{fid}", json={"verdict": "dismissed"})
    assert r.status_code == 200
    assert r.json()["verdict"] == "dismissed"


def test_verdict_404_for_foreign_finding(client, db_session, make_scan, engine_client):
    scan = make_scan()
    other = make_scan()
    run_scan(db_session, scan, client=engine_client)
    fid = client.get(f"/scans/{scan.id}/findings").json()[0]["id"]
    # finding belongs to `scan`, not `other`
    r = client.patch(f"/scans/{other.id}/findings/{fid}", json={"verdict": "confirmed"})
    assert r.status_code == 404


def test_html_report_renders(client, db_session, make_scan, engine_client):
    scan = make_scan()
    run_scan(db_session, scan, client=engine_client)

    r = client.get(f"/scans/{scan.id}/report.html")
    assert r.status_code == 200
    assert r.headers["content-type"].startswith("text/html")
    assert "API Security Scan Report" in r.text
    assert scan.target_base_url in r.text
    assert "<script" not in r.text.lower()  # self-contained, no JS


def test_export_returns_downloadable_json(client, db_session, make_scan, engine_client):
    scan = make_scan()
    run_scan(db_session, scan, client=engine_client)

    r = client.get(f"/scans/{scan.id}/export")
    assert r.status_code == 200
    assert "attachment" in r.headers["content-disposition"]
    body = r.json()
    assert body["scan"]["id"] == str(scan.id)
    assert len(body["findings"]) == len(scan.findings)


@pytest.mark.parametrize("sev", ["high", "medium"])
def test_findings_are_severity_ordered(client, db_session, sev, make_scan, engine_client):
    scan = make_scan()
    run_scan(db_session, scan, client=engine_client)
    sevs = [f["severity"] for f in client.get(f"/scans/{scan.id}/findings").json()]
    rank = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}
    assert sevs == sorted(sevs, key=lambda s: -rank[s])
    assert sev in sevs
