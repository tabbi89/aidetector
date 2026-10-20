"""A run can be scoped to a subset of engine checks ("headers only", "payloads").

The scope narrows what runs; it never enables a pass the flags keep off. A
diff after a narrower run must not call the left-out checks' findings fixed.
"""
from __future__ import annotations

import pytest
from pydantic import ValidationError

from app.api.schemas import RunRequest
from app.scans.run_options import RunOptions, descoped


def test_scope_round_trips_through_the_queue_and_is_absent_when_unscoped():
    opts = RunOptions(checks=("bola", "security_headers"))
    assert RunOptions.from_dict(opts.to_dict()) == opts
    assert "checks" not in RunOptions().to_dict()
    assert RunOptions().selects("ssrf")
    assert opts.selects("bola") and not opts.selects("ssrf")


def test_run_request_rejects_unknown_checks_and_keeps_registry_order():
    with pytest.raises(ValidationError):
        RunRequest(authorized=True, checks=["security_headers", "no_such_check"])
    request = RunRequest(authorized=True, checks=["ssrf", "bola", "ssrf"])
    assert request.to_options().checks == ("bola", "ssrf")


def test_descoped_counts_only_engine_checks_the_newer_scope_left_out():
    full, headers = {}, {"checks": ["security_headers"]}
    assert descoped("bola", full, headers)
    assert not descoped("security_headers", full, headers)
    assert not descoped("bola", headers, full)  # the newer run is wider
    assert not descoped("zap", full, headers)  # adjuncts are not scoped
    assert not descoped("bola", {"checks": ["ssrf"]}, headers)  # never tested before either


def test_scoped_run_executes_only_the_selected_checks(db_session, make_scan, engine_client):
    from app.engine.runner import run_scan

    scan = make_scan()
    run_scan(
        db_session, scan, client=engine_client,
        options=RunOptions(checks=("security_headers",)),
    )

    stages = [e.stage for e in scan.events]
    assert any(
        e.stage == "scope" and e.message.endswith("security_headers") for e in scan.events
    )
    assert "security_headers" in stages
    assert "bola" not in stages and "reflected_injection" not in stages
    # Left-out checks are stated once by the scope event, not skipped one by one.
    assert not any(e.stage == "check_skipped" for e in scan.events)
    assert scan.findings
    assert {f.check for f in scan.findings} == {"security_headers"}


def test_run_endpoint_refuses_an_unknown_check(client, make_scan):
    scan = make_scan()
    response = client.post(
        f"/scans/{scan.id}/run", json={"authorized": True, "checks": ["no_such_check"]}
    )
    assert response.status_code == 422


def test_diff_does_not_call_findings_outside_a_narrower_scope_fixed(
    client, db_session, make_scan, engine_client
):
    from app.engine.runner import run_scan

    scan = make_scan()
    run_scan(db_session, scan, client=engine_client)
    run_scan(
        db_session, scan, client=engine_client,
        options=RunOptions(checks=("security_headers",)),
    )

    body = client.get(f"/scans/{scan.id}/diff").json()
    assert body["options_changed"] is True
    assert body["not_retested"], "the full run's other findings were never re-tested"
    assert all(r["check"] != "security_headers" for r in body["not_retested"])
    assert all(r["check"] == "security_headers" for r in body["resolved"])
