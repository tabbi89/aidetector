"""What a run was asked to do and did not — said out loud, and kept out of "fixed".

A tool that never ran, a request budget that ran out and a run that crashed all
used to look like a clean result: "ZAP added 0 findings", "complete", or a bare
"failed". These pin that each one is reported, recorded on the run, and that
the diff counts its findings as not re-tested rather than fixed.
"""
from __future__ import annotations

import pytest

from app.core.config import settings
from app.core.redact import Redactor
from app.engine import adjuncts
from app.engine.journal import MAX_FAILURE_REASON, describe_failure
from app.scans import capabilities
from app.scans.run_options import RunOptions, producing_tool, unperformed
from tests.fakes import adjunct_harness

# ---- adjunct tools --------------------------------------------------------------


class _Broken:
    error = "ConnectError: connection refused"


def test_a_scanner_that_failed_raises_instead_of_reporting_nothing():
    with pytest.raises(adjuncts.AdjunctUnavailable, match="connection refused"):
        adjuncts._reported(_Broken(), [])
    assert adjuncts._reported(object(), []) == []  # ran, found nothing


def test_an_unavailable_tool_is_reported_as_not_run():
    db, scan, _, _ = adjunct_harness()
    events: list[tuple[str, str]] = []

    def produce():
        raise adjuncts.AdjunctUnavailable("ConnectError: connection refused")

    adjuncts.run_adjunct(
        db, scan, lambda stage, pct, message: events.append((stage, message)),
        tool="zap", start_message="ZAP", produce=produce,
    )
    assert [stage for stage, _ in events] == ["zap", "zap_skipped"]
    message = events[-1][1]
    assert "did not run" in message and "connection refused" in message
    assert "AdjunctUnavailable" not in message
    assert not any("added" in m for _, m in events)


def test_a_spent_adjunct_budget_names_every_tool_it_skipped():
    _, scan, emit, events = adjunct_harness()
    # A deadline already in the past: spent before the first pass, no sleeping.
    phase = adjuncts.AdjunctPhase(scan, emit, budget_seconds=-1, cancelled=lambda: False)
    ran: list[str] = []
    for name in ("zap", "sqlmap", "kali"):
        phase.add(name, lambda name=name: ran.append(name))
    assert phase.run() is True
    assert ran == []
    assert events == ["adjuncts_skipped", "zap_skipped", "sqlmap_skipped", "kali_skipped"]


def test_an_unreachable_zap_is_recorded_on_the_run(db_session, make_scan, engine_client,
                                                   monkeypatch):
    from app.engine.runner import run_scan

    # Nothing listens here, and the test harness blocks real sockets anyway.
    monkeypatch.setattr(settings, "zap_base_url", "http://zap.invalid:8090")
    scan = make_scan()
    run_scan(db_session, scan, client=engine_client, options=RunOptions(zap=True))

    stages = {e.stage: e.message for e in scan.events}
    assert "zap_skipped" in stages and "did not run" in stages["zap_skipped"]
    assert not any(e.message.startswith("ZAP added") for e in scan.events)
    assert scan.runs[-1].gaps["not_run"] == ["zap"]
    assert not scan.runs[-1].gaps.get("budget_exhausted")


def _testssl_calls(monkeypatch) -> list[str]:
    calls: list[str] = []
    monkeypatch.setattr(settings, "testssl_bin", "testssl")
    monkeypatch.setattr(
        adjuncts, "run_testssl", lambda db, scan, emit, redactor=None: calls.append(scan.id)
    )
    return calls


def test_testssl_does_not_run_unless_the_run_asks_for_it(
    db_session, make_scan, engine_client, monkeypatch
):
    """A configured TESTSSL_BIN no longer adds minutes to every fast-lane run."""
    from app.engine.runner import run_scan

    calls = _testssl_calls(monkeypatch)
    run_scan(db_session, make_scan(), client=engine_client, options=RunOptions(fuzz=True))
    assert calls == []


def test_testssl_runs_when_the_run_asks_for_it(
    db_session, make_scan, engine_client, monkeypatch
):
    from app.engine.runner import run_scan

    calls = _testssl_calls(monkeypatch)
    scan = make_scan()
    run_scan(db_session, scan, client=engine_client, options=RunOptions(testssl=True))
    assert calls == [scan.id]


# ---- the request budget ---------------------------------------------------------


def test_a_spent_request_budget_is_announced_once_and_recorded(
    db_session, make_scan, engine_client
):
    from app.engine.runner import run_scan

    scan = make_scan()
    run_scan(db_session, scan, client=engine_client, max_requests=5)

    announced = [e for e in scan.events if e.stage == "budget_exhausted"]
    assert len(announced) == 1
    assert "incomplete" in announced[0].message
    assert scan.runs[-1].gaps.get("budget_exhausted") is True


def test_a_run_within_budget_records_no_gaps(db_session, make_scan, engine_client):
    from app.engine.runner import run_scan

    scan = make_scan()
    run_scan(db_session, scan, client=engine_client)
    assert not any(e.stage == "budget_exhausted" for e in scan.events)
    gaps = scan.runs[-1].gaps
    assert not gaps.get("budget_exhausted") and not gaps.get("not_run")
    # What a default run did not look at is still a gap, said by name: the
    # write checks never run without ``mutate``.
    assert "write_authz" in gaps.get("skipped_checks", [])


# ---- a failed run says why ------------------------------------------------------


def test_a_failed_run_records_a_redacted_reason_and_the_next_run_clears_it(
    db_session, make_scan, engine_client, monkeypatch
):
    from app.engine import runner
    from app.models.scan import ScanStatus

    real_stages = runner._stages

    def exploding(*args, **kwargs):
        raise RuntimeError("upstream said no")

    scan = make_scan()
    monkeypatch.setattr(runner, "_stages", exploding)
    with pytest.raises(RuntimeError):
        runner.run_scan(db_session, scan, client=engine_client)
    assert scan.status == ScanStatus.failed
    assert scan.failure_reason == "RuntimeError: upstream said no"
    assert scan.events[-1].stage == "error"
    assert "upstream said no" in scan.events[-1].message

    monkeypatch.setattr(runner, "_stages", real_stages)
    runner.run_scan(db_session, scan, client=engine_client)
    assert scan.status == ScanStatus.completed and scan.failure_reason is None


def test_the_failure_reason_is_redacted_and_bounded():
    reason = describe_failure(ValueError("token s3cr3t-token-value leaked"),
                              Redactor(["s3cr3t-token-value"]))
    assert "s3cr3t-token-value" not in reason and reason.startswith("ValueError: ")
    assert len(describe_failure(ValueError("word " * 1000))) == MAX_FAILURE_REASON
    assert describe_failure(KeyError()) == "KeyError"


def test_failure_reason_is_on_the_scan_api(client, new_scan):
    assert client.get(f"/scans/{new_scan()}").json()["failure_reason"] is None


# ---- the diff -------------------------------------------------------------------


def test_adjunct_findings_map_to_their_tool():
    assert producing_tool("zap") == "zap"
    assert producing_tool("kali_nuclei") == "kali"
    assert producing_tool("sqlmap_confirm") == "sqlmap"
    assert producing_tool("testssl") == "testssl"
    assert producing_tool("bola") is None


def test_what_a_run_did_not_do_cannot_fix_a_finding():
    assert unperformed("zap", {"not_run": ["zap"]})
    assert not unperformed("zap", {"not_run": ["kali"]})
    assert not unperformed("zap", {"budget_exhausted": True})  # outside the budget
    assert unperformed("bola", {"budget_exhausted": True})
    assert not unperformed("bola", {})
    assert not unperformed("bola", None)
    assert unperformed("bfla", {"skipped_checks": ["bfla"]})
    assert not unperformed("bola", {"skipped_checks": ["bfla"]})


def test_diff_counts_a_tool_that_did_not_run_as_not_retested(
    client, db_session, make_scan, engine_client
):
    from app.engine.runner import run_scan

    scan = make_scan()
    run_scan(db_session, scan, client=engine_client, options=RunOptions(zap=True))
    run_scan(db_session, scan, client=engine_client, options=RunOptions(zap=True))
    older, newer = sorted(scan.runs, key=lambda r: r.run_number)
    zap_row = {"check": "zap", "severity": "medium", "confidence": "heuristic",
               "fingerprint": "zap-1", "title": "X-Frame-Options missing",
               "verdict": "unreviewed"}
    older.findings_snapshot = [*older.findings_snapshot, zap_row]
    newer.gaps = {"not_run": ["zap"]}
    db_session.commit()

    body = client.get(f"/scans/{scan.id}/diff").json()
    assert [r["fingerprint"] for r in body["not_retested"]] == ["zap-1"]
    assert all(r["fingerprint"] != "zap-1" for r in body["resolved"])


# ---- capabilities ---------------------------------------------------------------


def test_capabilities_say_what_is_missing_and_why(monkeypatch):
    import httpx

    monkeypatch.setattr(settings, "zap_base_url", "")
    monkeypatch.setattr(settings, "kali_base_url", "http://kali:8091")

    def down(url, headers):
        raise httpx.ConnectError("refused")

    result = capabilities.probe(get=down)
    assert result["zap"] == {"available": False,
                             "reason": "OWASP ZAP is not configured on this server"}
    assert result["kali"]["available"] is False and "not reachable" in result["kali"]["reason"]
    assert set(result) == {"zap", "kali", "confirm", "testssl", "plan", "adjudicate",
                           "security_review", "genai_payloads"}


def test_a_reachable_service_is_available(monkeypatch):
    monkeypatch.setattr(settings, "zap_base_url", "http://zap:8090")
    seen: list[str] = []

    def up(url, headers):
        seen.append(url)
        return 200

    assert capabilities.probe(get=up)["zap"] == {"available": True, "reason": None}
    assert seen[0] == "http://zap:8090/JSON/core/view/version/"


def test_capabilities_endpoint(client, monkeypatch):
    monkeypatch.setattr(capabilities, "probe", lambda: {"zap": {"available": False,
                                                                "reason": "r"}})
    capabilities.reset_cache()
    try:
        body = client.get("/capabilities").json()
        assert body["passes"] == {"zap": {"available": False, "reason": "r"}}
        # The tenant block answers a different question and is never cached with
        # the deployment probes. Auth is off here, so the caller is "default".
        assert body["premium"] == {
            "available": True,
            "plan": "premium",
            "reason": None,
        }
    finally:
        capabilities.reset_cache()


# ---- a check that skipped itself ------------------------------------------------


def test_a_skipped_check_is_recorded_on_the_run(db_session, make_scan, engine_client):
    from app.engine.runner import run_scan

    # Two accounts of one role: no privilege boundary, so BFLA cannot run.
    scan = make_scan(identities=[("alice", "user"), ("bob", "user")])
    run_scan(db_session, scan, client=engine_client)
    assert "bfla" in scan.runs[-1].gaps["skipped_checks"]
    assert any(
        e.stage == "check_skipped" and e.message.startswith("bfla ") for e in scan.events
    )


def test_diff_counts_a_skipped_identity_check_as_not_retested(
    client, db_session, make_scan, engine_client
):
    """Re-ranked roles can turn BFLA off; its old findings are not thereby fixed."""
    from app.engine.runner import run_scan

    scan = make_scan()
    run_scan(db_session, scan, client=engine_client)
    # The admin becomes a second user: BFLA has no boundary to test any more.
    for cred in scan.credential_profiles:
        cred.role = "user"
    db_session.commit()
    run_scan(db_session, scan, client=engine_client)
    older, newer = sorted(scan.runs, key=lambda r: r.run_number)
    assert "bfla" in newer.gaps["skipped_checks"]
    bfla_row = {"check": "bfla", "severity": "high", "confidence": "verified",
                "fingerprint": "bfla-1", "title": "Privileged function open",
                "verdict": "unreviewed"}
    older.findings_snapshot = [*older.findings_snapshot, bfla_row]
    db_session.commit()

    body = client.get(f"/scans/{scan.id}/diff").json()
    assert "bfla-1" in {r["fingerprint"] for r in body["not_retested"]}
    assert "bfla-1" not in {r["fingerprint"] for r in body["resolved"]}
