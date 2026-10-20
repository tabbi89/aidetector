"""A check that raised did not complete — said out loud, and kept out of "fixed".

A production scan against a slow host had ``bola`` and ``broken_auth`` each send
one request, meet a read timeout, and print "completed bola": the two checks the
user configured three identities for silently did nothing, and the next diff
would have read their missing findings as fixed. These pin that a raising check
gets its own event and a run gap, and that the trace names the transport error
instead of a bare missing status.
"""
from __future__ import annotations

from types import SimpleNamespace

import httpx
import pytest

from app.engine import execution, runner
from app.engine.probe import HttpProbe
from app.scans.run_options import unperformed
from tests.factories import operation, scan_context
from tests.fakes import FakeJournal


def _client(*answers: object) -> httpx.Client:
    """A client whose Nth request raises or returns ``answers[N]`` (the last repeats)."""
    calls: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(request.method)
        answer = answers[min(len(calls), len(answers)) - 1]
        if isinstance(answer, Exception):
            raise answer
        assert isinstance(answer, int)
        return httpx.Response(answer, json={})

    client = httpx.Client(transport=httpx.MockTransport(handler), base_url="http://target.test")
    client.calls = calls  # type: ignore[attr-defined]
    return client


def _timeout() -> httpx.ReadTimeout:
    # The message mimics what httpx may carry: never something to persist.
    return httpx.ReadTimeout("timed out reading http://target.test/items/1?token=s3cret")


# ---- the trace names the transport failure --------------------------------------


def test_a_transport_timeout_is_recorded_on_the_trace_row_by_class():
    client = _client(_timeout())
    probe = HttpProbe(client, max_requests=10, operations=[operation("POST", "/items")])
    probe.check_context = "bola"

    with pytest.raises(httpx.ReadTimeout):
        probe.send("POST", "/items", json={"name": "x"})

    [row] = probe.mutations
    assert row["error"] == "ReadTimeout"
    assert row["response"]["status"] is None
    assert row["route"] == "/items"
    assert "s3cret" not in str(row)


def test_a_row_that_got_a_response_carries_no_error():
    probe = HttpProbe(_client(200), max_requests=10)
    assert probe.send("GET", "/items") is not None
    assert probe.mutations[0]["error"] is None


def test_a_safe_read_is_retried_once_and_the_retry_is_budget_counted():
    client = _client(_timeout(), 200)
    probe = HttpProbe(client, max_requests=10)

    result = probe.send("GET", "/items")

    assert result is not None and result.status == 200
    assert probe.count == 2  # the retry spent its own slot
    assert [r["error"] for r in probe.mutations] == ["ReadTimeout", None]


def test_a_read_that_keeps_timing_out_raises_after_one_retry():
    client = _client(_timeout())
    probe = HttpProbe(client, max_requests=10)

    with pytest.raises(httpx.ReadTimeout):
        probe.send("GET", "/items")

    assert client.calls == ["GET", "GET"]  # type: ignore[attr-defined]
    assert probe.count == 2


def test_a_write_is_never_retried():
    """A timed-out write may still have landed; sending it again could double it."""
    client = _client(_timeout(), 200)
    probe = HttpProbe(client, max_requests=10)

    with pytest.raises(httpx.ReadTimeout):
        probe.send("POST", "/items", json={})

    assert client.calls == ["POST"]  # type: ignore[attr-defined]
    assert probe.count == 1


def test_no_retry_without_a_budget_slot_for_it():
    client = _client(_timeout(), 200)
    probe = HttpProbe(client, max_requests=1)

    with pytest.raises(httpx.ReadTimeout):
        probe.send("GET", "/items")

    assert client.calls == ["GET"]  # type: ignore[attr-defined]
    assert probe.count == 1


def test_no_retry_inside_a_reserved_test_case():
    client = _client(_timeout(), 200)
    probe = HttpProbe(client, max_requests=10)

    with pytest.raises(httpx.ReadTimeout), probe.test_case(2):
        probe.send("GET", "/items")

    assert client.calls == ["GET"]  # type: ignore[attr-defined]


def test_a_tls_or_protocol_error_is_not_retried():
    client = _client(httpx.RemoteProtocolError("bad framing"), 200)
    probe = HttpProbe(client, max_requests=10)

    with pytest.raises(httpx.RemoteProtocolError):
        probe.send("GET", "/items")

    assert client.calls == ["GET"]  # type: ignore[attr-defined]
    assert probe.mutations[0]["error"] == "RemoteProtocolError"


# ---- a raising check is a gap, not a completion ---------------------------------


def _checks(monkeypatch: pytest.MonkeyPatch) -> None:
    def times_out(ctx):
        ctx.probe.send("GET", "/items/7")
        return []

    def crashes(ctx):
        raise RuntimeError("token=s3cret leaked into a message")

    def finds_nothing(ctx):
        return []

    monkeypatch.setattr(
        execution,
        "ALL_CHECKS",
        [
            SimpleNamespace(key=key, run=fn)
            for key, fn in [("bola", times_out), ("bfla", crashes), ("cors", finds_nothing)]
        ],
    )


@pytest.mark.parametrize("workers", [1, 2])
def test_a_raising_check_emits_check_failed_not_completed(monkeypatch, workers):
    _checks(monkeypatch)
    ops = [operation("GET", "/items/{id}")]
    ctx = scan_context(ops, client=_client(_timeout()))
    journal = FakeJournal()

    runner._engine_stage(ctx, journal, runner._Deps(concurrency=workers))

    messages = {stage_message for _, _, stage_message in journal.events}
    assert "bola did not finish: ReadTimeout on GET /items/{id}" in messages
    assert "bfla did not finish: RuntimeError" in messages
    assert "completed cors" in messages
    assert not any(m in messages for m in ("completed bola", "completed bfla"))
    assert not any("s3cret" in m for m in messages)
    assert [s for s in journal.stages if s == "check_failed"] == ["check_failed"] * 2
    assert sorted(ctx.failed_checks) == ["bfla", "bola"]
    assert sorted(journal.failed) == ["bfla", "bola"]
    # Progress still advances past a failed check.
    assert journal.events[-1][1] == 85


def test_a_check_that_survived_a_timeout_and_raised_later_is_not_blamed_on_it(monkeypatch):
    def recovers_then_crashes(ctx):
        try:
            ctx.probe.send("GET", "/items/7")
        except httpx.ReadTimeout:
            pass
        raise KeyError("id")

    monkeypatch.setattr(
        execution, "ALL_CHECKS", [SimpleNamespace(key="bola", run=recovers_then_crashes)]
    )
    ctx = scan_context([operation("GET", "/items/{id}")], client=_client(_timeout()))
    journal = FakeJournal()

    execution._run_engine_checks(ctx, journal, max_workers=1)

    assert ("check_failed", 85, "bola did not finish: KeyError") in journal.events


def test_a_failed_check_cannot_fix_a_finding():
    assert unperformed("bola", {"failed_checks": ["bola"]})
    assert not unperformed("bfla", {"failed_checks": ["bola"]})


# ---- server-side: recorded on the run, honoured by the diff ---------------------


def test_a_failed_check_is_recorded_on_the_run_and_the_diff_keeps_its_findings(
    client, db_session, make_scan, engine_client, monkeypatch
):
    from app.engine.runner import run_scan

    scan = make_scan()
    run_scan(db_session, scan, client=engine_client)

    def bola_times_out(ctx):
        raise httpx.ReadTimeout("timed out")

    from app.engine.checks import ALL_CHECKS

    patched = [
        SimpleNamespace(key="bola", run=bola_times_out) if getattr(c, "key", None) == "bola"
        else c
        for c in ALL_CHECKS
    ]
    monkeypatch.setattr(execution, "ALL_CHECKS", patched)
    run_scan(db_session, scan, client=engine_client)

    older, newer = sorted(scan.runs, key=lambda r: r.run_number)
    assert newer.gaps["failed_checks"] == ["bola"]
    assert any(
        e.stage == "check_failed" and e.message == "bola did not finish: ReadTimeout"
        for e in scan.events
    )
    bola_row = {"check": "bola", "severity": "high", "confidence": "verified",
                "fingerprint": "bola-1", "title": "Object read across users",
                "verdict": "unreviewed"}
    older.findings_snapshot = [*older.findings_snapshot, bola_row]
    db_session.commit()

    body = client.get(f"/scans/{scan.id}/diff").json()
    assert "bola-1" in {r["fingerprint"] for r in body["not_retested"]}
    assert "bola-1" not in {r["fingerprint"] for r in body["resolved"]}
    listed = client.get(f"/scans/{scan.id}/runs").json()
    assert listed[0]["gaps"]["failed_checks"] == ["bola"]


def test_a_discovery_check_that_raised_is_a_gap_too(monkeypatch):
    """A shadow-path finding from a check that did not finish is not fixed either."""
    from app.domain.enums import Severity
    from app.engine.discovery_probe import DISCOVERY_CHECK_KEYS
    from app.models.finding import Finding

    key = sorted(DISCOVERY_CHECK_KEYS)[0]

    def times_out(ctx):
        ctx.probe.send("GET", "/admin/debug")
        return []

    monkeypatch.setattr(execution, "ALL_CHECKS", [SimpleNamespace(key=key, run=times_out)])
    ctx = scan_context([operation("GET", "/items")], client=_client(_timeout()))
    journal = FakeJournal()
    journal.scan = SimpleNamespace(  # type: ignore[attr-defined]
        findings=[Finding(check="kali_discovery", owasp_id=None, severity=Severity.low,
                          title="t", description="d", evidence={"path": "/admin/debug"})]
    )

    execution._run_discovery_probe(ctx, journal)

    assert ("check_failed", f"discovery {key} did not finish: ReadTimeout on GET /admin/debug") in [
        (stage, message) for stage, _, message in journal.events
    ]
    assert ctx.failed_checks == [key]
    assert journal.failed == [key]
