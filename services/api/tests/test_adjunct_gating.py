"""Adjunct gating — sqlmap/testssl/kali side paths no-op or skip cleanly.

DB-free: the adjunct passes only need ``scan.progress/findings/base_url``,
``db.commit()`` and an ``emit`` callable, so fakes exercise the exact gates.
"""
from __future__ import annotations

from app.core.config import settings
from app.engine import adjunct_run, adjuncts
from tests.fakes import adjunct_harness, lead_finding


def test_confirmer_deadline_stops_before_running_targets():
    """A past deadline means no target is executed — the phase budget is hard."""
    import time

    from app.engine.sqlmap_confirm import SqlmapConfirmer

    calls: list[str] = []

    def execute(argv, timeout):
        calls.append(argv[-1])
        return (0, "")

    confirmer = SqlmapConfirmer("sqlmap", execute=execute)
    targets = [{"path": "/a", "param": "id"}, {"path": "/b", "param": "q"}]
    out = confirmer.run("http://t:9000", targets, deadline=time.monotonic() - 1)
    assert out == []
    assert calls == []  # deadline already spent → nothing ran


def test_confirmer_should_stop_cancels_between_targets():
    """A cancel request lands between per-target runs, not just between tools."""
    from app.engine.sqlmap_confirm import SqlmapConfirmer

    calls: list[str] = []

    def execute(argv, timeout):
        calls.append(argv[-1])
        return (0, "")

    # Cancel becomes true after the first target runs.
    state = {"n": 0}

    def should_stop():
        state["n"] += 1
        return state["n"] > 1

    confirmer = SqlmapConfirmer("sqlmap", execute=execute)
    targets = [{"path": f"/a{i}", "param": "id"} for i in range(5)]
    confirmer.run("http://t:9000", targets, should_stop=should_stop)
    assert len(calls) == 1  # stopped after the first target


def _run_confirm(db, scan, emit, tool="sqlmap"):
    """Drive just one tool's confirmation pass out of the phase."""
    passes = dict(
        adjuncts.confirm_passes(
            db, scan, emit, deadline=None, should_stop=lambda: False
        )
    )
    if tool in passes:
        passes[tool]()
    return passes


def test_sqlmap_is_not_queued_when_unset(monkeypatch):
    """An unset *_BIN keeps the pass out of the phase entirely."""
    monkeypatch.setattr(settings, "sqlmap_bin", "")
    db, scan, emit, events = adjunct_harness(findings=[lead_finding("sqli")])
    assert "sqlmap" not in _run_confirm(db, scan, emit)
    assert events == []


def test_sqlmap_is_silent_without_leads(monkeypatch):
    monkeypatch.setattr(settings, "sqlmap_bin", "sqlmap")
    db, scan, emit, events = adjunct_harness(findings=[])
    _run_confirm(db, scan, emit)
    assert events == []


def test_sqlmap_skips_when_binary_missing(monkeypatch):
    monkeypatch.setattr(settings, "sqlmap_bin", "sqlmap")
    monkeypatch.setattr(adjunct_run.shutil, "which", lambda name: None)
    db, scan, emit, events = adjunct_harness(findings=[lead_finding("sqli")])
    _run_confirm(db, scan, emit)
    assert events == ["sqlmap_skipped"]


def test_testssl_reports_skipped_when_unset(monkeypatch):
    # The run asked for the audit, so an unconfigured tool must not read as clean.
    monkeypatch.setattr(settings, "testssl_bin", "")
    db, scan, emit, events = adjunct_harness(base_url="https://t")
    adjuncts.run_testssl(db, scan, emit)
    assert events == ["testssl_skipped"]


def test_testssl_is_silent_for_plaintext_targets(monkeypatch):
    monkeypatch.setattr(settings, "testssl_bin", "testssl.sh")
    db, scan, emit, events = adjunct_harness(base_url="http://t:9000")
    adjuncts.run_testssl(db, scan, emit)
    assert events == []


def test_testssl_skips_when_binary_missing(monkeypatch):
    monkeypatch.setattr(settings, "testssl_bin", "testssl.sh")
    monkeypatch.setattr(adjunct_run.shutil, "which", lambda name: None)
    db, scan, emit, events = adjunct_harness(base_url="https://t")
    adjuncts.run_testssl(db, scan, emit)
    assert events == ["testssl_skipped"]


def test_kali_skips_when_not_configured(monkeypatch):
    monkeypatch.setattr(settings, "kali_base_url", "")
    db, scan, emit, events = adjunct_harness()
    adjuncts.run_kali(db, scan, emit)
    assert events == ["kali_skipped"]
