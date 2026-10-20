"""Episodic memory persistence: remember a run, recall it on the next (DB-backed)."""
from __future__ import annotations

from app.domain.enums import Confidence, Severity
from app.models.finding import Finding
from app.scans.agent_memory import recall, remember


def _finding(scan, **kw):
    defaults = dict(
        scan_id=scan.id,
        check="bola",
        fingerprint="fp-bola-widgets",
        severity=Severity.high,
        confidence=Confidence.verified,
        title="BOLA on /widgets/{id}",
        evidence={"route": "/widgets/{id}", "param": "id"},
    )
    defaults.update(kw)
    return Finding(**defaults)


def test_remember_then_recall_round_trip(db_session, seeded_scan) -> None:
    scan = seeded_scan
    scan.findings.append(_finding(scan))
    db_session.commit()

    assert remember(db_session, scan) == 1
    db_session.commit()

    rows = recall(db_session, scan.tenant_id, scan.target_base_url)
    assert len(rows) == 1
    assert rows[0]["fingerprint"] == "fp-bola-widgets"
    assert rows[0]["check"] == "bola"
    assert rows[0]["hits"] == 1
    assert rows[0]["embedding"]  # a non-empty embedding was stored


def test_remember_is_idempotent_and_bumps_hits(db_session, seeded_scan) -> None:
    scan = seeded_scan
    scan.findings.append(_finding(scan))
    db_session.commit()
    remember(db_session, scan)
    db_session.commit()
    # Same fingerprint, a second heavy run: one row, hits incremented.
    remember(db_session, scan)
    db_session.commit()
    rows = recall(db_session, scan.tenant_id, scan.target_base_url)
    assert len(rows) == 1
    assert rows[0]["hits"] == 2


def test_findings_without_a_fingerprint_are_not_remembered(db_session, seeded_scan) -> None:
    scan = seeded_scan
    scan.findings.append(_finding(scan, fingerprint=""))
    db_session.commit()
    assert remember(db_session, scan) == 0


def test_recall_is_scoped_to_tenant_and_host(db_session, seeded_scan) -> None:
    a = seeded_scan
    a.tenant_id = "t1"
    a.findings.append(_finding(a))
    db_session.commit()
    remember(db_session, a)
    db_session.commit()
    assert recall(db_session, "t1", a.target_base_url)  # same tenant/host: present
    # A different tenant sees nothing for the same host.
    assert recall(db_session, "t2", a.target_base_url) == []
