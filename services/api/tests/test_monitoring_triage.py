"""Ordering and triage: which observation a reader sees first, and which stay answered.

Two properties the page depends on. The detectors are stateless and re-derive every
observation on each ``recompute``, hardcoding ``disposition: "candidate"`` -- so a
person's triage has to be re-applied there or suppressing a lead silently does nothing.
"""

import json
from datetime import UTC, date, datetime, timedelta

import pytest
from sqlalchemy import select

from app.models.monitoring import InfrastructureMonitor, MonitoringRun
from app.monitoring import service
from app.monitoring.waf import normalize_waf_event

SALT = b"test-only-tenant-salt"


def observation(kind: str, **overrides) -> dict:
    return {
        "type": kind,
        "fingerprint": kind,
        "severity": "medium",
        "confidence": "heuristic",
        "basis": "single_day",
        "disposition": "candidate",
        **overrides,
    }


def test_severity_outranks_every_other_ordering_signal():
    ordered = service.sort_observations([
        observation("low", severity="low"),
        observation("critical", severity="critical"),
        observation("info", severity="info"),
        observation("high", severity="high"),
        observation("medium"),
    ])
    assert [o["type"] for o in ordered] == ["critical", "high", "medium", "low", "info"]


def test_proof_beats_a_lead_and_a_baseline_beats_one_day_within_a_severity():
    ordered = service.sort_observations([
        observation("lead_one_day"),
        observation("lead_baseline", basis="baseline"),
        observation("proof", confidence="verified"),
    ])
    assert [o["type"] for o in ordered] == ["proof", "lead_baseline", "lead_one_day"]


def test_a_suppressed_observation_sinks_below_every_open_one():
    """Even a critical one: suppression is a person saying it is answered here."""
    ordered = service.sort_observations([
        observation("suppressed_critical", severity="critical", disposition="suppressed"),
        observation("open_info", severity="info"),
    ])
    assert [o["type"] for o in ordered] == ["open_info", "suppressed_critical"]


def test_ordering_does_not_depend_on_detector_arrival_order():
    leads = [observation(f"k{i}", severity=s) for i, s in enumerate(["low", "high", "medium"])]
    assert service.sort_observations(leads) == service.sort_observations(list(reversed(leads)))


def test_open_observations_excludes_only_suppressed_ones():
    rows = [
        observation("a"),
        observation("b", disposition="suppressed"),
        observation("c", disposition="reviewed"),
    ]
    assert [o["type"] for o in service.open_observations(rows)] == ["a", "c"]
    assert service.open_observations(None) == []


def waf_day(day: date, count: int = 80) -> list[dict]:
    """A day that reliably produces at least one single-day lead."""
    start = datetime(day.year, day.month, day.day, 12, tzinfo=UTC)
    return [
        {
            "timestamp": (start + timedelta(seconds=i)).isoformat(),
            "httpMethod": "GET",
            "uri": f"/users/{i}",
            "clientIp": "198.51.100.5",
            "requestId": f"r-{day}-{i}",
        }
        for i in range(1, count)
    ]


@pytest.fixture
def monitor(db_session):
    row = InfrastructureMonitor(
        tenant_id="default", name="m", target_binding="https://target.test", source_ids=[]
    )
    db_session.add(row)
    db_session.commit()
    return row


def collected_day(db_session, monitor, day: date, count: int = 80):
    events = [normalize_waf_event(r, salt=SALT) for r in waf_day(day, count)]
    return service.ingest_normalized_events(
        db_session, monitor, events, observation_date=day, source_revisions={}
    )


def test_suppressing_an_observation_survives_the_next_recompute(db_session, monitor):
    day = date(2026, 9, 15)
    run = collected_day(db_session, monitor, day)
    assert run.observations, "the fixture day must produce a lead to triage"
    target = run.observations[0]["fingerprint"]

    monitor.triage = {target: "suppressed"}
    service.recompute(db_session, monitor)
    db_session.commit()

    run = db_session.scalar(select(MonitoringRun).where(MonitoringRun.id == run.id))
    by_fingerprint = {o["fingerprint"]: o for o in run.observations}
    assert by_fingerprint[target]["disposition"] == "suppressed"
    # The detector still reports it; triage changes the disposition, not the evidence.
    assert target in by_fingerprint
    assert all(
        o["disposition"] == "candidate"
        for f, o in by_fingerprint.items() if f != target
    )


def test_a_day_whose_leads_are_all_suppressed_is_not_an_anomaly(db_session, monitor):
    """Otherwise a monitor can never return to normal once anything has fired."""
    monitor.minimum_baseline_days = 1
    day = date(2026, 9, 15)
    # A quiet baseline day, then one that walks far more identifiers than it.
    collected_day(db_session, monitor, day - timedelta(days=1), count=20)
    run = collected_day(db_session, monitor, day, count=400)
    db_session.refresh(run)
    assert run.state == "anomaly"

    monitor.triage = {o["fingerprint"]: "suppressed" for o in run.observations}
    service.recompute(db_session, monitor)
    db_session.commit()
    db_session.refresh(run)
    assert run.state == "baseline_ready"
    assert json.dumps(run.observations), "suppressed observations are kept, not deleted"
