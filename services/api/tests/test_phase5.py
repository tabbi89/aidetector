"""Phase 5: rotating payloads, scheduling, PDF report, cost breakdown."""
from __future__ import annotations

from datetime import UTC, datetime, timedelta

from app.ai.types import Usage
from app.engine.payloads import FAMILIES, rotating_set
from app.engine.runner import run_scan
from app.models.scan import ScanStatus
from app.scans.run_options import RunOptions
from app.scans.scheduler import dispatch_due, set_schedule
from tests import factories
from tests.fakes import FakeCascade

# ---- rotating payloads ----

def test_rotating_set_covers_all_families_and_is_seed_deterministic():
    a = rotating_set(seed=42)
    b = rotating_set(seed=42)
    assert {p.family for p in a} == set(FAMILIES)
    assert a == b  # deterministic for a fixed seed


def test_different_seeds_can_rotate_payloads():
    seen = {tuple(p.template for p in rotating_set(seed=s)) for s in range(30)}
    # across seeds we get more than one distinct selection
    assert len(seen) > 1


def test_injection_still_fires_with_rotating_payloads():
    scan_findings = _run_engine()
    assert any(f.check == "reflected_injection" for f in scan_findings)


def _run_engine():
    from app.engine.checks import ALL_CHECKS

    search = factories.operation(
        "GET", "/search", id="s",
        params=[{"name": "q", "in": "query", "required": False}],
    )
    ctx = factories.scan_context(
        [search],
        credentials=[factories.credential("a", "user", secret="t")],
        seed=7,
    )
    out = []
    for c in ALL_CHECKS:
        out.extend(c.run(ctx))
    return out


# ---- scheduling ----

def test_set_and_clear_schedule(db_session, seeded_scan, engine_client):
    set_schedule(db_session, seeded_scan, 15)
    assert seeded_scan.schedule_minutes == 15
    assert seeded_scan.next_run_at is not None
    set_schedule(db_session, seeded_scan, None)
    assert seeded_scan.schedule_minutes is None
    assert seeded_scan.next_run_at is None


def test_dispatch_enqueues_due_and_advances(db_session, seeded_scan, engine_client):
    set_schedule(db_session, seeded_scan, 30)
    # force it due
    seeded_scan.next_run_at = datetime.now(UTC) - timedelta(minutes=1)
    db_session.commit()

    enqueued: list[tuple[str, dict]] = []
    ids = dispatch_due(
        db_session, datetime.now(UTC), lambda sid, opts: enqueued.append((sid, opts))
    )

    assert ids == [str(seeded_scan.id)]
    # No saved options → a default, read-only run.
    assert enqueued == [(str(seeded_scan.id), RunOptions().to_dict())]
    assert seeded_scan.status == ScanStatus.queued
    # next_run_at advanced into the future
    assert seeded_scan.next_run_at > datetime.now(UTC)


def test_dispatch_skips_not_yet_due(db_session, seeded_scan, engine_client):
    set_schedule(db_session, seeded_scan, 30)  # next_run ~30 min out
    ids = dispatch_due(db_session, datetime.now(UTC), lambda _i, _o: None)
    assert ids == []


def test_dispatch_skips_running_scan(db_session, seeded_scan, engine_client):
    set_schedule(db_session, seeded_scan, 30)
    seeded_scan.next_run_at = datetime.now(UTC) - timedelta(minutes=1)
    seeded_scan.status = ScanStatus.running
    db_session.commit()
    ids = dispatch_due(db_session, datetime.now(UTC), lambda _i, _o: None)
    assert ids == []  # busy → skipped, but schedule still advanced
    assert seeded_scan.next_run_at > datetime.now(UTC)


def test_schedule_endpoint(client, db_session, seeded_scan, engine_client):
    r = client.put(
        f"/scans/{seeded_scan.id}/schedule", json={"minutes": 60, "authorized": True}
    )
    assert r.status_code == 200
    assert r.json()["schedule_minutes"] == 60
    assert r.json()["next_run_at"] is not None

    # Clearing a schedule starts nothing, so it needs no authorization.
    r = client.put(f"/scans/{seeded_scan.id}/schedule", json={"minutes": 0})
    assert r.json()["schedule_minutes"] is None
    assert r.json()["schedule_options"] == {}


def test_enabling_a_schedule_requires_authorization(client, seeded_scan, engine_client):
    """A schedule starts active scans, so it answers the run's authorization gate."""
    r = client.put(f"/scans/{seeded_scan.id}/schedule", json={"minutes": 60})
    assert r.status_code == 403
    assert client.get(f"/scans/{seeded_scan.id}").json()["schedule_minutes"] is None


def test_scheduling_premium_passes_requires_the_tier(
    client, seeded_scan, engine_client, monkeypatch
):
    from app.core.config import settings

    monkeypatch.setattr(settings, "premium_tenants", "someone-else")
    r = client.put(
        f"/scans/{seeded_scan.id}/schedule",
        json={"minutes": 60, "authorized": True, "premium": True},
    )
    assert r.status_code == 402


def test_scheduled_runs_carry_the_options_the_schedule_was_authorized_with(
    client, db_session, seeded_scan, engine_client
):
    r = client.put(
        f"/scans/{seeded_scan.id}/schedule",
        json={
            "minutes": 60, "authorized": True, "mutate": True,
            "predefined_resource_ids": {"merchant": "merchant_live_1"},
        },
    )
    assert r.status_code == 200
    assert r.json()["schedule_options"]["mutate"] is True
    # Target identifiers are kept for the run but never returned by the API.
    assert "predefined_resource_ids" not in r.json()["schedule_options"]

    db_session.refresh(seeded_scan)
    seeded_scan.next_run_at = datetime.now(UTC) - timedelta(minutes=1)
    db_session.commit()
    enqueued: list[dict] = []
    dispatch_due(db_session, datetime.now(UTC), lambda _sid, opts: enqueued.append(opts))
    assert len(enqueued) == 1 and enqueued[0]["mutate"] is True
    assert enqueued[0]["predefined_resource_ids"] == {"merchant": "merchant_live_1"}


def test_dispatch_pauses_server_runs_when_the_tenant_loses_premium(
    db_session, seeded_scan, engine_client, monkeypatch
):
    from app.core.config import settings

    set_schedule(db_session, seeded_scan, 30, RunOptions(premium=True, adaptive=True))
    seeded_scan.next_run_at = datetime.now(UTC) - timedelta(minutes=1)
    db_session.commit()
    monkeypatch.setattr(settings, "premium_tenants", "someone-else")

    enqueued: list[dict] = []
    now = datetime.now(UTC)
    dispatched = dispatch_due(db_session, now, lambda _sid, opts: enqueued.append(opts))
    assert dispatched == [] and enqueued == []
    db_session.refresh(seeded_scan)
    assert seeded_scan.next_run_at > now
    assert seeded_scan.status != ScanStatus.queued


# ---- PDF report ----

def test_pdf_report_endpoint(client, db_session, seeded_scan, engine_client):
    fake = FakeCascade([Usage("claude-opus-5", "adjudicate", 1000, 400)])
    run_scan(
        db_session, seeded_scan, client=engine_client,
        cascade=fake, options=RunOptions(adjudicate=True),
    )

    r = client.get(f"/scans/{seeded_scan.id}/report.pdf")
    assert r.status_code == 200
    assert r.headers["content-type"] == "application/pdf"
    assert r.content[:4] == b"%PDF"
    assert "attachment" in r.headers["content-disposition"]


# ---- cost breakdown ----

def test_cost_breakdown_by_phase(client, db_session, seeded_scan, engine_client):
    fake = FakeCascade([
        Usage("claude-opus-5", "adjudicate", 8000, 3000),
        Usage("deepseek-chat", "execute", 4000, 1500),
    ])
    run_scan(
        db_session, seeded_scan, client=engine_client,
        cascade=fake, options=RunOptions(adjudicate=True),
    )

    body = client.get(f"/scans/{seeded_scan.id}/cost").json()
    phases = {e["phase"] for e in body["entries"]}
    assert phases == {"adjudicate", "execute"}
    assert body["total_usd"] > 0
