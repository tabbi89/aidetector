"""Spending budgets, run admission and operator diagnostics."""
from __future__ import annotations

from datetime import UTC, datetime, timedelta
from unittest.mock import Mock

import pytest

from app.ai import budget as budgets
from app.ai.budget import BudgetExhausted, spend_micros
from app.core.config import settings
from app.engine import ai_phases
from app.models.ledger import TokenLedger
from app.models.scan import ScanRun, ScanStatus
from app.scans import scheduler, workspace


def _scan_with_budget(db, make_scan, **limits):
    scan = make_scan()
    tenant = workspace.ensure_tenant(db, scan.tenant_id)
    for field, value in limits.items():
        setattr(tenant, field, value)
    db.commit()
    return scan, tenant


def test_budget_sums_every_phase_and_enforces_both_limits(
    db_session, make_scan
):
    scan, tenant = _scan_with_budget(
        db_session,
        make_scan,
        ai_monthly_micros=1000,
        ai_per_scan_micros=5000,
    )
    db_session.add(
        TokenLedger(
            tenant_slug=scan.tenant_id,
            scan_id=scan.id,
            phase="plan",
            model="m",
            tokens_in=1,
            tokens_out=1,
            cost_micros=600,
        )
    )
    db_session.commit()
    current = budgets.load_budget(db_session, scan)
    assert current.month_spent_micros == 600
    assert current.exhausted() is None

    db_session.add(
        TokenLedger(
            tenant_slug=scan.tenant_id,
            scan_id=scan.id,
            phase="adjudicate",
            model="m",
            tokens_in=1,
            tokens_out=1,
            cost_micros=500,
        )
    )
    db_session.commit()
    assert budgets.load_budget(db_session, scan).exhausted() == "monthly"

    tenant.ai_monthly_micros = None
    tenant.ai_per_scan_micros = 500
    db_session.commit()
    assert budgets.load_budget(db_session, scan).exhausted() == "scan"


def test_require_budget_emits_a_skip_event(db_session, make_scan):
    scan, _ = _scan_with_budget(
        db_session, make_scan, ai_monthly_micros=0
    )
    events: list[tuple[str, int, str]] = []

    assert (
        budgets.require_budget(
            db_session,
            scan,
            lambda stage, pct, message: events.append((stage, pct, message)),
            "AI planning",
        )
        is None
    )
    assert events[0][0] == "ai_budget_exhausted"
    assert "monthly" in events[0][2]


def test_answer_question_refuses_before_spending(db_session, make_scan):
    scan, _ = _scan_with_budget(
        db_session, make_scan, ai_monthly_micros=0
    )

    with pytest.raises(BudgetExhausted):
        ai_phases.answer_question(db_session, scan, "why?", None)


def test_admission_counts_active_queued_and_daily(db_session, make_scan):
    scan, tenant = _scan_with_budget(
        db_session, make_scan, max_concurrent_runs=1
    )
    scan.status = ScanStatus.queued
    db_session.commit()

    with pytest.raises(workspace.RunLimit) as exc:
        workspace.admit_run(db_session, scan.tenant_id)
    assert exc.value.reason == "concurrent_run_limit"

    tenant.max_concurrent_runs = None
    tenant.max_queued_runs = 0
    db_session.commit()
    with pytest.raises(workspace.RunLimit) as exc:
        workspace.admit_run(db_session, scan.tenant_id)
    assert exc.value.reason == "queued_run_limit"

    tenant.max_queued_runs = None
    tenant.scans_per_day = 1
    scan.status = ScanStatus.completed
    db_session.commit()
    workspace.admit_run(db_session, scan.tenant_id, scan_id=scan.id)
    db_session.commit()
    with pytest.raises(workspace.RunLimit) as exc:
        workspace.admit_run(db_session, scan.tenant_id)
    assert exc.value.reason == "daily_scan_limit"


def test_ops_status_reports_queue_slow_checks_and_cleanup(
    client, db_session, make_scan
):
    scan = make_scan()
    now = datetime.now(UTC)
    scan.status = ScanStatus.queued
    scan.queued_at = now
    run = ScanRun(
        scan_id=scan.id,
        run_number=1,
        status="completed",
        queued_at=now,
        claimed_at=now + timedelta(seconds=12),
        finished_at=now + timedelta(seconds=30),
        check_timings={"bola": {"ms": 250, "requests": 4}},
        gaps={
            "cleanup_failed": ["DELETE /x: 500"],
            "not_run": ["zap"],
        },
    )
    db_session.add(run)
    db_session.commit()

    body = client.get("/ops/status").json()

    assert body["queue"]["queued"] >= 1
    assert body["queue_delay_seconds"]["max"] >= 12
    assert body["slow_checks"][0]["check"] == "bola"
    assert body["cleanup_failures"] == ["DELETE /x: 500"]
    assert body["tools_not_run"][0] == {"tool": "zap", "runs": 1}


def test_workspace_budgets_round_trip(client):
    response = client.put(
        "/workspace/budgets",
        json={
            "ai_monthly_micros": 5000,
            "max_concurrent_runs": 2,
            "scans_per_day": 3,
        },
    )
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["ai_monthly_micros"] == 5000
    assert body["max_concurrent_runs"] == 2
    assert body["month_spent_micros"] == 0

    assert (
        client.get("/workspace/budgets").json()["scans_per_day"] == 3
    )
    actions = {
        row["action"] for row in client.get("/workspace/audit").json()
    }
    assert "workspace.budgets_updated" in actions


def test_daily_allowance_counts_every_execution_of_one_scan(db_session, make_scan):
    scan, tenant = _scan_with_budget(db_session, make_scan, scans_per_day=2)
    for _ in range(2):
        workspace.admit_run(db_session, scan.tenant_id, scan_id=scan.id)
        db_session.commit()
    with pytest.raises(workspace.RunLimit) as exc:
        workspace.admit_run(db_session, scan.tenant_id, scan_id=scan.id)
    assert exc.value.reason == "daily_scan_limit"


def test_deleting_a_scan_does_not_refund_its_daily_allowance(db_session, make_scan):
    scan, tenant = _scan_with_budget(db_session, make_scan, scans_per_day=1)
    workspace.admit_run(db_session, scan.tenant_id, scan_id=scan.id)
    db_session.commit()
    slug = scan.tenant_id
    db_session.delete(scan)
    db_session.commit()
    other = make_scan()
    with pytest.raises(workspace.RunLimit):
        workspace.admit_run(db_session, slug, scan_id=other.id)


def test_scheduled_batch_respects_concurrency_without_autoflush(db_session, make_scan):
    from sqlalchemy.orm import Session

    from app.scans import scheduler

    first, tenant = _scan_with_budget(db_session, make_scan, max_concurrent_runs=1)
    second = make_scan()
    now = datetime.now(UTC)
    for scan in (first, second):
        scan.schedule_minutes = 60
        scan.next_run_at = now - timedelta(minutes=1)
        scan.status = ScanStatus.completed
    db_session.commit()
    enqueued: list[str] = []
    # The production session factory does not autoflush (app/core/db.py).
    with Session(bind=db_session.get_bind(), autoflush=False) as session:
        dispatched = scheduler.dispatch_due(
            session, now, lambda scan_id, options: enqueued.append(scan_id)
        )
    assert len(dispatched) == 1
    assert enqueued == dispatched


def test_a_run_the_broker_refused_does_not_spend_the_daily_allowance(
    client, db_session, scan_with_spec, monkeypatch
):
    from kombu.exceptions import OperationalError

    from app.api.routes.scans import runs as run_routes
    from app.models.identity import RunAdmission

    sid = scan_with_spec()
    tenant = workspace.ensure_tenant(db_session, "default")
    tenant.scans_per_day = 1
    db_session.commit()

    def broker_down(*args, **kwargs):
        raise OperationalError("synthetic broker outage")

    monkeypatch.setattr(run_routes.run_scan_task, "delay", broker_down)
    for _ in range(3):
        response = client.post(f"/scans/{sid}/run", json={"authorized": True})
        assert response.status_code == 503, response.text
    db_session.expire_all()
    assert db_session.query(RunAdmission).count() == 0


def test_a_scheduled_run_the_broker_refused_is_put_back(db_session, make_scan):
    from app.models.identity import RunAdmission
    from app.scans import scheduler

    scan, tenant = _scan_with_budget(db_session, make_scan, scans_per_day=5)
    other = make_scan()
    now = datetime.now(UTC)
    for row in (scan, other):
        row.schedule_minutes = 60
        row.next_run_at = now - timedelta(minutes=1)
        row.status = ScanStatus.completed
    db_session.commit()
    refused = str(scan.id)

    def enqueue(scan_id, options):
        if scan_id == refused:
            raise RuntimeError("synthetic broker outage")

    dispatched = scheduler.dispatch_due(db_session, now, enqueue)
    assert dispatched == [str(other.id)]
    db_session.refresh(scan)
    assert scan.status == ScanStatus.completed
    admitted = [row.scan_id for row in db_session.query(RunAdmission).all()]
    assert admitted == [other.id]
    # The schedule still advanced, so a broken broker does not retry every tick.
    assert scan.next_run_at is not None and scan.next_run_at > now


def test_local_claim_answers_the_workspace_limits(
    client, db_session, make_scan, monkeypatch
):
    monkeypatch.setattr(settings, "local_runner_enabled", True)
    scan = make_scan(target_base_url="http://127.0.0.1")
    tenant = workspace.ensure_tenant(db_session, scan.tenant_id)
    tenant.max_concurrent_runs = 0
    db_session.commit()
    response = client.post(
        f"/scans/{scan.id}/local-runs", json={"authorized": True}
    )
    assert response.status_code == 429, response.text


def test_scheduled_dispatch_answers_the_workspace_limits(
    db_session, make_scan
):
    scan = make_scan()
    tenant = workspace.ensure_tenant(db_session, scan.tenant_id)
    tenant.max_concurrent_runs = 0
    now = datetime.now(UTC)
    scan.status = ScanStatus.completed
    scan.schedule_minutes = 60
    scan.next_run_at = now - timedelta(minutes=1)
    db_session.commit()
    enqueue = Mock()
    assert scheduler.dispatch_due(db_session, now, enqueue) == []
    enqueue.assert_not_called()


def test_daily_allowance_counts_a_queued_admission(db_session, make_scan):
    first, second = make_scan(), make_scan()
    tenant = workspace.ensure_tenant(db_session, first.tenant_id)
    tenant.scans_per_day = 1
    db_session.commit()
    workspace.admit_run(db_session, first.tenant_id)
    first.status = ScanStatus.queued
    first.queued_at = datetime.now(UTC)
    db_session.commit()
    with pytest.raises(workspace.RunLimit):
        workspace.admit_run(db_session, second.tenant_id)


def test_deleting_a_scan_does_not_refund_its_spend(db_session, make_scan):
    scan = make_scan()
    tenant = workspace.ensure_tenant(db_session, scan.tenant_id)
    tenant.ai_monthly_micros = 100
    db_session.add(
        TokenLedger(
            tenant_slug=scan.tenant_id,
            scan_id=scan.id,
            phase="plan",
            model="m",
            tokens_in=1,
            tokens_out=1,
            cost_micros=80,
        )
    )
    db_session.commit()
    assert spend_micros(db_session, scan.tenant_id) == 80
    db_session.delete(scan)
    db_session.commit()
    assert spend_micros(db_session, scan.tenant_id) == 80
