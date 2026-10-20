"""A budget claim must cover what the runtime is allowed to spend, and every
paid call must be claimed, metered once and released — including the calls
whose output turns out to be unusable."""
from __future__ import annotations

import importlib.util
import sys
from datetime import UTC, datetime, timedelta
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock

import pytest
from sqlalchemy import func, select

from app.ai import budget as budgets
from app.ai import limits
from app.ai.budget import BudgetExhausted, load_budget
from app.ai.pricing import cost_micros
from app.ai.types import Usage
from app.core.config import settings
from app.core.redact import Redactor
from app.domain.enums import Confidence, Severity
from app.engine import ai_phases, security_review
from app.models.finding import Finding
from app.models.ledger import AiBudgetReservation, TokenLedger
from app.models.scan import ScanRun
from app.scans import workspace
from tests.factories import operation

RUNTIME = Path(__file__).resolve().parents[1] / "ai_runtime"
MODES = ("qa", "payloads", "security_review", "plan", "adjudicate", "adaptive", "propose_resource")


def _runtime():
    spec = importlib.util.spec_from_file_location(
        "plan_agent_under_test", RUNTIME / "plan_agent.py"
    )
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def _scan(db, make_scan, **limits_):
    scan = make_scan()
    tenant = workspace.ensure_tenant(db, scan.tenant_id)
    for field, value in limits_.items():
        setattr(tenant, field, value)
    db.commit()
    return scan


def _reservations(db) -> int:
    return int(db.scalar(select(func.count()).select_from(AiBudgetReservation)) or 0)


def _usage(phase: str, tokens_in: int = 1000, tokens_out: int = 1000) -> Usage:
    return Usage(model="deepseek-chat", phase=phase, tokens_in=tokens_in, tokens_out=tokens_out)


# ---- the claim covers the runtime's own ceiling -----------------------------


def test_every_runtime_system_prompt_fits_the_priced_bound():
    agent = _runtime()
    prompts = {name: getattr(agent, name) for name in dir(agent) if name.endswith("_SYSTEM")}
    prompts["security_review_prompt.md"] = (RUNTIME / "security_review_prompt.md").read_text()
    assert len(prompts) >= 7
    for name, text in prompts.items():
        assert len(text.encode()) < limits.SYSTEM_PROMPT_MAX_BYTES, name


@pytest.mark.parametrize("mode", MODES)
def test_runtime_sends_exactly_the_output_ceiling_the_claim_priced(mode, monkeypatch):
    agent = _runtime()
    seen: list[int] = []

    def fake_chat(system, user, model, base_url, phase, max_tokens):
        seen.append(max_tokens)
        return "{}", {"model": model, "phase": phase, "tokens_in": 1, "tokens_out": 1}

    monkeypatch.setattr(agent, "_deepseek_chat", fake_chat)
    monkeypatch.setenv("EXECUTOR_MAX_TOKENS", str(settings.executor_max_tokens))
    cfg = {
        "mode": mode,
        "provider": "deepseek",
        "planner_model": "deepseek-chat",
        "executor_model": "deepseek-chat",
        "deepseek_base_url": "http://deepseek.invalid",
        "findings": [],
        "question": "q",
        "families": [],
        "operations": [],
        "payload": {},
        **limits.runtime_limits(mode),
    }
    if mode == "qa":
        agent._answer_with_deepseek(cfg)
    elif mode == "payloads":
        agent._generate_payloads_with_deepseek(cfg)
    elif mode == "security_review":
        agent._review_security_with_deepseek(cfg)
    else:
        agent._direct_with_deepseek(cfg)
    assert seen == [limits.output_ceiling(mode)]


def test_qna_claim_covers_a_completion_at_the_runtime_ceiling(db_session, make_scan):
    # The validator's case: a 560-micro claim admitted an 840-micro completion
    # (3,000 output tokens on deepseek-chat) carrying a single input token.
    charged = cost_micros("deepseek-chat", 1, limits.output_ceiling("qa"))
    request = {"findings": [], "question": "anything?"}
    assert limits.worst_case_micros("qa", request) >= charged

    scan = _scan(db_session, make_scan, ai_monthly_micros=charged - 1)
    cascade = SimpleNamespace(answer=Mock(return_value=("answer", [])))
    with pytest.raises(BudgetExhausted):
        ai_phases.answer_question(db_session, scan, "anything?", cascade)
    cascade.answer.assert_not_called()


def test_claim_bounds_the_prompt_by_bytes_not_characters():
    wide = {"findings": [{"title": "€" * 4000}]}
    assert limits.prompt_bytes("adjudicate", wide) >= len(("€" * 4000).encode())


def test_agent_provider_prices_every_turn_and_triage_call(monkeypatch):
    monkeypatch.setattr(settings, "planner_provider", "anthropic")
    requests = limits.requests_for("adjudicate", {"findings": []})
    agent = [r for r in requests if r.model == settings.planner_model]
    triage = [r for r in requests if r.model == settings.executor_model]
    assert len(agent) == limits.AGENT_MAX_TURNS
    assert len(triage) == limits.TRIAGE_MAX_CALLS
    assert all(r.max_output_tokens == limits.AGENT_OUTPUT_TOKENS for r in agent)
    direct = limits.worst_case_micros("adjudicate", {"findings": []})
    monkeypatch.setattr(settings, "planner_provider", "deepseek")
    assert direct > limits.worst_case_micros("adjudicate", {"findings": []})


def test_planner_hands_the_runtime_the_priced_limits(monkeypatch):
    from app.ai import planner as planner_module

    captured: dict = {}

    def fake_run(argv, *, input, **kwargs):
        import json

        captured.update(json.loads(input))
        return SimpleNamespace(returncode=0, stdout='{"answer": "", "usages": []}', stderr="")

    monkeypatch.setattr(settings, "deepseek_api_key", "test-key")
    monkeypatch.setattr(planner_module.subprocess, "run", fake_run)
    monkeypatch.setattr(planner_module, "_AGENT_SCRIPT", RUNTIME / "plan_agent.py")
    p = planner_module.OpusPlanner()
    p.python = Path(sys.executable)
    p.answer([], "q")
    for key, value in limits.runtime_limits("qa").items():
        assert captured[key] == value


# ---- one claim, one meter, no leftovers -------------------------------------


def test_usable_payloads_are_charged_once(db_session, make_scan):
    scan = _scan(db_session, make_scan)
    planner = SimpleNamespace(
        generate_payloads=Mock(
            return_value=({"xss": ["<svg/onload=aidx{m}>"]}, [_usage("payloads")])
        )
    )
    ctx = SimpleNamespace(payload_provider=None)
    ai_phases.generate_payloads(db_session, scan, ctx, SimpleNamespace(), planner, Mock())
    assert ctx.payload_provider is not None
    db_session.refresh(scan)
    assert len(scan.ledger) == 1
    assert _reservations(db_session) == 0


def _plan_scan(db, make_scan):
    scan = _scan(db, make_scan)
    ops = [operation("GET", "/a", id="a"), operation("GET", "/b", id="b")]
    run = ScanRun(scan_id=scan.id, run_number=1, status="running")
    db.add(run)
    db.commit()
    return scan, SimpleNamespace(operations=ops), run


def test_completed_planning_releases_its_claim(db_session, make_scan):
    scan, ctx, run = _plan_scan(db_session, make_scan)
    planner = SimpleNamespace(
        plan=Mock(return_value=([{"operation_id": "b", "priority": "high"}], [_usage("plan")]))
    )
    ai_phases.plan_operations(db_session, scan, ctx, run, planner, Mock())
    assert [o.id for o in ctx.operations] == ["b", "a"]
    assert _reservations(db_session) == 0
    db_session.refresh(scan)
    assert len(scan.ledger) == 1


MALFORMED_PLANS = [
    ["invalid"],
    "invalid",
    [{"operation_id": "a", "resource_dependencies": "x"}],
    None,
]


@pytest.mark.parametrize("output", MALFORMED_PLANS)
def test_malformed_plan_is_metered_and_skipped(db_session, make_scan, output):
    scan, ctx, run = _plan_scan(db_session, make_scan)
    planner = SimpleNamespace(plan=Mock(return_value=(output, [_usage("plan")])))
    emit = Mock()
    ai_phases.plan_operations(db_session, scan, ctx, run, planner, emit)
    assert [o.id for o in ctx.operations] == ["a", "b"]
    assert _reservations(db_session) == 0
    db_session.refresh(scan)
    assert len(scan.ledger) == 1


def test_malformed_verdict_elements_are_metered_and_ignored(db_session, make_scan):
    scan = _scan(db_session, make_scan)
    target = Finding(
        scan_id=scan.id,
        check="bola",
        title="Fixture",
        description="Fixture",
        severity=Severity.high,
        confidence=Confidence.verified,
    )
    db_session.add(target)
    db_session.commit()
    db_session.refresh(scan)
    cascade = SimpleNamespace(
        run=Mock(
            return_value=(
                ["invalid", None, {"id": str(target.id), "verdict": "confirmed", "rationale": "r"}],
                [_usage("adjudicate")],
            )
        )
    )
    ai_phases.adjudicate_findings(db_session, scan, cascade, Mock())
    assert target.verdict.value == "confirmed"
    assert _reservations(db_session) == 0
    assert db_session.scalar(select(func.count()).select_from(TokenLedger)) == 1


# ---- live claims across the month boundary ------------------------------------


def test_a_live_claim_from_last_month_still_holds_its_allowance(db_session, make_scan, monkeypatch):
    scan = _scan(db_session, make_scan, ai_monthly_micros=1000, ai_per_scan_micros=1000)
    turned = datetime.now(UTC)
    db_session.add(
        AiBudgetReservation(
            tenant_slug=scan.tenant_id,
            scan_id=scan.id,
            phase="adjudicate",
            reserved_micros=700,
            created_at=turned - timedelta(seconds=1),
        )
    )
    db_session.commit()
    monkeypatch.setattr(budgets, "month_start", lambda now=None: turned)
    current = budgets.load_budget(db_session, scan)
    assert current.month_spent_micros == 700
    assert current.scan_spent_micros == 700


# ---- refinement loops claim each call ----------------------------------------


def test_refinement_loop_stops_at_the_first_refused_claim(db_session, make_scan):
    one_call = limits.worst_case_micros("adaptive", {"payload": {"n": 1}})
    scan = _scan(db_session, make_scan, ai_per_scan_micros=one_call + one_call // 2)
    inner = SimpleNamespace(
        refine=Mock(return_value=({"action": "stop"}, [_usage("adaptive", 1, 1)]))
    )
    events: list[str] = []
    planner = ai_phases.MeteredPlanner(
        inner,
        db_session,
        scan,
        lambda stage, pct, msg: events.append(stage),
        "AI adaptive refinement",
    )
    assert planner.refine({"n": 1})[0] == {"action": "stop"}
    # The first call was cheap, but a second worst case no longer fits.
    db_session.add(
        AiBudgetReservation(
            tenant_slug=scan.tenant_id, scan_id=scan.id, phase="adaptive", reserved_micros=one_call
        )
    )
    db_session.commit()
    for _ in range(3):
        with pytest.raises(BudgetExhausted):
            planner.refine({"n": 1})
    assert inner.refine.call_count == 1
    assert events == ["ai_budget_exhausted"]
    db_session.refresh(scan)
    assert len(scan.ledger) == 1


def test_resource_refinement_meters_each_proposal_once(db_session, make_scan):
    scan = _scan(db_session, make_scan)
    inner = SimpleNamespace(
        propose_resource=Mock(return_value=({"name": "x"}, [_usage("propose_resource")]))
    )
    planner = ai_phases.MeteredPlanner(inner, db_session, scan, Mock(), "AI resource refinement")
    for _ in range(2):
        planner.propose_resource({"op": "POST /x"})
    db_session.refresh(scan)
    assert len(scan.ledger) == 2
    assert _reservations(db_session) == 0


# ---- a call that failed after it was sent is still spend ----------------------


def test_a_call_that_may_have_been_paid_is_charged_its_claim(db_session, make_scan):
    from app.ai.planner import PlannerUnavailable

    scan = _scan(db_session, make_scan)
    cascade = SimpleNamespace(answer=Mock(side_effect=PlannerUnavailable("agent timed out")))
    with pytest.raises(PlannerUnavailable):
        ai_phases.answer_question(db_session, scan, "q?", cascade)
    db_session.refresh(scan)
    assert [row.model for row in scan.ledger] == ["unmetered"]
    assert scan.ledger[0].cost_micros == limits.worst_case_micros(
        "qa", {"findings": [], "question": "q?"}
    )
    assert _reservations(db_session) == 0


def test_a_call_that_never_started_costs_nothing(db_session, make_scan):
    from app.ai.planner import PlannerNotStarted

    scan = _scan(db_session, make_scan)
    cascade = SimpleNamespace(answer=Mock(side_effect=PlannerNotStarted("no key")))
    with pytest.raises(PlannerNotStarted):
        ai_phases.answer_question(db_session, scan, "q?", cascade)
    db_session.refresh(scan)
    assert scan.ledger == []
    assert _reservations(db_session) == 0


def test_repeated_failing_refinements_stop_at_the_cap(db_session, make_scan):
    from app.ai.planner import PlannerUnavailable

    one_call = limits.worst_case_micros("adaptive", {"payload": {"n": 1}})
    scan = _scan(db_session, make_scan, ai_per_scan_micros=one_call * 2)
    inner = SimpleNamespace(refine=Mock(side_effect=PlannerUnavailable("agent timed out")))
    planner = ai_phases.MeteredPlanner(inner, db_session, scan, Mock(), "AI adaptive refinement")
    for _ in range(5):
        with pytest.raises((PlannerUnavailable, BudgetExhausted)):
            planner.refine({"n": 1})
    # Each timeout is charged its claim, so the cap holds after two of them.
    assert inner.refine.call_count == 2
    assert budgets.load_budget(db_session, scan).scan_spent_micros <= one_call * 2


# ---- agent-mode cache traffic, tool listing, claim lifetime -------------------


def _fake_agent_sdk(monkeypatch, usage: dict) -> dict:
    """Stand-in for claude_agent_sdk (not installed in the service image)."""
    import types

    captured: dict = {}
    sdk = types.ModuleType("claude_agent_sdk")

    class ClaudeAgentOptions:
        def __init__(self, **kwargs):
            captured.update(kwargs)

    class AssistantMessage:
        content: list = []

    class TextBlock:
        text = ""

    class ResultMessage:
        def __init__(self, usage):
            self.usage = usage

    async def query(prompt, options):
        yield ResultMessage(usage)

    sdk.ClaudeAgentOptions = ClaudeAgentOptions
    sdk.AssistantMessage = AssistantMessage
    sdk.TextBlock = TextBlock
    sdk.ResultMessage = ResultMessage
    sdk.query = query
    sdk.create_sdk_mcp_server = lambda **kwargs: object()
    sdk.tool = lambda *args, **kwargs: (lambda fn: fn)
    sdk.PermissionResultAllow = object
    sdk.PermissionResultDeny = object
    monkeypatch.setitem(sys.modules, "claude_agent_sdk", sdk)
    return captured


def _agent_cfg(mode: str) -> dict:
    return {
        "mode": mode,
        "provider": "anthropic",
        "planner_model": "claude-opus-5",
        "executor_model": "deepseek-chat",
        "deepseek_base_url": "http://deepseek.invalid",
        "findings": [],
        "operations": [],
        **limits.runtime_limits(mode),
    }


def test_agent_mode_reports_cache_traffic_and_lists_no_builtin_tools(monkeypatch):
    import asyncio

    agent = _runtime()
    captured = _fake_agent_sdk(
        monkeypatch,
        {
            "input_tokens": 120,
            "output_tokens": 40,
            "cache_read_input_tokens": 90_000,
            "cache_creation_input_tokens": 15_000,
        },
    )
    out = asyncio.run(agent._run(_agent_cfg("adjudicate")))
    usage = out["usages"][-1]
    assert usage["cache_read_tokens"] == 90_000
    assert usage["cache_write_tokens"] == 15_000
    # Only the triage MCP tool is offered: `tools=[]` lists no built-in tool.
    assert captured["tools"] == []
    assert captured["allowed_tools"] == ["mcp__executor__triage"]
    assert captured["max_turns"] == limits.AGENT_MAX_TURNS
    assert captured["env"]["CLAUDE_CODE_MAX_OUTPUT_TOKENS"] == str(limits.AGENT_OUTPUT_TOKENS)


def test_cache_tokens_are_stored_and_priced(db_session, make_scan):
    scan = _scan(db_session, make_scan)
    usage = Usage(
        model="claude-opus-5",
        phase="adjudicate",
        tokens_in=100,
        tokens_out=50,
        cache_read_tokens=1_000_000,
        cache_write_tokens=100_000,
    )
    ai_phases.write_ledger(scan, [usage])
    db_session.commit()
    db_session.refresh(scan)
    row = scan.ledger[0]
    assert (row.cache_read_tokens, row.cache_write_tokens) == (1_000_000, 100_000)
    plain = cost_micros("claude-opus-5", 100, 50)
    # 1M cache reads at a tenth of $5/M plus 100k writes at 1.25x of it.
    assert row.cost_micros == plain + 500_000 + 625_000


def test_planner_reads_cache_usage_from_the_runtime():
    from app.ai.planner import OpusPlanner

    usages = OpusPlanner._usages(
        {"usages": [{"model": "m", "phase": "plan", "tokens_in": 1, "tokens_out": 2,
                     "cache_read_tokens": 3, "cache_write_tokens": 4}]}
    )
    assert (usages[0].cache_read_tokens, usages[0].cache_write_tokens) == (3, 4)


def test_agent_worst_case_covers_input_written_to_cache(monkeypatch):
    monkeypatch.setattr(settings, "planner_provider", "anthropic")
    request = {"findings": []}
    agent = [
        r
        for r in limits.requests_for("adjudicate", request)
        if r.model == settings.planner_model
    ]
    as_writes = sum(
        cost_micros(r.model, 0, r.max_output_tokens, cache_write=r.max_input_tokens) for r in agent
    )
    assert limits.worst_case_micros("adjudicate", request) >= as_writes


def test_a_claim_must_outlive_the_call_it_covers():
    from pydantic import ValidationError

    from app.core.config import Settings

    with pytest.raises(ValidationError, match="ai_reservation_ttl_seconds must exceed"):
        Settings(ai_reservation_ttl_seconds=300, ai_timeout_seconds=300)
    assert Settings(ai_reservation_ttl_seconds=900, ai_timeout_seconds=300)


def _journal(db_session, scan):
    return SimpleNamespace(
        scan=scan,
        db=db_session,
        run_row=SimpleNamespace(security_review={}),
        event=Mock(),
        cancelled=lambda: False,
        progress=0,
    )


def test_zero_monthly_budget_blocks_the_security_review(
    db_session, make_scan, monkeypatch
):
    scan = make_scan()
    tenant = workspace.ensure_tenant(db_session, scan.tenant_id)
    tenant.ai_monthly_micros = 0
    db_session.commit()
    planner = SimpleNamespace(
        review_security=Mock(
            return_value=({"suggestions": []}, [
                Usage(model="deepseek-chat", phase="security_review", tokens_in=1, tokens_out=1)
            ])
        )
    )
    ctx = SimpleNamespace(
        spec={"openapi": "3.0.3", "paths": {"/x": {"get": {"responses": {}}}}},
        redact=Redactor(),
    )
    journal = _journal(db_session, scan)
    security_review.review_security_design(ctx, journal, planner)
    planner.review_security.assert_not_called()
    assert scan.ledger == []


def test_qna_refuses_a_call_the_remaining_allowance_cannot_cover(
    db_session, make_scan, monkeypatch
):
    scan = make_scan()
    tenant = workspace.ensure_tenant(db_session, scan.tenant_id)
    tenant.ai_monthly_micros = 100
    db_session.commit()
    monkeypatch.setattr(settings, "executor_max_tokens", 1_000_000)
    cascade = SimpleNamespace(answer=Mock(return_value=("answer", [])))
    with pytest.raises(BudgetExhausted):
        ai_phases.answer_question(db_session, scan, "question", cascade)
    cascade.answer.assert_not_called()


def test_payload_usage_is_metered_even_when_the_variants_are_unusable(
    db_session, make_scan
):
    scan = make_scan()
    workspace.ensure_tenant(db_session, scan.tenant_id)
    db_session.commit()
    planner = SimpleNamespace(
        generate_payloads=Mock(
            return_value=({}, [
                Usage(model="deepseek-chat", phase="payloads", tokens_in=1000, tokens_out=1000)
            ])
        )
    )
    ai_phases.generate_payloads(
        db_session,
        scan,
        SimpleNamespace(),
        SimpleNamespace(),
        planner,
        Mock(),
    )
    db_session.refresh(scan)
    assert len(scan.ledger) == 1
    assert scan.ledger[0].cost_micros > 0


def test_reservation_expires_so_a_dead_caller_cannot_spend_forever(
    db_session, make_scan
):
    scan = make_scan()
    workspace.ensure_tenant(db_session, scan.tenant_id)
    db_session.commit()
    reservation = budgets.reserve(
        db_session,
        scan,
        "plan",
        request={"operations": [{"path": "/x" * 100_000}]},
    )
    assert reservation is not None
    budget = load_budget(db_session, scan)
    assert budget.month_spent_micros > 0
    budgets.release(db_session, reservation)
    db_session.commit()
    assert load_budget(db_session, scan).month_spent_micros == 0
