"""AI cascade plumbing — verdict application, token ledger, cost, and graceful
degradation. Uses a fake cascade so no API keys or network are needed.
"""
from __future__ import annotations

from app.ai.pricing import cost_micros, rate_for
from app.ai.types import HYBRID_CHECKS, Usage
from app.engine.runner import run_scan
from app.scans.run_options import RunOptions
from tests.fakes import BrokenCascade, BrokenPlanner, FakeCascade, FakePlanner


def test_pricing_matches_expected_rates():
    assert rate_for("claude-opus-5") == (5.0, 25.0)
    assert rate_for("deepseek-chat") == (0.14, 0.28)
    # 1M in + 1M out on opus = $5 + $25 = $30 = 30_000_000 micros
    assert cost_micros("claude-opus-5", 1_000_000, 1_000_000) == 30_000_000


def test_cascade_applies_verdicts_and_writes_ledger(db_session, seeded_scan, engine_client):
    usages = [
        Usage("claude-opus-5", "adjudicate", 8000, 3000),
        Usage("deepseek-chat", "execute", 4000, 1500),
    ]
    fake = FakeCascade(usages)

    run_scan(
        db_session, seeded_scan, client=engine_client,
        cascade=fake, options=RunOptions(adjudicate=True),
    )

    # only HYBRID findings were sent for adjudication
    sent_checks = {f["check"] for f in fake.seen_payload}
    assert sent_checks <= HYBRID_CHECKS
    assert "bola" in sent_checks

    hybrid = [f for f in seeded_scan.findings if f.check in HYBRID_CHECKS]
    assert all(f.verdict.value == "confirmed" for f in hybrid)
    assert all(f.ai_rationale for f in hybrid)
    # non-HYBRID findings are untouched by AI
    non_hybrid = [f for f in seeded_scan.findings if f.check not in HYBRID_CHECKS]
    assert non_hybrid
    assert all(f.verdict.value == "unreviewed" for f in non_hybrid)

    # ledger: one row per (model, phase)
    assert {(e.model, e.phase) for e in seeded_scan.ledger} == {
        ("claude-opus-5", "adjudicate"),
        ("deepseek-chat", "execute"),
    }
    # cost = opus(8k in/3k out) + deepseek(4k in/1.5k out)
    expected = cost_micros("claude-opus-5", 8000, 3000) + cost_micros(
        "deepseek-chat", 4000, 1500
    )
    assert sum(e.cost_micros for e in seeded_scan.ledger) == expected
    assert seeded_scan.cost_usd == expected / 1_000_000


def test_cascade_can_dismiss(db_session, seeded_scan, engine_client):
    fake = FakeCascade([], verdict_for=lambda check: "dismissed")
    run_scan(
        db_session, seeded_scan, client=engine_client,
        cascade=fake, options=RunOptions(adjudicate=True),
    )
    hybrid = [f for f in seeded_scan.findings if f.check in HYBRID_CHECKS]
    assert hybrid and all(f.verdict.value == "dismissed" for f in hybrid)


def test_cascade_failure_degrades_gracefully(db_session, seeded_scan, engine_client):
    findings = run_scan(
        db_session, seeded_scan, client=engine_client,
        cascade=BrokenCascade(), options=RunOptions(adjudicate=True),
    )
    # scan still completes; engine findings intact; nothing adjudicated
    assert seeded_scan.status.value == "completed"
    assert findings
    assert all(f.verdict.value == "unreviewed" for f in seeded_scan.findings)
    assert seeded_scan.ledger == []
    assert any(e.stage == "ai_skipped" for e in seeded_scan.events)


def test_no_adjudication_when_flag_off(db_session, seeded_scan, engine_client):
    run_scan(db_session, seeded_scan, client=engine_client, options=RunOptions(adjudicate=False))
    assert all(f.verdict.value == "unreviewed" for f in seeded_scan.findings)
    assert seeded_scan.ledger == []


def test_cost_endpoint(client, db_session, seeded_scan, engine_client):
    fake = FakeCascade([Usage("claude-opus-5", "adjudicate", 1000, 500)])
    run_scan(
        db_session, seeded_scan, client=engine_client,
        cascade=fake, options=RunOptions(adjudicate=True),
    )

    r = client.get(f"/scans/{seeded_scan.id}/cost")
    assert r.status_code == 200
    body = r.json()
    assert body["total_usd"] > 0
    assert len(body["entries"]) == 1
    assert body["entries"][0]["model"] == "claude-opus-5"
    # the per-model AI summary is populated for the scan summary view
    assert [m["model"] for m in body["models"]] == ["claude-opus-5"]
    assert body["models"][0]["phases"] == ["adjudicate"]
    assert body["models"][0]["calls"] == 1


def test_ai_summary_aggregates_models_across_calls():
    from types import SimpleNamespace

    from app.ai.summary import summarize_models

    def row(model, phase, ti, to, cm):
        return SimpleNamespace(
            model=model, phase=phase, tokens_in=ti, tokens_out=to, cost_micros=cm
        )

    ledger = [
        row("claude-opus-5", "plan", 100, 20, 1000),
        row("deepseek-chat", "execute", 200, 40, 50),
        row("claude-opus-5", "adjudicate", 300, 60, 3000),
    ]
    models = {m["model"]: m for m in summarize_models(ledger)}
    assert models["claude-opus-5"]["phases"] == ["plan", "adjudicate"]
    assert models["claude-opus-5"]["calls"] == 2
    assert models["claude-opus-5"]["tokens_in"] == 400
    assert models["claude-opus-5"]["cost_usd"] == 0.004
    assert models["deepseek-chat"]["phases"] == ["execute"]


def test_pre_scan_plan_reorders_ops_and_persists(db_session, seeded_scan, engine_client):
    # seeded ops: /accounts/{id}, /admin/.../promote, /search
    planner = FakePlanner(
        priority_for=lambda p: "high" if "search" in p else "low",
        usages=[Usage("claude-opus-5", "plan", 500, 100)],
    )
    run_scan(
        db_session, seeded_scan, client=engine_client,
        planner=planner, options=RunOptions(plan=True),
    )

    run = max(seeded_scan.runs, key=lambda r: r.run_number)
    assert run.plan, "plan should be persisted on the run"
    # the high-risk /search op is ordered first
    assert run.plan[0]["path"] == "/search"
    assert run.plan[0]["priority"] == "high"
    # plan cost is metered under the 'plan' phase
    assert any(e.phase == "plan" and e.model == "claude-opus-5" for e in seeded_scan.ledger)


def test_pre_scan_plan_degrades_gracefully(db_session, seeded_scan, engine_client):
    findings = run_scan(
        db_session, seeded_scan, client=engine_client,
        planner=BrokenPlanner(), options=RunOptions(plan=True),
    )
    assert seeded_scan.status.value == "completed"  # scan still finishes in spec order
    assert "plan_skipped" in [e.stage for e in seeded_scan.events]
    assert findings  # engine findings intact


def test_adjudication_cache_prevents_respend_on_rerun(db_session, seeded_scan, engine_client):
    """A re-scan reuses cached verdicts and never calls the cascade again."""
    fake1 = FakeCascade([Usage("claude-opus-5", "adjudicate", 1000, 500)])
    run_scan(
        db_session, seeded_scan, client=engine_client,
        cascade=fake1, options=RunOptions(adjudicate=True),
    )
    assert fake1.seen_payload, "first run should adjudicate uncached findings"
    hybrid = [f for f in seeded_scan.findings if f.check in HYBRID_CHECKS]
    assert hybrid and all(f.verdict.value == "confirmed" for f in hybrid)

    # Re-run the same seeded_scan: identical HYBRID findings → cache hit → the cascade
    # is never invoked, but the cached verdicts are still applied.
    fake2 = FakeCascade([Usage("claude-opus-5", "adjudicate", 1000, 500)])
    run_scan(
        db_session, seeded_scan, client=engine_client,
        cascade=fake2, options=RunOptions(adjudicate=True),
    )
    assert fake2.seen_payload is None, "cached re-run must not call the cascade"
    hybrid2 = [f for f in seeded_scan.findings if f.check in HYBRID_CHECKS]
    assert hybrid2 and all(f.verdict.value == "confirmed" for f in hybrid2)


def test_confirmed_finding_takes_the_ai_remediation(db_session, seeded_scan, engine_client):
    """A confirmed verdict with a remediation overrides the static catalogue fix."""
    fake = FakeCascade(
        [], verdict_for=lambda c: "confirmed",
        remediation_for=lambda c: f"Add an ownership check to the {c} handler.",
    )
    run_scan(
        db_session, seeded_scan, client=engine_client,
        cascade=fake, options=RunOptions(adjudicate=True),
    )
    hybrid = [f for f in seeded_scan.findings if f.check in HYBRID_CHECKS]
    assert hybrid
    assert all(f.remediation.startswith("Add an ownership check") for f in hybrid)
    # the model was shown the existing (static) remediation to improve on
    assert all("remediation" in f for f in fake.seen_payload)
    # and the evidence tier, so adjudication can weigh a lead against proof
    assert all("confidence" in f for f in fake.seen_payload)


def test_dismissed_finding_keeps_its_static_remediation(db_session, seeded_scan, engine_client):
    """A dismissed finding is not a place to write a fix."""
    fake = FakeCascade(
        [], verdict_for=lambda c: "dismissed",
        remediation_for=lambda c: "SHOULD NOT BE APPLIED",
    )
    run_scan(
        db_session, seeded_scan, client=engine_client,
        cascade=fake, options=RunOptions(adjudicate=True),
    )
    hybrid = [f for f in seeded_scan.findings if f.check in HYBRID_CHECKS]
    assert hybrid
    assert all("SHOULD NOT BE APPLIED" not in (f.remediation or "") for f in hybrid)


def test_null_ai_remediation_keeps_the_static_fix(db_session, seeded_scan, engine_client):
    """A model returning JSON null must not overwrite the fix with the string "None"."""
    fake = FakeCascade(
        [], verdict_for=lambda c: "confirmed",
        remediation_for=lambda c: None,  # the model emits `"remediation": null`
    )
    run_scan(
        db_session, seeded_scan, client=engine_client,
        cascade=fake, options=RunOptions(adjudicate=True),
    )
    hybrid = [f for f in seeded_scan.findings if f.check in HYBRID_CHECKS]
    assert hybrid
    # The static catalogue fix stands — never the literal text "None".
    assert all(f.remediation and f.remediation != "None" for f in hybrid)


def test_ai_remediation_is_cached_and_reused_without_respending(
    db_session, seeded_scan, engine_client
):
    """A re-scan reuses the cached AI fix and does not call the cascade again."""
    fake = FakeCascade(
        [], verdict_for=lambda c: "confirmed",
        remediation_for=lambda c: "Cached concrete fix.",
    )
    run_scan(db_session, seeded_scan, client=engine_client,
             cascade=fake, options=RunOptions(adjudicate=True))

    # Second run: the cache is warm, so this cascade should never be invoked.
    class Boom:
        def run(self, *a, **k):
            raise AssertionError("cascade should not run on a cache hit")

    run_scan(db_session, seeded_scan, client=engine_client,
             cascade=Boom(), options=RunOptions(adjudicate=True))
    hybrid = [f for f in seeded_scan.findings if f.check in HYBRID_CHECKS]
    assert hybrid and all(f.remediation == "Cached concrete fix." for f in hybrid)


def test_premium_widens_adjudication_to_every_finding(
    db_session, seeded_scan, engine_client
):
    """premium:true reviews every finding, not just the judgment-heavy HYBRID set."""
    fake = FakeCascade([], verdict_for=lambda c: "confirmed")
    run_scan(
        db_session, seeded_scan, client=engine_client,
        cascade=fake, options=RunOptions(adjudicate=True, premium=True),
    )
    non_hybrid = [f for f in seeded_scan.findings if f.check not in HYBRID_CHECKS]
    assert non_hybrid, "the vulnerable app must yield non-hybrid findings"
    assert all(f.verdict.value == "confirmed" for f in non_hybrid)


def test_answer_question_returns_the_cascade_answer(db_session, seeded_scan, engine_client):
    from app.engine.ai_phases import answer_question

    run_scan(db_session, seeded_scan, client=engine_client)
    fake = FakeCascade([])
    answer = answer_question(db_session, seeded_scan, "what should I fix first?", fake)
    assert answer == "canned answer to: what should I fix first?"


def test_answer_question_writes_the_token_ledger(db_session, seeded_scan, engine_client):
    from app.engine.ai_phases import answer_question

    run_scan(db_session, seeded_scan, client=engine_client)
    fake = FakeCascade([Usage("claude-opus-5", "adjudicate", 1_000_000, 1_000_000)])
    answer_question(db_session, seeded_scan, "what should I fix first?", fake)
    # The Q&A is metered like any other AI phase — a ledger row and a cost land.
    assert any(row.tokens_in == 1_000_000 for row in seeded_scan.ledger)
    assert seeded_scan.cost_cents == 3000  # $30 on opus for 1M in + 1M out


def test_ask_endpoint_requires_premium(client, new_scan, monkeypatch):
    from app.core.config import settings

    sid = new_scan()
    monkeypatch.setattr(settings, "premium_tenants", "")
    r = client.post(f"/scans/{sid}/ask", json={"question": "what is the top risk?"})
    assert r.status_code == 402
    assert "premium" in r.json()["detail"]


def test_ask_endpoint_answers_for_a_premium_tenant(client, new_scan, monkeypatch):
    import app.ai.cascade as cascade_mod
    from app.core.config import settings

    sid = new_scan()
    monkeypatch.setattr(settings, "premium_tenants", "*")
    # The route builds its own AICascade; swap it for a fake so no subprocess runs.
    monkeypatch.setattr(cascade_mod, "AICascade", lambda: FakeCascade([]))
    r = client.post(f"/scans/{sid}/ask", json={"question": "what is the top risk?"})
    assert r.status_code == 200
    assert r.json()["answer"] == "canned answer to: what is the top risk?"


def test_ask_endpoint_maps_planner_failure_to_502(client, new_scan, monkeypatch):
    import app.ai.cascade as cascade_mod
    from app.core.config import settings

    sid = new_scan()
    monkeypatch.setattr(settings, "premium_tenants", "*")
    monkeypatch.setattr(cascade_mod, "AICascade", lambda: BrokenCascade())
    r = client.post(f"/scans/{sid}/ask", json={"question": "what is the top risk?"})
    assert r.status_code == 502
    assert "AI unavailable" in r.json()["detail"]
