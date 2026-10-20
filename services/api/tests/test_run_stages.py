"""The run's shape: which stages exist, in what order, and where a cancel lands.

These are the invariants ``run_scan`` exists to guarantee, and until the
:class:`~app.engine.journal.RunJournal` port they could only be exercised through
a full run against Postgres — so without a database they *skipped* rather than
failed, leaving the safety properties the runner is responsible for as the ones
least covered.

They are unit tests now. ``_stages`` is a pure function of (context, options),
and ``FakeJournal`` is two lists, so nothing here touches the network or the
database. ``test_char_stage_order.py`` still pins the same order end to end
against a real scan; this pins the sequence itself.
"""
from __future__ import annotations

from contextlib import contextmanager
from dataclasses import replace

import pytest

from app.engine.runner import Stage, _Deps, _stages, run_scan
from app.scans.run_options import RunOptions
from tests import factories
from tests.fakes import FakeCascade, FakeJournal, FakePlanner

ALL_ON = RunOptions(
    plan=True, genai_payloads=True, security_review=True, adjudicate=True, mutate=True, fuzz=True,
    zap=True, kali=True, confirm=True,
)


def _plan(opts: RunOptions) -> list[Stage]:
    ctx = factories.scan_context(factories.engine_operations(), allow_mutation=opts.mutate)
    return _stages(ctx, opts, FakeJournal(), _Deps())


def _enabled(opts: RunOptions) -> list[str]:
    return [s.name for s in _plan(opts) if s.enabled]


# ---- the sequence -------------------------------------------------------------


def test_stage_order_is_the_scan_lifecycle() -> None:
    """Every stage, in the one order that makes the pipeline correct."""
    assert [s.name for s in _plan(RunOptions())] == [
        "plan", "genai_payloads", "engine", "adjuncts", "discovery", "adjudicate",
        "security_review", "triage",
    ]


def test_a_default_run_only_does_the_engine_tier_and_triage() -> None:
    """Every optional pass is off by default — a safety property, not a default."""
    assert _enabled(RunOptions()) == ["engine", "adjuncts", "triage"]


def test_every_flag_on_enables_every_stage() -> None:
    assert _enabled(ALL_ON) == [
        "plan", "genai_payloads", "engine", "adjuncts", "discovery", "adjudicate",
        "security_review", "triage",
    ]


@pytest.mark.parametrize(
    ("flag", "stage"),
    [
        ("plan", "plan"),
        ("genai_payloads", "genai_payloads"),
        ("kali", "discovery"),
        ("adjudicate", "adjudicate"),
        ("security_review", "security_review"),
    ],
)
def test_each_optional_stage_is_gated_on_its_own_flag(flag: str, stage: str) -> None:
    assert stage not in _enabled(RunOptions())
    assert stage in _enabled(RunOptions(**{flag: True}))


def test_planning_precedes_the_engine_tier() -> None:
    """The plan reorders operations, so it is worthless after the budget is spent."""
    names = _enabled(RunOptions(plan=True))
    assert names.index("plan") < names.index("engine")


def test_discovery_follows_the_adjuncts_that_feed_it() -> None:
    """Discovery probes what ffuf/katana found, so it cannot run before them."""
    names = _enabled(RunOptions(kali=True))
    assert names.index("adjuncts") < names.index("discovery")


def test_triage_is_last_so_a_human_outranks_the_model() -> None:
    """Adjudication sets verdicts; triage re-applies the ones a person set."""
    names = _enabled(ALL_ON)
    assert names[-1] == "triage"
    assert names.index("adjudicate") < names.index("triage")


# ---- cancellation --------------------------------------------------------------


@pytest.fixture
def run_with_journal(monkeypatch):
    """Inject setup and stage work, but execute the production run_scan loop."""
    import app.engine.runner as runner

    def run(journal: FakeJournal, opts: RunOptions, *, fail_stage: str | None = None):
        ctx = factories.scan_context([])
        ran: list[str] = []

        @contextmanager
        def open_run(*_args, **_kwargs):
            yield ctx, journal

        def work(name: str) -> None:
            ran.append(name)
            if name == fail_stage:
                raise RuntimeError("stage exploded")

        stages = [
            replace(stage, run=lambda name=stage.name: work(name))
            for stage in _stages(ctx, opts, journal, _Deps())
        ]
        with monkeypatch.context() as patch:
            patch.setattr(runner, "_open_run", open_run)
            patch.setattr(runner, "_stages", lambda *_args: stages)
            result = runner.run_scan(None, None, options=opts)
        assert result == journal.findings
        return ran

    return run


def test_a_cancel_stops_the_run_at_the_next_stage_boundary(run_with_journal) -> None:
    journal = FakeJournal(cancel_after=1)      # cancel after the first check
    ran = run_with_journal(journal, RunOptions())
    assert ran == ["engine"]                    # adjuncts and triage never started
    assert journal.lifecycle == ["cancel"]


def test_a_cancel_before_anything_runs_nothing(run_with_journal) -> None:
    journal = FakeJournal(cancel_after=0)
    assert run_with_journal(journal, RunOptions()) == []
    assert journal.lifecycle == ["cancel"]


def test_an_uncancelled_run_completes(run_with_journal) -> None:
    journal = FakeJournal()
    ran = run_with_journal(journal, RunOptions())
    assert ran == ["engine", "adjuncts", "triage"]
    assert journal.lifecycle == ["complete"]


def test_cancellation_is_checked_between_stages_not_inside_them(run_with_journal) -> None:
    """A stage owns its work and must finish it.

    The write oracles restore what they changed and delete what they created;
    stopping mid-stage would leave a target dirty. So the check happens once per
    stage boundary — exactly as many times as there are enabled stages.
    """
    journal = FakeJournal()
    run_with_journal(journal, RunOptions())
    assert journal.cancel_checks == 3          # engine, adjuncts, triage


@pytest.mark.parametrize("cancel_after", [0, 1, 2, 3, 4, 5, 6, 7])
def test_cancel_at_every_enabled_stage(cancel_after, run_with_journal):
    journal = FakeJournal(cancel_after=cancel_after)
    ran = run_with_journal(journal, ALL_ON)
    assert ran == [
        "plan", "genai_payloads", "engine", "adjuncts", "discovery", "adjudicate",
        "security_review", "triage",
    ][:cancel_after]
    assert journal.lifecycle == ["cancel"]


def test_production_loop_marks_failure_without_completing(run_with_journal):
    journal = FakeJournal()
    with pytest.raises(RuntimeError, match="stage exploded"):
        run_with_journal(journal, RunOptions(), fail_stage="engine")
    assert journal.lifecycle == ["fail"]


# ---- failure -------------------------------------------------------------------


def test_a_stage_that_raises_fails_the_run_and_re_raises(
    db_session, make_scan, engine_client, monkeypatch
) -> None:
    """A crash marks the run failed rather than leaving it 'running' forever.

    Driven through the real runner, because the interesting part is that
    journal.fail() happens *and* the exception still propagates to the Celery
    task that must retry or record it.
    """
    import app.engine.runner as runner

    def boom(*_a, **_k):
        raise RuntimeError("engine exploded")

    monkeypatch.setattr(runner, "_run_engine_checks", boom)
    scan = make_scan()
    with pytest.raises(RuntimeError, match="engine exploded"):
        run_scan(db_session, scan, client=engine_client)

    from app.models.scan import ScanStatus

    assert scan.status is ScanStatus.failed
    assert [e.stage for e in scan.events][-1] == "error"


def test_the_transport_is_closed_even_when_a_stage_raises(
    db_session, make_scan, monkeypatch
) -> None:
    """ExitStack owns the lifetimes, so a crash cannot leak the HTTP transport."""
    import app.engine.runner as runner

    closed: list[str] = []

    class _Bridge:
        def __init__(self, *_a, **_k) -> None:
            pass

        def request(self, *_a, **_k):
            raise RuntimeError("no network in this test")

        def close(self) -> None:
            closed.append("transport")

    monkeypatch.setattr(runner, "AsyncHttpClientBridge", _Bridge)
    monkeypatch.setattr(
        runner, "_run_engine_checks", lambda *a, **k: (_ for _ in ()).throw(RuntimeError("x"))
    )
    scan = make_scan()
    with pytest.raises(RuntimeError):
        run_scan(db_session, scan)          # client=None → the bridge is built

    assert closed == ["transport"]


def test_a_broken_oob_teardown_does_not_mask_the_result(
    db_session, make_scan, engine_client, monkeypatch
) -> None:
    """Cleanup must never turn a completed scan into a failed one."""
    import app.engine.runner as runner

    class _Oob:
        active = False

        def payload_url(self, token: str) -> str:
            return ""

        def payload_domain(self, token: str) -> str:
            return ""

        def poll(self) -> list:
            return []

        def close(self) -> None:
            raise RuntimeError("teardown blew up")

    monkeypatch.setattr(runner, "_build_oob_client", lambda: _Oob())
    scan = make_scan()
    findings = run_scan(db_session, scan, client=engine_client)

    from app.models.scan import ScanStatus

    assert scan.status is ScanStatus.completed
    assert findings is not None


# ---- the journal is the only thing a stage reports through ---------------------


def test_engine_checks_report_only_through_the_journal() -> None:
    """The engine tier persists nothing itself — that is what the port bought.

    Run the real check loop against a fake journal: findings arrive as records
    and progress as events, with no session anywhere.
    """
    from app.engine.runner import _run_engine_checks

    ctx = factories.scan_context(factories.engine_operations())
    journal = FakeJournal()
    _run_engine_checks(ctx, journal, max_workers=1)

    assert journal.findings, "the vulnerable app must yield findings"
    assert "bola" in journal.stages
    # This context has `mutate` off, so every writing check declares itself
    # inapplicable and is skipped with a reason rather than running to no
    # effect. What is left is the parallel group, in registry order.
    assert journal.stages[-1] == "grpc_reflection"
    skipped = {
        message.split(" did not run:")[0]
        for stage, _, message in journal.events
        if stage == "check_skipped"
    }
    assert {"write_authz", "seeded_bola", "mass_assignment", "race_condition"} <= skipped
    assert all(0 <= pct <= 85 for _, pct, _ in journal.events)


def test_a_writing_check_says_why_it_did_not_run() -> None:
    """"Found nothing" and "never ran" must not read the same in a report.

    A check with nothing to work against returns an empty list, which is exactly
    what a clean result looks like. The event is the difference, and it names
    the thing to change.
    """
    from app.engine.runner import _run_engine_checks

    ctx = factories.scan_context(factories.engine_operations())  # mutate off
    journal = FakeJournal()
    _run_engine_checks(ctx, journal, max_workers=1)

    reasons = {
        message.split(" did not run: ")[0]: message.split(" did not run: ")[1]
        for stage, _, message in journal.events
        if stage == "check_skipped"
    }
    assert "mutate" in reasons["write_authz"]
    assert "OAST_SERVER" in reasons["oob_injection"]
    assert "fuzz" in reasons["schema_fuzz"]


def test_a_check_with_what_it_needs_is_not_skipped() -> None:
    """The gate must open, not just close — a skip list that never shrinks is a bug."""
    from app.engine.runner import _run_engine_checks

    # vulnapp's widgets are a real create/read pair, which is what the write
    # oracle needs; the standard five-endpoint set deliberately has none.
    operations = factories.engine_operations() + [
        factories.operation(
            "POST", "/widgets", id="op-widgets-create",
            params=[{"name": "name", "in": "body", "schema": {"type": "string"}}],
        ),
        factories.operation("GET", "/widgets/{widget_id}", id="op-widget-read"),
        factories.operation(
            "PUT", "/widgets/{widget_id}", id="op-widget-update",
            params=[
                {"name": "widget_id", "in": "path", "required": True},
                {"name": "name", "in": "body", "schema": {"type": "string"}},
            ],
        ),
    ]
    ctx = factories.scan_context(
        operations, credentials=factories.two_identities(), allow_mutation=True
    )
    journal = FakeJournal()
    _run_engine_checks(ctx, journal, max_workers=1)

    skipped = {
        message.split(" did not run:")[0]
        for stage, _, message in journal.events
        if stage == "check_skipped"
    }
    assert "write_authz" not in skipped
    assert "mass_assignment" not in skipped
    assert "write_authz" in journal.stages


def test_a_check_that_raises_is_isolated_from_the_rest() -> None:
    """One broken check never aborts a scan — asserted without a database."""
    from app.engine.runner import _run_engine_checks

    class _Broken:
        key = "bola"          # stand in for a real check by key

        def run(self, ctx):
            raise RuntimeError("check exploded")

    import app.engine.execution as execution

    ctx = factories.scan_context(factories.engine_operations())
    journal = FakeJournal()
    original = list(execution.ALL_CHECKS)
    try:
        execution.ALL_CHECKS[:] = [_Broken(), *original[1:]]
        _run_engine_checks(ctx, journal, max_workers=1)
    finally:
        execution.ALL_CHECKS[:] = original

    # The broken check says it did not finish — never "completed" — and
    # everything after it ran.
    assert ("check_failed", "bola did not finish: RuntimeError") in [
        (stage, message) for stage, _, message in journal.events
    ]
    assert "bola" not in journal.stages
    assert ctx.failed_checks == ["bola"]
    assert len([s for s in journal.stages if s != "id_seed"]) == len(original)


def test_planning_failure_leaves_spec_order(db_session, make_scan, engine_client) -> None:
    """An AI problem must never fail a scan — it degrades to a skip event."""
    from tests.fakes import BrokenPlanner

    scan = make_scan()
    run_scan(
        db_session, scan,
        options=RunOptions(plan=True),
        client=engine_client,
        planner=BrokenPlanner(),
    )
    stages = [e.stage for e in scan.events]
    assert "plan_skipped" in stages
    assert stages[-1] == "done"


def test_adjudication_failure_leaves_findings_unreviewed(
    db_session, make_scan, engine_client
) -> None:
    from app.domain.enums import Verdict
    from tests.fakes import BrokenCascade

    scan = make_scan()
    run_scan(
        db_session, scan,
        options=RunOptions(adjudicate=True),
        client=engine_client,
        cascade=BrokenCascade(),
    )
    assert "ai_skipped" in [e.stage for e in scan.events]
    assert scan.findings
    assert all(f.verdict is Verdict.unreviewed for f in scan.findings)


def test_fake_cascade_is_used_when_adjudication_is_on(
    db_session, make_scan, engine_client
) -> None:
    """Sanity: the injected collaborator really is what the stage calls."""
    cascade = FakeCascade()
    run_scan(
        db_session, make_scan(),
        options=RunOptions(adjudicate=True), client=engine_client, cascade=cascade,
    )
    assert cascade.calls == 1


def test_fake_planner_is_used_when_planning_is_on(
    db_session, make_scan, engine_client
) -> None:
    planner = FakePlanner(priority_for=lambda path: "high")
    run_scan(
        db_session, make_scan(),
        options=RunOptions(plan=True), client=engine_client, planner=planner,
    )
    assert planner.seen is not None
