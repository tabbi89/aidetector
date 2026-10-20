"""The opt-in AI payload-design phase (Phase 4).

DB-free: the phase touches only ``scan.ledger``/``scan.cost_cents`` and a
``db.commit()``, so lightweight doubles stand in. Covers the three outcomes that
matter — a good proposal installs an augmented provider and meters cost; an AI
failure and an all-junk proposal both degrade to the curated + corpus rotation
without touching the ledger — plus the property that the reflection check
actually rotates over the augmented pool.
"""
from __future__ import annotations

from types import SimpleNamespace

from app.ai.types import Usage
from app.engine import ai_phases
from app.engine.payloads import FAMILIES
from app.engine.runner import _Deps, _stages
from app.scans.run_options import RunOptions
from tests import factories


def _scan():
    return SimpleNamespace(progress=0, ledger=[], cost_cents=0)


def _db():
    return SimpleNamespace(commit=lambda: None)


class _Designer:
    """A planner double that returns a canned family->variants map."""

    def __init__(self, payloads, usages=None):
        self._payloads = payloads
        self._usages = usages or []
        self.seen = None

    def generate_payloads(self, families_payload):
        self.seen = families_payload
        return self._payloads, self._usages


class _Broken:
    def generate_payloads(self, families_payload):
        raise RuntimeError("ai unavailable")


def _events():
    events: list[tuple] = []
    return events, lambda *a: events.append(a)


def test_good_proposal_installs_provider_and_meters_cost():
    ctx = factories.scan_context(factories.engine_operations())
    scan = _scan()
    events, emit = _events()
    designer = _Designer(
        {"xss": ["<svg/onload=aidx{m}>", "plainword"]},  # one good, one dropped
        [Usage(model="deepseek-chat", phase="payloads", tokens_in=40, tokens_out=12)],
    )

    ai_phases.generate_payloads(_db(), scan, ctx, None, designer, emit)

    assert ctx.payload_provider is not None
    templates = {p.template for p in ctx.payload_provider.rotating_set(1, per_family=999)}
    assert any("onload=aidx{m}" in t for t in templates)
    assert "plainword" not in templates  # junk variant was dropped
    assert scan.ledger and scan.ledger[0].phase == "payloads"
    assert any(e[0] == "genai_payloads_ready" for e in events)
    # The designer was handed families with example templates, no target data.
    assert {f["family"] for f in designer.seen} == set(FAMILIES)
    assert all(f["examples"] for f in designer.seen)


def test_reflected_injection_rotates_over_the_augmented_pool():
    # With the provider installed, the check draws from ctx, so an AI variant can
    # be the one selected for a family on a given seed.
    ctx = factories.scan_context(factories.engine_operations())
    scan = _scan()
    _events_list, emit = _events()
    variant = "<aidx{m} data-x=1>"
    ai_phases.generate_payloads(
        _db(), scan, ctx, None, _Designer({"xss": [variant]}), emit
    )
    # Across seeds the augmented variant is eventually selected for xss.
    picked = set()
    for seed in range(60):
        ctx.seed = seed
        picked.update(p.template for p in ctx.reflection_payloads(per_family=1))
    assert variant in picked


def test_ai_failure_degrades_to_curated_rotation():
    ctx = factories.scan_context(factories.engine_operations())
    scan = _scan()
    events, emit = _events()

    ai_phases.generate_payloads(_db(), scan, ctx, None, _Broken(), emit)

    assert ctx.payload_provider is None
    assert scan.ledger == []
    assert any(e[0] == "genai_payloads_skipped" for e in events)


def test_runner_stage_wires_the_phase_to_the_planner_and_context():
    # The end-to-end wiring: the Stage built by _stages, when run, must call
    # ai_phases.generate_payloads with deps.planner and install the provider on
    # ctx. This catches a regression the phase-only unit tests would miss (a
    # stage that stops threading deps.planner, or is gated wrong).
    ctx = factories.scan_context(factories.engine_operations())
    events, emit = _events()
    journal = SimpleNamespace(
        db=_db(), scan=_scan(), run_row=None, event=emit, apply_triage=lambda: None
    )
    designer = _Designer({"xss": ["<svg/onload=aidx{m}>"]})

    stages = _stages(ctx, RunOptions(genai_payloads=True), journal, _Deps(planner=designer))
    stage = next(s for s in stages if s.name == "genai_payloads")
    assert stage.enabled
    stage.run()

    assert ctx.payload_provider is not None
    assert designer.seen is not None  # the phase actually invoked the planner
    assert any(e[0] == "genai_payloads_ready" for e in events)


def test_runner_stage_is_disabled_by_default():
    ctx = factories.scan_context(factories.engine_operations())
    journal = SimpleNamespace(
        db=_db(), scan=_scan(), run_row=None, event=lambda *a: None, apply_triage=lambda: None
    )
    stages = _stages(ctx, RunOptions(), journal, _Deps())
    stage = next(s for s in stages if s.name == "genai_payloads")
    assert not stage.enabled


def test_all_junk_proposal_is_skipped():
    ctx = factories.scan_context(factories.engine_operations())
    scan = _scan()
    events, emit = _events()

    ai_phases.generate_payloads(
        _db(), scan, ctx, None, _Designer({"xss": ["plainword"], "bogus": ["<x>aidx{m}"]}), emit
    )

    assert ctx.payload_provider is None
    assert scan.ledger == []
    assert any(e[0] == "genai_payloads_skipped" for e in events)
