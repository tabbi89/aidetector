"""Scan levels: what each level expands to, and that every run path expands it.

The rules that matter are safety rules, so they are pinned here directly: a
level never implies writes, AI is never on unless asked for, a level leaves out
what the tenant or the lane cannot run instead of failing, and an explicit flag
still answers its own gate.
"""
from __future__ import annotations

import pytest

from app.core.config import settings
from app.scans.run_levels import LEVELS, LOCAL_REFUSED, expand


def _on(level, **kw):
    args = {"ai": False, "writes": False, "entitled": True, "lane": "server", **kw}
    return set(expand(level, **args))


# ---- the pure expansion ------------------------------------------------------


def test_no_level_and_no_ai_adds_nothing():
    assert _on(None) == set()


def test_quick_is_the_engine_tier_alone():
    assert _on("quick") == set()


def test_standard_adds_fuzzing_and_premium():
    assert _on("standard") == {"fuzz", "premium"}


def test_deep_adds_the_external_tools():
    assert _on("deep") == {"fuzz", "premium", "zap", "kali", "confirm", "testssl"}


@pytest.mark.parametrize("level", ["quick", "standard"])
def test_the_fast_levels_never_run_an_external_tool(level):
    # The web's levels: testssl alone can take five minutes, so it is Deep-only.
    tools = {"zap", "kali", "confirm", "testssl"}
    assert not _on(level, ai=True, writes=True) & tools


def test_levels_are_cumulative():
    previous: set[str] = set()
    for level in LEVELS:
        current = _on(level, ai=True, writes=True)
        assert previous <= current, level
        previous = current


@pytest.mark.parametrize("level", [None, *LEVELS])
@pytest.mark.parametrize("ai", [False, True])
@pytest.mark.parametrize("entitled", [False, True])
@pytest.mark.parametrize("lane", ["server", "local"])
def test_no_level_ever_turns_on_writes(level, ai, entitled, lane):
    assert "mutate" not in _on(level, ai=ai, writes=True, entitled=entitled, lane=lane)


@pytest.mark.parametrize("level", LEVELS)
def test_no_level_spends_tokens_without_the_ai_switch(level):
    ai_passes = {"plan", "adjudicate", "security_review", "genai_payloads", "adaptive",
                 "resource_refine"}
    assert not _on(level, writes=True) & ai_passes


def test_ai_without_a_level_reads_as_quick():
    assert _on(None, ai=True) == {"plan", "adjudicate", "security_review"}


def test_deep_ai_adds_the_premium_ai_passes_only_with_writes_for_refinement():
    assert _on("deep", ai=True) >= {"genai_payloads", "adaptive"}
    assert "resource_refine" not in _on("deep", ai=True)
    assert "resource_refine" in _on("deep", ai=True, writes=True)


def test_an_unentitled_tenant_gets_the_level_without_its_premium_passes():
    assert _on("standard", entitled=False) == {"fuzz"}
    deep = _on("deep", ai=True, writes=True, entitled=False)
    assert not deep & {"premium", "adaptive", "resource_refine"}


def test_a_local_run_now_performs_every_pass_a_server_run_does():
    # LOCAL_REFUSED is empty: a local run performs the same passes as a server
    # run at the same level — the lane no longer narrows the set.
    assert _on("deep", lane="local") == _on("deep")
    assert _on("deep", ai=True, writes=True, lane="local") == _on("deep", ai=True, writes=True)


def test_every_name_a_level_turns_on_is_a_real_pass():
    """A typo would silently drop a pass; a non-pass name could answer a gate."""
    from app.api.schemas import RunRequest
    from app.scans.run_levels import EXPANDABLE, LEVEL_AI_PASSES, LEVEL_PASSES

    request_bools = {
        name for name, info in RunRequest.model_fields.items() if info.annotation is bool
    }
    for table in (LEVEL_PASSES, LEVEL_AI_PASSES):
        for level, names in table.items():
            assert set(names) <= EXPANDABLE, level
            assert set(names) <= request_bools, level
    assert not EXPANDABLE & {"mutate", "agent", "authorized", "ai"}


def test_a_bad_table_entry_still_cannot_authorize_or_write(monkeypatch):
    from app.scans import run_levels

    monkeypatch.setitem(
        run_levels.LEVEL_PASSES, "deep", ("fuzz", "authorized", "mutate", "fuz")
    )
    assert _on("deep") == {"fuzz"}


def test_the_gate_reads_authorization_from_the_request_not_the_expansion(monkeypatch):
    from fastapi import HTTPException

    from app.api.routes.scans import _shared
    from app.api.schemas import RunRequest

    real = RunRequest.resolved

    def forged(self, **kw):
        return real(self, **kw).model_copy(update={"authorized": True})

    monkeypatch.setattr(RunRequest, "resolved", forged)
    monkeypatch.setattr("app.scans.workspace.is_premium", lambda db, tenant: False)
    with pytest.raises(HTTPException) as refused:
        _shared._require_run_authorization(
            RunRequest(authorized=False, level="deep"), "tenant", db=None  # type: ignore[arg-type]
        )
    assert refused.value.status_code == 403


def test_the_local_claim_refuses_exactly_what_the_level_leaves_out():
    from app.api.routes import runner

    assert runner._LOCAL_REFUSED == LOCAL_REFUSED


def test_resolving_a_request_keeps_explicit_flags():
    from app.api.schemas import RunRequest

    body = RunRequest(authorized=True, level="standard", kali=True, mutate=True)
    opts = body.resolved(entitled=False, lane="server").to_options()
    assert (opts.fuzz, opts.premium, opts.kali, opts.mutate) == (True, False, True, True)


def test_an_unknown_level_is_rejected():
    from pydantic import ValidationError

    from app.api.schemas import RunRequest

    with pytest.raises(ValidationError):
        RunRequest(authorized=True, level="max")


# ---- every path that starts scans expands it ------------------------------------


@pytest.fixture
def sent(monkeypatch):
    from app.api.routes import scans as routes

    captured: list[dict] = []
    monkeypatch.setattr(routes.run_scan_task, "delay", lambda *a, **kw: captured.append(kw))
    return captured


def test_a_run_expands_its_level_for_an_entitled_tenant(client, scan_with_spec, sent,
                                                         monkeypatch):
    monkeypatch.setattr(settings, "premium_tenants", "*")
    sid = scan_with_spec()
    r = client.post(f"/scans/{sid}/run", json={"authorized": True, "level": "standard"})
    assert r.status_code == 202, r.text
    options = sent[0]["options"]
    assert options["fuzz"] is True and options["premium"] is True
    assert options["mutate"] is False and options["plan"] is False


@pytest.mark.parametrize("level", [None, "quick", "standard", "deep"])
def test_server_execution_requires_premium_at_every_level(client, scan_with_spec, sent,
                                                          monkeypatch, level):
    monkeypatch.setattr(settings, "premium_tenants", "someone-else")
    sid = scan_with_spec()
    r = client.post(f"/scans/{sid}/run", json={"authorized": True, "level": level})
    assert r.status_code == 402, r.text
    assert "local CLI" in r.json()["detail"]
    assert sent == []
    assert client.get(f"/scans/{sid}").json()["status"] == "draft"


def test_an_explicit_premium_flag_is_still_refused_for_a_free_tenant(client, scan_with_spec,
                                                                    sent, monkeypatch):
    monkeypatch.setattr(settings, "premium_tenants", "someone-else")
    sid = scan_with_spec()
    r = client.post(
        f"/scans/{sid}/run", json={"authorized": True, "level": "standard", "premium": True}
    )
    assert r.status_code == 402
    assert sent == []


def test_workspace_plan_controls_server_execution_without_a_dev_override(
    client, scan_with_spec, sent, db_session, monkeypatch,
):
    from app.scans import workspace

    monkeypatch.setattr(settings, "premium_tenants", "")
    sid = scan_with_spec()
    tenant = workspace.ensure_tenant(db_session, "default")
    tenant.plan = "free"
    db_session.commit()
    assert client.post(f"/scans/{sid}/run", json={"authorized": True}).status_code == 402
    assert sent == []
    tenant.plan = "premium"
    db_session.commit()
    assert client.post(f"/scans/{sid}/run", json={"authorized": True}).status_code == 202
    assert len(sent) == 1


def test_a_level_does_not_answer_the_authorization_gate(client, scan_with_spec, sent):
    sid = scan_with_spec()
    r = client.post(f"/scans/{sid}/run", json={"authorized": False, "level": "deep"})
    assert r.status_code == 403
    assert sent == []


def test_a_schedule_saves_the_expanded_options(client, scan_with_spec, db_session,
                                               monkeypatch):
    monkeypatch.setattr(settings, "premium_tenants", "*")
    sid = scan_with_spec()
    r = client.put(
        f"/scans/{sid}/schedule",
        json={"minutes": 60, "authorized": True, "level": "standard", "ai": True},
    )
    assert r.status_code == 200, r.text
    import uuid

    from app.models.scan import Scan

    db_session.expire_all()
    saved = db_session.get(Scan, uuid.UUID(sid)).schedule_options
    assert saved["fuzz"] is True and saved["plan"] is True
    assert saved["premium"] is True and saved.get("mutate", False) is False


def test_a_local_claim_at_deep_runs_what_the_runner_can(client, scan_with_spec, monkeypatch):
    monkeypatch.setattr(settings, "local_runner_enabled", True)
    monkeypatch.setattr(settings, "premium_tenants", "someone-else")
    sid = scan_with_spec("http://127.0.0.1")
    r = client.post(
        f"/scans/{sid}/local-runs", json={"authorized": True, "level": "deep", "ai": True}
    )
    assert r.status_code == 201, r.text
    options = r.json()["options"]
    assert options["fuzz"] is True and options["security_review"] is True
    assert not options.get("premium") and not options.get("adaptive")
    assert not any(options.get(name) for name in LOCAL_REFUSED)


def test_a_local_claim_accepts_an_explicit_heavy_pass(client, scan_with_spec, monkeypatch):
    monkeypatch.setattr(settings, "local_runner_enabled", True)
    monkeypatch.setattr(settings, "premium_tenants", "*")
    sid = scan_with_spec("http://127.0.0.1")
    r = client.post(
        f"/scans/{sid}/local-runs",
        json={"authorized": True, "level": "deep", "adaptive": True,
              "premium": True, "mutate": True},
    )
    assert r.status_code == 201, r.text
