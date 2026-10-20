"""PLANNER_PROVIDER: DeepSeek-only by default, Opus only when asked for."""
from __future__ import annotations

import asyncio
import json
import sys
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock

import pytest

from ai_runtime import plan_agent
from app.ai import planner as planner_mod
from app.ai.planner import OpusPlanner, PlannerUnavailable
from app.ai.subprocess_env import INHERITED_ENV
from app.core.config import settings
from app.scans import capabilities

_AGENT_MODES = ("adjudicate", "plan", "adaptive", "propose_resource")

_REPLIES = {
    "adjudicate": '[{"id": "f1", "verdict": "confirmed", "rationale": "r"}]',
    "plan": '[{"operation_id": "op1", "priority": "high", "rationale": "r"}]',
    "adaptive": '{"action": "stop", "variant": null, "assessment": "accepted"}',
    "propose_resource": '{"proposal": {"name": "x"}}',
}


def _cfg(mode: str) -> dict:
    return {
        "provider": "deepseek",
        "mode": mode,
        "planner_model": "deepseek-chat",
        "executor_model": "deepseek-chat",
        "deepseek_base_url": "https://api.deepseek.com",
        "findings": [{"id": "f1"}],
        "operations": [{"operation_id": "op1"}],
        "payload": {"route": "/x"},
    }


@pytest.mark.parametrize("mode", _AGENT_MODES)
def test_deepseek_provider_runs_agent_modes_without_the_sdk(monkeypatch, mode):
    # The SDK import would raise: the direct path must never reach it.
    monkeypatch.setitem(sys.modules, "claude_agent_sdk", None)
    chat = Mock(return_value=(_REPLIES[mode], {"model": "deepseek-chat", "phase": mode}))
    monkeypatch.setattr(plan_agent, "_deepseek_chat", chat)

    out = asyncio.run(plan_agent._run(_cfg(mode)))

    system, prompt, model, _base, phase, max_tokens = chat.call_args.args
    assert "triage" not in system.lower()
    assert model == "deepseek-chat" and phase == mode
    assert max_tokens >= (8000 if mode in ("plan", "adjudicate") else 4000)
    assert out["usages"] == [{"model": "deepseek-chat", "phase": mode}]
    if mode == "adjudicate":
        assert out["verdicts"][0]["verdict"] == "confirmed"
        assert "f1" in prompt
    elif mode == "plan":
        assert out["plan"][0]["priority"] == "high"
    elif mode == "adaptive":
        assert out["proposal"]["action"] == "stop"
    else:
        assert out["proposal"] == {"name": "x"}


def test_direct_prompts_only_lose_the_tool_hints():
    assert plan_agent._system("adjudicate", direct=False) == plan_agent._SYSTEM
    assert plan_agent._TRIAGE_HINT in plan_agent._SYSTEM
    direct = plan_agent._system("adjudicate", direct=True)
    assert direct == plan_agent._SYSTEM.replace(plan_agent._TRIAGE_HINT, "")
    assert "UNTRUSTED" in direct  # the prompt-injection guard stays

    assert plan_agent._ADAPTIVE_TRIAGE_HINT in plan_agent._ADAPTIVE_SYSTEM
    adaptive = plan_agent._system("adaptive", direct=True)
    assert "Never invent values, fields, request methods" in adaptive
    assert "triage" not in adaptive.lower()


def test_missing_provider_defaults_to_deepseek(monkeypatch):
    monkeypatch.setitem(sys.modules, "claude_agent_sdk", None)
    chat = Mock(return_value=(_REPLIES["plan"], {"phase": "plan"}))
    monkeypatch.setattr(plan_agent, "_deepseek_chat", chat)
    cfg = _cfg("plan")
    del cfg["provider"]
    assert asyncio.run(plan_agent._run(cfg))["plan"]


def test_default_settings_use_deepseek_for_the_planner():
    assert settings.planner_provider == "deepseek"
    planner = OpusPlanner()
    assert planner.provider == "deepseek"
    assert planner.model == settings.executor_model


def test_deepseek_planner_falls_back_to_this_interpreter(monkeypatch, tmp_path):
    monkeypatch.setattr(settings, "ai_python", str(tmp_path / "missing-python"))
    assert OpusPlanner().python == Path(sys.executable)

    monkeypatch.setattr(settings, "planner_provider", "anthropic")
    # The Agent SDK needs its venv: no silent fallback there.
    assert OpusPlanner().python == tmp_path / "missing-python"
    assert OpusPlanner().model == settings.planner_model


def test_deepseek_planner_without_a_key_is_unavailable(monkeypatch):
    run = Mock()
    monkeypatch.setattr(planner_mod.subprocess, "run", run)
    with pytest.raises(PlannerUnavailable, match="DEEPSEEK_API_KEY"):
        OpusPlanner().plan([])
    run.assert_not_called()


def test_deepseek_planner_never_hands_the_anthropic_key_over(monkeypatch):
    monkeypatch.setattr(settings, "deepseek_api_key", "ds-test")
    monkeypatch.setattr(settings, "anthropic_api_key", "sk-ant-test")
    monkeypatch.setattr(settings, "anthropic_workspace_id", "ws-test")
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    seen: dict = {}

    def fake_run(argv, *, input, env, **_kwargs):
        seen["cfg"], seen["env"] = json.loads(input), env
        return SimpleNamespace(returncode=0, stdout='{"plan": [], "usages": []}', stderr="")

    monkeypatch.setattr(planner_mod.subprocess, "run", fake_run)
    OpusPlanner().plan([])
    assert seen["cfg"]["provider"] == "deepseek"
    assert seen["cfg"]["planner_model"] == settings.executor_model
    assert seen["env"]["DEEPSEEK_API_KEY"] == "ds-test"
    assert "ANTHROPIC_API_KEY" not in seen["env"]
    assert "ANTHROPIC_CUSTOM_HEADERS" not in seen["env"]

    monkeypatch.setattr(settings, "planner_provider", "anthropic")
    monkeypatch.setattr(settings, "ai_python", sys.executable)  # stands in for .venv-ai
    OpusPlanner().plan([])
    assert seen["cfg"]["provider"] == "anthropic"
    assert seen["env"]["ANTHROPIC_API_KEY"] == "sk-ant-test"


_WORKER_SECRETS = {
    "VAULT_KEY": "vault-test",
    "DATABASE_URL": "postgresql://u:p@db/x",
    "REDIS_URL": "redis://redis:6379/0",
    "AWS_SECRET_ACCESS_KEY": "aws-test",
    "API_KEYS": "tenant:key-test",
}


@pytest.mark.parametrize("provider", ["deepseek", "anthropic"])
def test_planner_subprocess_gets_an_allowlist_not_the_worker_env(monkeypatch, provider):
    for name, value in _WORKER_SECRETS.items():
        monkeypatch.setenv(name, value)
    monkeypatch.setenv("PATH", "/usr/bin")
    monkeypatch.setenv("CLAUDE_CONFIG_DIR", "/opt/claude")
    monkeypatch.setattr(settings, "planner_provider", provider)
    monkeypatch.setattr(settings, "ai_python", sys.executable)
    monkeypatch.setattr(settings, "deepseek_api_key", "ds-test")
    seen: dict = {}

    def fake_run(argv, *, input, env, **_kwargs):
        seen["env"] = env
        return SimpleNamespace(returncode=0, stdout='{"plan": [], "usages": []}', stderr="")

    monkeypatch.setattr(planner_mod.subprocess, "run", fake_run)
    OpusPlanner().plan([])

    env = seen["env"]
    assert not set(_WORKER_SECRETS) & set(env)
    assert env["PATH"] == "/usr/bin" and env["DEEPSEEK_API_KEY"] == "ds-test"
    # The claude CLI's own settings ride along only where the CLI runs.
    assert ("CLAUDE_CONFIG_DIR" in env) is (provider == "anthropic")
    allowed = set(INHERITED_ENV) | {
        "DEEPSEEK_API_KEY", "EXECUTOR_MAX_TOKENS", "ANTHROPIC_API_KEY",
        "CLAUDE_CONFIG_DIR", "ANTHROPIC_BASE_URL",
    }
    assert set(env) <= allowed


def test_capabilities_report_a_missing_deepseek_key(monkeypatch):
    monkeypatch.setattr(settings, "ai_python", sys.executable)
    cap = capabilities._ai_runtime()
    assert cap["available"] is False and "DEEPSEEK_API_KEY" in cap["reason"]

    monkeypatch.setattr(settings, "deepseek_api_key", "ds-test")
    assert capabilities._ai_runtime()["available"] is True

