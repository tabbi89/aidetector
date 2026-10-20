"""AI explanations of monitoring observations: optional, read-only, never evidence."""

import importlib.util
import json
import os
import subprocess
import sys
import uuid
from datetime import UTC, datetime
from pathlib import Path
from types import SimpleNamespace

import pytest

from app.ai import provider as provider_module
from app.core.config import settings
from app.models.monitoring import InfrastructureMonitor, MonitoringRun
from app.monitoring import demo, service

TOKEN = "github_pat_monitor_owned"


def github_source(client, *, token=TOKEN):
    body = {
        "name": "repo",
        "target_binding": "https://target.test",
        "connector": "github",
        "config": {"repository": "acme/api", "ref": "main"},
    }
    if token:
        body["credentials"] = {"github_token": token}
    response = client.post("/monitoring/sources", json=body)
    assert response.status_code == 201, response.text
    return response.json()


def demo_monitor(client, db_session, repository=None):
    source = client.post(
        "/monitoring/sources", json={"name": "logs", "target_binding": "https://target.test"}
    ).json()
    monitor = client.post(
        "/monitoring",
        json={
            "name": "demo",
            "target_binding": "https://target.test",
            "source_ids": [source["id"]],
        },
    ).json()
    for day, records in demo.history(datetime.now(UTC).date()):
        response = client.post(
            f"/monitoring/{monitor['id']}/sources/{source['id']}/snapshot",
            params={"observation_date": str(day), "revision": 1},
            headers={"Content-Type": "application/json"},
            content=json.dumps(records),
        )
        assert response.status_code == 200, response.text
    if repository:
        row = db_session.get(InfrastructureMonitor, uuid.UUID(monitor["id"]))
        row.context = {
            "repository": {"repository": "acme/api", "ref": "main"},
            "repository_source_id": repository["id"],
            "repository_revision": repository["revision"],
        }
        db_session.commit()
    run = client.get(f"/monitoring/{monitor['id']}/runs").json()[0]
    observation = next(o for o in run["observations"] if o["type"] == "enumeration_anomaly")
    return monitor["id"], run["id"], observation


def explain(client, monitor_id, run_id, fingerprint):
    return client.post(
        f"/monitoring/{monitor_id}/runs/{run_id}/observations/{fingerprint}/explain"
    )


def stored(client, monitor_id, fingerprint):
    run = client.get(f"/monitoring/{monitor_id}/runs").json()[0]
    return next(o for o in run["observations"] if o["fingerprint"] == fingerprint)


@pytest.fixture
def cursor(monkeypatch):
    monkeypatch.setattr(settings, "monitoring_ai_provider", "cursor")
    monkeypatch.setattr(settings, "cursor_api_key", "cursor-key")
    monkeypatch.setattr(settings, "ai_python", sys.executable)
    monkeypatch.setenv("VAULT_KEY", "vault-secret")
    captured: dict = {}

    def fake_agent(args, payload, env, timeout, on_event=None):
        captured.update(input=payload, env=env)
        if on_event is not None:
            for at, text in [
                ("2026-09-15T19:30:00+00:00", "Agent started · tools offered: mcp"),
                ("2026-09-15T19:30:02+00:00", "→ get_file_contents(path=app/main.py)"),
            ]:
                on_event({"t": at, "text": text})
        structured = {
            "summary": "The handler loads accounts by id without an owner check.",
            "code_refs": [{"path": "app/main.py", "line": 75, "note": "get_account"}],
            "remediation": "Filter by the caller's account.",
            "questions": [],
        }
        stdout = json.dumps(
            {
                "model": "composer-2.5",
                "text": json.dumps(structured),
                "structured": structured,
                "usages": [{"model": "composer-2.5", "tokens_in": 120, "tokens_out": 40}],
            }
        )
        return 0, stdout, ""

    monkeypatch.setattr(provider_module, "_run_agent", fake_agent)
    return captured


def test_disabled_provider_records_a_reason_and_leaves_evidence_alone(client, db_session):
    monitor_id, run_id, observation = demo_monitor(client, db_session)
    assert explain(client, monitor_id, run_id, observation["fingerprint"]).status_code == 202
    after = stored(client, monitor_id, observation["fingerprint"])
    assert after.pop("ai_explanation")["reason"] == "disabled"
    assert after == observation


def test_unknown_or_malformed_observations(client, db_session):
    monitor_id, run_id, _ = demo_monitor(client, db_session)
    assert explain(client, monitor_id, run_id, "0" * 64).status_code == 404
    assert explain(client, monitor_id, run_id, "not-a-fingerprint").status_code == 422


def test_cursor_reads_the_repository_with_the_monitors_own_token(client, db_session, cursor):
    repository = github_source(client)
    monitor_id, run_id, observation = demo_monitor(client, db_session, repository)
    assert explain(client, monitor_id, run_id, observation["fingerprint"]).status_code == 202

    github = json.loads(cursor["env"]["CURSOR_MCP_SERVERS_JSON"])["github"]
    assert github["url"].startswith("https://")
    assert github["headers"]["X-MCP-Readonly"] == "true"
    assert github["headers"]["X-MCP-Toolsets"] == "repos"
    assert github["headers"]["Authorization"] == f"Bearer {TOKEN}"
    assert TOKEN not in cursor["input"]
    assert "VAULT_KEY" not in cursor["env"]
    request = json.loads(cursor["input"])
    assert request["context"]["repository"] == {"repository": "acme/api", "ref": "main"}
    # The explainer is told how the day was sampled, so it reads counts as sample counts.
    assert request["context"]["sampling"]["method"] in {"every_event", "newest_per_hour"}
    assert "cohort" not in request["observation"]
    assert "cohort" not in request["observation"]["current"]

    after = stored(client, monitor_id, observation["fingerprint"])
    explanation = after.pop("ai_explanation")
    assert explanation["status"] == "complete"
    assert explanation["structured"]["code_refs"][0]["path"] == "app/main.py"
    assert (explanation["tokens_in"], explanation["tokens_out"]) == (120, 40)
    assert [line["text"] for line in explanation["log"]][-2:] == [
        "Agent started · tools offered: mcp",
        "→ get_file_contents(path=app/main.py)",
    ]
    assert TOKEN not in json.dumps(explanation)
    assert after == observation


@pytest.mark.parametrize(
    "prepare, reason",
    [
        (lambda client, source: None, "github_not_configured"),
        (
            lambda client, source: client.post(f"/monitoring/sources/{source['id']}/revoke"),
            "repository_unavailable",
        ),
    ],
    ids=["no-token", "revoked"],
)
def test_repository_without_a_usable_token_is_never_offered(
    client, db_session, cursor, prepare, reason
):
    repository = github_source(client, token=None if reason == "github_not_configured" else TOKEN)
    monitor_id, run_id, observation = demo_monitor(client, db_session, repository)
    prepare(client, repository)
    explain(client, monitor_id, run_id, observation["fingerprint"])
    explanation = stored(client, monitor_id, observation["fingerprint"])["ai_explanation"]
    assert (explanation["status"], explanation["reason"]) == ("unavailable", reason)
    assert cursor == {}


def test_explanation_survives_a_recomputed_day(client, db_session, cursor):
    repository = github_source(client)
    monitor_id, run_id, observation = demo_monitor(client, db_session, repository)
    explain(client, monitor_id, run_id, observation["fingerprint"])
    triage = client.put(
        f"/monitoring/{monitor_id}/triage",
        json={"fingerprint": observation["fingerprint"], "disposition": "reviewed"},
    )
    assert triage.status_code == 200
    after = stored(client, monitor_id, observation["fingerprint"])
    assert after["ai_explanation"]["status"] == "complete"

    # Re-collecting the same day used to clear observations before recompute,
    # which discarded an explanation even though its fingerprint still existed.
    monitor = db_session.get(InfrastructureMonitor, uuid.UUID(monitor_id))
    run = db_session.get(MonitoringRun, uuid.UUID(run_id))
    assert monitor is not None and run is not None
    service.ingest_day_metrics(
        db_session,
        monitor,
        dict(run.metrics),
        observation_date=run.observation_date,
        source_revisions={"recollection": "2"},
    )
    after_recollection = stored(client, monitor_id, observation["fingerprint"])
    assert after_recollection["ai_explanation"]["status"] == "complete"


AGENT = Path(__file__).resolve().parents[1] / "ai_runtime" / "monitoring_agent.py"


def load_agent():
    spec = importlib.util.spec_from_file_location("monitoring_agent_under_test", AGENT)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_agent_log_lines_name_steps_but_never_tool_results():
    agent = load_agent()
    system = SimpleNamespace(type="system", tools=["mcp"])
    assert agent._describe(system) == "Agent started · tools offered: mcp"
    running = SimpleNamespace(
        type="tool_call",
        name="get_file_contents",
        status="running",
        args={"owner": "acme", "path": "ajax.php", "content": "$password = 'hunter2';"},
        result=None,
    )
    assert agent._describe(running) == "→ get_file_contents(owner=acme, path=ajax.php)"
    done = SimpleNamespace(
        type="tool_call", name="get_file_contents", status="completed", args={}, result="hunter2"
    )
    assert agent._describe(done) == "✓ get_file_contents returned"
    thinking = SimpleNamespace(type="thinking", text="the password is hunter2")
    assert agent._describe(thinking) == "thinking…"


def test_wrapped_mcp_calls_are_named_without_leaking_contents():
    agent = load_agent()

    def call(args, status="running"):
        return SimpleNamespace(type="tool_call", name="mcp", status=status, args=args)

    nested = {
        "providerIdentifier": "github",
        "toolName": "get_file_contents",
        "args": {"owner": "acme", "repo": "api", "path": "ajax.php", "content": "hunter2"},
    }
    assert agent._describe(call(nested)) == (
        "→ github.get_file_contents(owner=acme, repo=api, path=ajax.php)"
    )
    assert agent._describe(call(nested, "completed")) == "✓ github.get_file_contents returned"
    as_json = {"name": "search_code", "arguments": json.dumps({"q": "phone repo:acme/api"})}
    assert agent._describe(call(as_json)) == "→ search_code(q=phone repo:acme/api)"
    unknown = {"payload": "hunter2", "mode": "fast"}
    assert agent._describe(call(unknown)) == "→ mcp(keys: mode, payload)"
    assert "hunter2" not in "".join(
        agent._describe(call(args)) for args in (nested, as_json, unknown)
    )


def test_tool_calls_are_named_from_interaction_updates():
    agent = load_agent()

    def update(kind, tool_call):
        return SimpleNamespace(
            interaction_update=SimpleNamespace(type=kind, tool_call=tool_call), sdk_message=None
        )

    def bare_sdk_call():
        message = SimpleNamespace(type="tool_call", name="mcp", status="running", args=None)
        return SimpleNamespace(interaction_update=None, sdk_message=message)

    # Before any interaction update, the SDK message is the only signal.
    assert agent._EventDescriber()(bare_sdk_call()) == "→ mcp()"

    describe = agent._EventDescriber()
    wrapped = {
        "mcpToolCall": {
            "args": {
                "providerIdentifier": "github",
                "toolName": "get_file_contents",
                "args": {"path": "ajax.php", "content": "hunter2"},
            }
        }
    }
    assert describe(update("tool-call-started", wrapped)) == (
        "→ github.get_file_contents(path=ajax.php)"
    )
    assert describe(bare_sdk_call()) is None  # already logged from the update
    assert describe(update("tool-call-completed", {**wrapped, "result": "hunter2"})) is not None
    completed = describe(update("tool-call-completed", wrapped))
    assert completed == "✓ github.get_file_contents returned"
    read = update("tool-call-started", {"readToolCall": {"args": {"path": "src/app.php"}}})
    assert describe(read) == "→ read(path=src/app.php)"


def test_busy_lines_collapse_in_the_activity_log(capsys):
    agent = load_agent()
    log = agent._Log()
    for text in ["thinking…", "writing the answer…", "thinking…", "→ search_code()", "thinking…"]:
        log(text)
    lines = [json.loads(line)["event"]["text"] for line in capsys.readouterr().out.splitlines()]
    assert lines == ["thinking…", "→ search_code()", "thinking…"]


@pytest.mark.allow_subprocess
def test_agent_events_stream_live_and_a_hung_agent_is_ended():
    script = (
        "import json, sys; sys.stdin.read(); "
        "print(json.dumps({'event': {'t': 'x', 'text': 'step one'}}), flush=True); "
        "print(json.dumps({'text': 'done'}), flush=True)"
    )
    seen: list[dict] = []
    code, result, _ = provider_module._run_agent(
        [sys.executable, "-c", script], "{}", dict(os.environ), 20, seen.append
    )
    assert (code, json.loads(result)) == (0, {"text": "done"})
    assert seen == [{"t": "x", "text": "step one"}]
    hang = "import sys, time; sys.stdin.read(); time.sleep(120)"
    with pytest.raises(subprocess.TimeoutExpired):
        provider_module._run_agent([sys.executable, "-c", hang], "{}", dict(os.environ), 1)
