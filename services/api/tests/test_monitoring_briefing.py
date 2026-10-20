"""AI traffic briefings: optional, value-free, commentary beside the evidence."""

import importlib.util
import json
import sys
import uuid
from datetime import UTC, datetime
from pathlib import Path

import pytest

from app.ai import provider as provider_module
from app.core.config import settings
from app.models.monitoring import InfrastructureMonitor, MonitoringRun
from app.monitoring import analysis, bots, briefing, clients, demo, lb

BRIEFING = {
    "headline": "One client walked account ids; the AI crawlers are normal.",
    "verdict": "act_now",
    "traffic_summary": "Mostly verified search engines.",
    "act_now": [{"title": "Enumeration", "why": "ids 1-80", "action": "Check ownership",
                 "lead_type": "enumeration_anomaly"}],
    "review": [],
    "safe_to_ignore": [{"title": "Googlebot", "why": "verified"}],
    "alerting": {"current_state": "anomaly", "will_alert_when": ["state changes"], "gaps": []},
    "questions": [],
}


def demo_monitor(client):
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
    return monitor["id"]


@pytest.fixture
def cursor(monkeypatch):
    monkeypatch.setattr(settings, "monitoring_ai_provider", "cursor")
    monkeypatch.setattr(settings, "cursor_api_key", "cursor-key")
    monkeypatch.setattr(settings, "ai_python", sys.executable)
    captured: dict = {}

    def fake_agent(args, payload, env, timeout, on_event=None):
        captured.update(input=payload, env=env)
        if on_event is not None:
            started = "Agent started · tools offered: mcp"
            on_event({"t": "2026-09-16T10:00:00+00:00", "text": started})
        stdout = json.dumps({
            "model": "composer-2.5",
            "text": json.dumps(BRIEFING),
            "structured": BRIEFING,
            "usages": [{"model": "composer-2.5", "tokens_in": 900, "tokens_out": 300}],
        })
        return 0, stdout, ""

    monkeypatch.setattr(provider_module, "_run_agent", fake_agent)
    return captured


def test_no_briefing_until_one_is_asked_for(client):
    monitor_id = demo_monitor(client)
    response = client.get(f"/monitoring/{monitor_id}/briefing")
    assert response.status_code == 200
    assert response.json()["status"] == "none"
    assert client.post(f"/monitoring/{monitor_id}/briefing", params={"days": 0}).status_code == 422
    assert client.get(f"/monitoring/{uuid.uuid4()}/briefing").status_code == 404


def test_disabled_provider_records_a_reason(client):
    monitor_id = demo_monitor(client)
    before = client.get(f"/monitoring/{monitor_id}/runs").json()
    assert client.post(f"/monitoring/{monitor_id}/briefing").status_code == 202
    stored = client.get(f"/monitoring/{monitor_id}/briefing").json()
    assert (stored["status"], stored["reason"]) == ("unavailable", "disabled")
    assert client.get(f"/monitoring/{monitor_id}/runs").json() == before


def test_cursor_briefs_from_value_free_evidence_and_the_detectors_rules(client, cursor):
    monitor_id = demo_monitor(client)
    before = client.get(f"/monitoring/{monitor_id}/runs").json()
    response = client.post(f"/monitoring/{monitor_id}/briefing", params={"days": 14})
    assert response.status_code == 202

    request = json.loads(cursor["input"])
    assert request["mode"] == "monitoring_briefing"
    evidence = request["evidence"]
    assert evidence["window_days"] == 14
    assert {rule["type"] for rule in evidence["rules"]} >= (
        set(bots.REMEDIATION) | set(clients.REMEDIATION)
    )
    assert evidence["alerting"] == briefing.ALERTING
    assert evidence["latest_day"]["open_leads"]
    assert "cohort" not in cursor["input"]
    assert json.loads(cursor["env"]["CURSOR_MCP_SERVERS_JSON"]) == {}
    assert "VAULT_KEY" not in cursor["env"]

    stored = client.get(f"/monitoring/{monitor_id}/briefing").json()
    assert stored["status"] == "complete"
    assert stored["structured"]["verdict"] == "act_now"
    assert (stored["tokens_in"], stored["tokens_out"], stored["days"]) == (900, 300, 14)
    assert stored["evidence_through"] == evidence["latest_day"]["date"]
    assert stored["evidence_trimmed"] == []
    assert [line["text"] for line in stored["log"]][-1] == "Agent started · tools offered: mcp"
    # Commentary only: the runs, their observations and states are untouched.
    assert client.get(f"/monitoring/{monitor_id}/runs").json() == before


def test_a_superseded_request_never_overwrites_the_newer_one(client, db_session, monkeypatch):
    monitor_id = demo_monitor(client)
    monitor = db_session.get(InfrastructureMonitor, uuid.UUID(monitor_id))
    briefing.request(db_session, monitor, 7)
    newer = {"status": "pending", "requested_at": "newer", "days": 7}

    class Racing:
        def brief(self, evidence, *, on_event=None):
            with briefing.SessionLocal() as db:
                row = db.get(InfrastructureMonitor, uuid.UUID(monitor_id))
                row.ai_briefing = newer
                db.commit()
            return provider_module.ProviderResponse("cursor", "m", "{}")

    monkeypatch.setattr(briefing, "build_monitoring_provider", Racing)
    assert briefing.run_briefing(monitor_id) == {"status": "superseded"}
    db_session.expire_all()
    assert db_session.get(InfrastructureMonitor, uuid.UUID(monitor_id)).ai_briefing == newer


def test_briefing_evidence_is_bounded_and_says_what_was_cut(client, db_session, monkeypatch):
    monitor_id = demo_monitor(client)
    monitor = db_session.get(InfrastructureMonitor, uuid.UUID(monitor_id))
    whole = briefing.evidence(db_session, monitor, 28)
    assert whole["evidence_trimmed"] == []
    monkeypatch.setattr(briefing, "MAX_EVIDENCE_BYTES", 1)
    evidence = briefing.evidence(db_session, monitor, 28)
    assert "series" not in evidence["bots"]
    assert len(evidence["latest_day"]["open_leads"]) <= 10
    assert all("current" not in lead for lead in evidence["lead_history"])
    assert evidence["evidence_trimmed"][0] == "daily bot category series"
    assert evidence["evidence_trimmed"][-1] == "still over the size budget"


def test_every_lead_type_has_a_rule_with_its_real_thresholds():
    emitted = (
        set(analysis.REMEDIATION) | set(bots.REMEDIATION)
        | set(clients.REMEDIATION) | set(lb.REMEDIATION)
    )
    rules = {rule["type"]: rule for rule in briefing.rules()}
    assert set(rules) == emitted
    assert all(rule["severity"] != "varies" for rule in rules.values())
    assert f"at least {analysis.DAY_ENUM_IDENTIFIERS} distinct" in rules["enumeration_anomaly"][
        "trigger"
    ]
    assert "Before the baseline only" in rules["high_volume_client"]["trigger"]


def test_earlier_leads_suppressed_leads_load_balancer_and_crawler_routes(client, db_session):
    monitor_id = demo_monitor(client)
    run = client.get(f"/monitoring/{monitor_id}/runs").json()[0]
    hidden = run["observations"][0]
    triage = client.put(
        f"/monitoring/{monitor_id}/triage",
        json={"fingerprint": hidden["fingerprint"], "disposition": "suppressed"},
    )
    assert triage.status_code == 200
    monitor = db_session.get(InfrastructureMonitor, uuid.UUID(monitor_id))
    db_session.refresh(monitor)
    latest_run = db_session.get(MonitoringRun, uuid.UUID(run["id"]))
    latest_run.metrics = {
        **latest_run.metrics,
        "origin": demo.day_load_balancer(latest_run.observation_date, attack=True),
    }
    db_session.commit()
    evidence = briefing.evidence(db_session, monitor, 28)

    latest = evidence["latest_day"]
    assert latest["suppressed_leads_total"] == 1
    assert latest["suppressed_leads"][0]["type"] == hidden["type"]
    assert "current" not in latest["suppressed_leads"][0]

    history = {(lead["type"], lead["last_seen"]): lead for lead in evidence["lead_history"]}
    assert history, "the demo has leads"
    for lead in evidence["lead_history"]:
        assert lead["days"] and lead["first_seen"] <= lead["last_seen"]
        assert lead["on_latest_day"] == (lead["last_seen"] == latest["date"])
        # Evidence lives on the latest day for open leads, on the history for earlier ones.
        assert ("current" in lead) != lead["on_latest_day"]
    assert any(lead["disposition"] == "suppressed" for lead in evidence["lead_history"])

    lb_days = evidence["load_balancer_days"]
    assert lb_days and lb_days[-1]["date"] == latest["date"]
    assert {"server_error_rate", "worst_5xx_hours", "slowest_hours"} <= set(lb_days[-1])

    assert any(row.get("routes") for row in evidence["bots"]["crawlers"])
    assert all(len(row["routes"]) <= briefing.MAX_CRAWLER_ROUTES
               for row in evidence["bots"]["crawlers"])
    # The page's own bot endpoint keeps its shape.
    page = client.get(f"/monitoring/{monitor_id}/bots").json()
    assert all("routes" not in row for row in page["crawlers"])


def test_briefing_prompt_carries_rules_schema_and_evidence():
    path = Path(__file__).resolve().parents[1] / "ai_runtime" / "monitoring_agent.py"
    spec = importlib.util.spec_from_file_location("monitoring_agent_briefing", path)
    assert spec is not None and spec.loader is not None
    agent = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(agent)
    prompt = agent._briefing_prompt({"evidence": {"window_days": 7, "rules": [{"type": "x"}]}})
    assert '"verdict": "act_now" | "review" | "all_clear" | "not_enough_data"' in prompt
    assert '"window_days": 7' in prompt
    assert '"earlier": [' in prompt and "lead_history" in prompt and "evidence_trimmed" in prompt
    assert "do not invent other" in prompt


def test_every_complete_day_says_how_it_was_sampled(client, db_session):
    monitor_id = demo_monitor(client)
    monitor = db_session.get(InfrastructureMonitor, uuid.UUID(monitor_id))
    runs = client.get(f"/monitoring/{monitor_id}/runs").json()
    latest_run = db_session.get(MonitoringRun, uuid.UUID(runs[0]["id"]))
    origin = demo.day_load_balancer(latest_run.observation_date, attack=True)
    latest_run.metrics = {
        **latest_run.metrics,
        "origin": origin,
        "sample": {"strategy": "newest_per_hour", "per_hour": 834, "limit": 20_000,
                   "kept": 20_000, "read": 27_000},
    }
    db_session.commit()
    evidence = briefing.evidence(db_session, monitor, 28)

    sampling = evidence["latest_day"]["sampling"]
    lb_requests = origin["total"]["requests"]
    assert sampling == {
        "method": "newest_per_hour", "per_hour": 834, "kept": 20_000,
        "load_balancer_requests": lb_requests, "kept_share": round(20_000 / lb_requests, 4),
    }
    assert evidence["latest_day"]["sampled"] is True
    by_date = {day["date"]: day for day in evidence["days"]}
    assert by_date[evidence["latest_day"]["date"]]["sampling"] == sampling
    # A day that kept every event says so rather than leaving the model to guess.
    earlier = [day for day in evidence["days"] if day["date"] != evidence["latest_day"]["date"]]
    assert earlier and all(day["sampling"] == {"method": "every_event"} for day in earlier)


def test_a_sampled_day_without_load_balancer_totals_has_no_share(db_session):
    run = MonitoringRun(metrics={"event_count": 900, "sample": {"strategy": "newest_per_hour",
                                                               "per_hour": 50}})
    assert briefing.day_sampling(run) == {
        "method": "newest_per_hour", "per_hour": 50, "kept": 900,
    }


def test_briefing_prompt_forbids_reading_a_sample_as_totals_or_absence():
    path = Path(__file__).resolve().parents[1] / "ai_runtime" / "monitoring_agent.py"
    spec = importlib.util.spec_from_file_location("monitoring_agent_sampling", path)
    assert spec is not None and spec.loader is not None
    agent = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(agent)
    prompt = agent._briefing_prompt({"evidence": {"window_days": 7}})
    assert "Absence in a sampled day is not evidence of stopping" in prompt
    assert "'N in the sample'" in prompt and "load_balancer_days" in prompt
    assert "Bot Control" in prompt and "all allowed" in prompt
    assert "that they stopped" not in prompt
    explain = agent._prompt({"observation": {"type": "high_volume_client"}, "context": {}}, False)
    assert "newest_per_hour" in explain


def test_the_high_volume_rule_says_it_counts_the_sample():
    rule = next(r for r in briefing.rules() if r["type"] == "high_volume_client")
    assert "newest events of the hour" in rule["trigger"]
