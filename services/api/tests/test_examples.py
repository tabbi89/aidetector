"""Dev-only examples on the bundled target, so a demo needs no typing."""

import json
from datetime import UTC, datetime, timedelta

import pytest

from app.core.config import settings
from app.monitoring import demo, rapid_service, setup

# Shaped like services/target's published spec: raw Authorization header, no securitySchemes.
SPEC = json.dumps(
    {
        "openapi": "3.1.0",
        "info": {"title": "vulnbank", "version": "0.1.0"},
        "paths": {
            "/login": {"post": {"responses": {"200": {"description": "ok"}}}},
            "/users/me": {"get": {"responses": {"200": {"description": "ok"}}}},
            "/accounts/{account_id}": {
                "get": {
                    "parameters": [
                        {
                            "name": "account_id",
                            "in": "path",
                            "required": True,
                            "schema": {"type": "integer"},
                        }
                    ],
                    "responses": {"200": {"description": "ok"}},
                }
            },
            "/notes/{note_id}": {
                "get": {
                    "parameters": [
                        {
                            "name": "note_id",
                            "in": "path",
                            "required": True,
                            "schema": {"type": "integer"},
                        }
                    ],
                    "responses": {"200": {"description": "ok"}},
                }
            },
            "/search": {"get": {"responses": {"200": {"description": "ok"}}}},
            "/health": {"get": {"responses": {"200": {"description": "ok"}}}},
        },
    }
)


@pytest.fixture
def target_spec(monkeypatch):
    monkeypatch.setattr(setup, "fetch_example_spec", lambda: SPEC)


def test_examples_are_dev_only(client, target_spec, monkeypatch):
    monkeypatch.setattr(settings, "env", "production")
    # A production env now also requires a caller; the example guard is what
    # this test is about, so present the operator key.
    monkeypatch.setattr(settings, "api_keys", "default:key")
    headers = {"X-API-Key": "key"}
    assert client.get("/health").json()["examples"] is False
    assert client.post("/scans/example", headers=headers).status_code == 404
    assert client.post("/monitoring/example", headers=headers).status_code == 404
    assert client.get("/scans", headers=headers).json() == []


def test_example_scan_is_ready_to_run(client, target_spec):
    response = client.post("/scans/example")
    assert response.status_code == 201, response.text
    scan = response.json()
    assert scan["target_base_url"] == setup.EXAMPLE_TARGET
    assert scan["status"] not in {"queued", "running"}
    assert {op["path"] for op in scan["operations"]} >= {"/accounts/{account_id}", "/search"}
    profiles = scan["credential_profiles"]
    assert sorted((c["name"], c["role"], c["header_name"]) for c in profiles) == [
        ("admin", "admin", "Authorization"),
        ("alice", "user", "Authorization"),
    ]
    assert "alice-token" not in response.text


def test_unreachable_target_creates_nothing(client, monkeypatch):
    def unavailable():
        raise setup.HTTPException(503, "example target unavailable")

    monkeypatch.setattr(setup, "fetch_example_spec", unavailable)
    assert client.post("/scans/example").status_code == 503
    assert client.get("/scans").json() == []


def test_example_monitor_shows_anomalies_and_bot_traffic(client, target_spec):
    response = client.post("/monitoring/example")
    assert response.status_code == 201, response.text
    monitor = response.json()
    assert monitor["rapid_enabled"] is True
    rapid = client.get(f"/monitoring/{monitor['id']}/rapid-runs").json()
    assert len(rapid) == 3
    assert rapid[0]["pulse"]["minutes"] == 5
    assert rapid[0]["pulse"]["requests"] > 0
    assert rapid[0]["pulse"]["attack_requests"] == 6
    assert rapid[0]["pulse"]["attack_allowed"] == 2
    assert rapid[0]["pulse"]["off_spec_requests"] >= 4
    assert {row["type"] for row in rapid[0]["observations"]} >= {
        "injection_attempts", "path_discovery", "slow_recon_ip",
    }
    runs = client.get(f"/monitoring/{monitor['id']}/runs").json()
    assert len(runs) == 8
    latest = runs[0]
    assert latest["state"] == "anomaly"
    kinds = {o["type"] for o in latest["observations"]}
    assert {
        "enumeration_anomaly",
        "unverified_ai_surge",
        "bot_identity_spoof",
        "ja4_endpoint_probing",
        "ja4_identifier_enumeration",
        "ja4_request_manipulation",
    } <= kinds
    assert all(o["confidence"] == "heuristic" for o in latest["observations"])
    assert all(run["observations"] == [] for run in runs[1:])

    # The load balancer tells the same story from the app's side, in the same hours.
    assert all(run["metrics"]["origin"]["load_balancer"] == demo.LOAD_BALANCER for run in runs)
    balancer = {o["type"]: o for o in latest["observations"] if o["type"].startswith("lb_")}
    assert {kind: o["hours"] for kind, o in balancer.items()} == {
        "lb_client_error_surge": [14],  # the walk's 404s
        "lb_server_error_surge": [3],  # the scanner's payloads that got through
        "lb_latency_surge": [14],
    }
    assert balancer["lb_server_error_surge"]["severity"] == "high"
    walk = next(o for o in latest["observations"] if o["type"] == "enumeration_anomaly")
    assert walk["hours"] == balancer["lb_client_error_surge"]["hours"]
    # 03:00 is always refused a little more; being compared with itself, it is not a lead.
    assert 3 not in balancer["lb_client_error_surge"]["hours"]

    fingerprints = client.get(f"/monitoring/{monitor['id']}/clients").json()
    assert fingerprints["day"] == latest["observation_date"]
    scanner = next(row for row in fingerprints["clients"] if row["ja4"] == demo.SCANNER_JA4)
    assert set(scanner["flags"]) == {"ja4_endpoint_probing", "ja4_request_manipulation"}
    assert (scanner["addresses"], scanner["attack_allowed"]) == (3, 2)
    assert fingerprints["clients"][0]["flags"]  # leads are listed first

    view = client.get(f"/monitoring/{monitor['id']}/bots").json()
    assert view["days"] == 8
    assert view["unverified_ai_pct"] == 100.0
    top = view["crawlers"][0]
    assert (top["name"], top["category"], top["verification"]) == ("gptbot", "ai", "unverified")
    assert view["series"][-1]["by_category"]["ai"] > view["series"][0]["by_category"]["ai"]

    trends = client.get(f"/monitoring/{monitor['id']}/routes").json()
    assert trends["days"] == 8
    accounts = next(r for r in trends["routes"] if r["route"] == "/accounts/{account_id}")
    assert accounts["state"] == "anomaly" and accounts["change"] > 1
    assert len(accounts["series"]) == 8

    again = client.post("/monitoring/example")
    assert again.json()["id"] == monitor["id"]
    assert len(client.get(f"/monitoring/{monitor['id']}/rapid-runs").json()) == 3

    # The beat keeps the dev-only pulse fresh without pretending its snapshot is AWS.
    later = datetime.now(UTC) + timedelta(minutes=20)
    assert rapid_service.collect_recent(monitor["id"], now=later)["status"] == "complete"
    refreshed = client.get(f"/monitoring/{monitor['id']}/rapid-runs").json()
    assert len(refreshed) == 4
    assert refreshed[0]["pulse"]["attack_requests"] == 6
