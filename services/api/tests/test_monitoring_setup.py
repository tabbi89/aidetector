"""One-step monitor setup: API contract, WAF log group and repository in one call."""

import json

import pytest
from sqlalchemy import func, select

from app.core.config import settings
from app.models.monitoring import EvidenceSource, InfrastructureMonitor
from app.models.scan import Scan
from app.monitoring.contracts import parse_log_group_arn

ARN = "arn:aws:logs:us-west-2:257498453293:log-group:aws-waf-logs-pd_prod:*"
TARGET = "https://target.test"
TOKEN = "github_pat_example_read_only"
SPEC = json.dumps(
    {
        "openapi": "3.0.0",
        "info": {"title": "orders", "version": "1"},
        "components": {"securitySchemes": {"bearer": {"type": "http", "scheme": "bearer"}}},
        "paths": {
            "/orders/{id}": {
                "get": {
                    "parameters": [
                        {
                            "name": "id",
                            "in": "path",
                            "required": True,
                            "schema": {"type": "integer"},
                        }
                    ],
                    "security": [{"bearer": []}],
                    "responses": {"200": {"description": "ok"}},
                }
            },
            "/health": {"get": {"responses": {"200": {"description": "ok"}}}},
        },
    }
)


@pytest.fixture
def allowed(monkeypatch):
    monkeypatch.setattr(
        settings,
        "monitoring_aws_log_groups",
        "arn:aws:logs:us-west-2:257498453293:log-group:aws-waf-logs-pd_prod",
    )


def setup(client, headers=None, **overrides):
    body = {
        "name": "pd_prod",
        "target_binding": TARGET,
        "openapi": SPEC,
        "waf_log_group_arn": ARN,
        "github_repository": "acme/api",
        "github_token": TOKEN,
        **overrides,
    }
    return client.post(
        "/monitoring/setup",
        headers=headers,
        json={key: value for key, value in body.items() if value is not None},
    )


@pytest.mark.parametrize("arn", [ARN, ARN.removesuffix(":*")])
def test_log_group_arn_parses_with_or_without_the_console_suffix(arn):
    assert parse_log_group_arn(arn) == ("us-west-2", "257498453293", "aws-waf-logs-pd_prod")


@pytest.mark.parametrize(
    "arn",
    [
        "arn:aws:s3:::aws-waf-logs-pd_prod",
        "arn:aws:logs:us-west-2:25749845329:log-group:aws-waf-logs-pd_prod",
        "arn:aws:logs:us-west-2:257498453293:log-group:application-logs",
        "arn:aws:logs:us-west-2:257498453293:log-group:aws-waf-logs-a:b",
    ],
)
def test_log_group_arn_rejects_other_resources(arn):
    with pytest.raises(ValueError):
        parse_log_group_arn(arn)


def test_setup_creates_contract_sources_and_monitor(client, allowed):
    response = setup(client)
    assert response.status_code == 201, response.text
    monitor = response.json()
    assert monitor["scan_id"] and len(monitor["source_ids"]) == 1
    assert monitor["schedule_enabled"] is True

    listing = client.get("/monitoring/sources")
    by_connector = {s["connector"]: s for s in listing.json()}
    waf = by_connector["aws_cloudwatch"]
    assert waf["id"] == monitor["source_ids"][0]
    assert waf["has_credentials"] is False  # the deployment's credential chain signs reads
    assert {k: waf["config"][k] for k in ("region", "account_id", "log_group")} == {
        "region": "us-west-2",
        "account_id": "257498453293",
        "log_group": "aws-waf-logs-pd_prod",
    }
    github = by_connector["github"]
    assert github["config"]["ref"] == "main"
    assert github["has_credentials"] is True  # the monitor's own token, encrypted

    context = client.get(f"/monitoring/{monitor['id']}/context")
    assert {"method": "GET", "path": "/orders/{id}"} in context.json()["routes"]
    assert context.json()["repository"] == {"repository": "acme/api", "ref": "main"}
    assert context.json()["repository_source_id"] == github["id"]
    for text in (response.text, listing.text, context.text):
        assert TOKEN not in text


def test_any_repository_is_accepted_without_a_deployment_allowlist(client, allowed):
    response = setup(client, github_repository="someone-else/service", github_token=None)
    assert response.status_code == 201, response.text
    github = next(
        s for s in client.get("/monitoring/sources").json() if s["connector"] == "github"
    )
    assert github["config"]["repository"] == "someone-else/service"
    assert github["has_credentials"] is False


def test_setup_without_repository(client, allowed):
    response = setup(client, github_repository=None, github_token=None)
    assert response.status_code == 201, response.text
    assert [s["connector"] for s in client.get("/monitoring/sources").json()] == [
        "aws_cloudwatch"
    ]


@pytest.mark.parametrize(
    "override",
    [
        {"waf_log_group_arn": "arn:aws:logs:us-west-2:257498453293:log-group:app-logs"},
        {"waf_log_group_arn": "arn:aws:logs:us-west-2:257498453293:log-group:aws-waf-logs-x"},
        {"github_repository": "not a repository"},
        {"openapi": "openapi: [unclosed"},
        {"target_binding": "ftp://target.test"},
    ],
)
def test_refused_setup_leaves_nothing_behind(client, db_session, allowed, override):
    assert setup(client, **override).status_code == 422
    for model in (Scan, EvidenceSource, InfrastructureMonitor):
        assert db_session.scalar(select(func.count()).select_from(model)) == 0


def test_contract_is_optional_but_not_both(client, db_session, allowed):
    both = setup(client, scan_id="00000000-0000-0000-0000-000000000000")
    assert both.status_code == 422
    response = setup(client, openapi=None)
    assert response.status_code == 201, response.text
    monitor = response.json()
    assert monitor["scan_id"] is None
    assert db_session.scalar(select(func.count()).select_from(Scan)) == 0
    context = client.get(f"/monitoring/{monitor['id']}/context").json()
    assert "routes" not in context
    assert context["repository"] == {"repository": "acme/api", "ref": "main"}


def test_setup_from_an_existing_scan_is_tenant_scoped(client, allowed, monkeypatch):
    monkeypatch.setattr(settings, "api_keys", "alice:a-key,bob:b-key")
    alice, bob = {"X-API-Key": "a-key"}, {"X-API-Key": "b-key"}
    scan = client.post("/scans", headers=alice, json={"target_base_url": TARGET}).json()
    spec = client.post(f"/scans/{scan['id']}/spec", headers=alice, json={"content": SPEC})
    assert spec.status_code == 200, spec.text
    assert setup(client, headers=bob, openapi=None, scan_id=scan["id"]).status_code == 404
    response = setup(client, headers=alice, openapi=None, scan_id=scan["id"])
    assert response.status_code == 201, response.text
    assert response.json()["scan_id"] == scan["id"]
