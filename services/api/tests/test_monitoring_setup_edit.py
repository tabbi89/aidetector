"""An optional ALB on setup, and editing a monitor's setup after the fact.

The load balancer only adds origin status to WAF traffic, so its rules mirror that:
it must sit beside the WAF (same region and account), it must be allowlisted by the
operator, and removing it detaches it without touching the monitor's WAF history.
"""

import json

import pytest
from sqlalchemy import func, select

from app.core.config import settings
from app.models.monitoring import EvidenceSource, InfrastructureMonitor, MonitoringRun
from app.monitoring.contracts import ORIGIN_SOURCE_KEY, parse_load_balancer_arn

WAF_ARN = "arn:aws:logs:us-west-2:257498453293:log-group:aws-waf-logs-pd_prod"
ALB_ARN = (
    "arn:aws:elasticloadbalancing:us-west-2:257498453293:"
    "loadbalancer/app/pd-prod/50dc6c495c0c9188"
)
OTHER_ALB = (
    "arn:aws:elasticloadbalancing:us-west-2:257498453293:"
    "loadbalancer/app/pd-canary/1111222233334444"
)
TARGET = "https://target.test"
TOKEN = "github_pat_example_read_only"
NEW_TOKEN = "github_pat_replacement_token"
SPEC = json.dumps({
    "openapi": "3.0.0",
    "info": {"title": "orders", "version": "1"},
    "paths": {"/orders/{id}": {"get": {"responses": {"200": {"description": "ok"}}}}},
})


@pytest.fixture
def allowed(monkeypatch):
    monkeypatch.setattr(settings, "monitoring_aws_log_groups", WAF_ARN)
    monkeypatch.setattr(settings, "monitoring_aws_load_balancers", f"{ALB_ARN},{OTHER_ALB}")


def setup(client, **overrides):
    body = {
        "name": "pd_prod",
        "target_binding": TARGET,
        "waf_log_group_arn": WAF_ARN,
        "github_repository": "acme/api",
        "github_token": TOKEN,
        **overrides,
    }
    response = client.post(
        "/monitoring/setup", json={k: v for k, v in body.items() if v is not None}
    )
    assert response.status_code == 201, response.text
    return response.json()


def sources_by_connector(client):
    return {s["connector"]: s for s in client.get("/monitoring/sources").json()}


# --- the ARN itself -----------------------------------------------------------------


def test_alb_arn_parses_to_region_account_and_resource():
    assert parse_load_balancer_arn(ALB_ARN) == (
        "us-west-2", "257498453293", "app/pd-prod/50dc6c495c0c9188"
    )


@pytest.mark.parametrize(
    "arn,reason",
    [
        (ALB_ARN.replace("/app/", "/net/"), "HTTP response codes"),
        (WAF_ARN, "expected"),
        (ALB_ARN.replace("50dc6c495c0c9188", "short"), "expected"),
    ],
)
def test_alb_arn_refuses_other_resources_and_says_why(arn, reason):
    with pytest.raises(ValueError, match=reason):
        parse_load_balancer_arn(arn)


# --- setup --------------------------------------------------------------------------


def test_setup_with_an_alb_links_an_origin_source(client, allowed):
    monitor = setup(client, alb_arn=ALB_ARN)
    # The origin source is supplementary: the primary binding is still the WAF alone.
    assert len(monitor["source_ids"]) == 1
    alb = sources_by_connector(client)["aws_alb"]
    assert alb["config"] == {
        "region": "us-west-2",
        "account_id": "257498453293",
        "load_balancer": "app/pd-prod/50dc6c495c0c9188",
        "routes": [],
        "paths": [],
    }
    assert client.get(f"/monitoring/{monitor['id']}/setup").json()["alb_arn"] == ALB_ARN


def test_an_alb_outside_the_wafs_region_is_refused(client, db_session, allowed, monkeypatch):
    elsewhere = ALB_ARN.replace("us-west-2", "eu-west-1")
    monkeypatch.setattr(settings, "monitoring_aws_load_balancers", elsewhere)
    response = client.post("/monitoring/setup", json={
        "name": "m", "target_binding": TARGET, "waf_log_group_arn": WAF_ARN, "alb_arn": elsewhere,
    })
    assert response.status_code == 422
    assert "region" in response.json()["detail"]
    assert db_session.scalar(select(func.count()).select_from(EvidenceSource)) == 0


def test_an_alb_the_operator_did_not_allowlist_is_refused_with_the_right_setting(
    client, db_session, allowed, monkeypatch
):
    monkeypatch.setattr(settings, "monitoring_aws_load_balancers", "")
    response = client.post("/monitoring/setup", json={
        "name": "m", "target_binding": TARGET, "waf_log_group_arn": WAF_ARN, "alb_arn": ALB_ARN,
    })
    assert response.status_code == 422
    # Not the log-group message: that would send the operator to the wrong setting.
    assert "MONITORING_AWS_LOAD_BALANCERS" in response.json()["detail"]
    for model in (EvidenceSource, InfrastructureMonitor):
        assert db_session.scalar(select(func.count()).select_from(model)) == 0


# --- editing ------------------------------------------------------------------------


def test_setup_view_never_returns_the_token(client, allowed):
    monitor = setup(client)
    response = client.get(f"/monitoring/{monitor['id']}/setup")
    view = response.json()
    assert view["github_token_set"] is True
    assert view["waf_log_group_arn"] == WAF_ARN
    assert TOKEN not in response.text


def test_editing_name_and_schedule_leaves_everything_else(client, allowed):
    monitor = setup(client, alb_arn=ALB_ARN)
    before = client.get(f"/monitoring/{monitor['id']}/setup").json()
    response = client.put(
        f"/monitoring/{monitor['id']}/setup", json={"name": "renamed", "schedule_enabled": False}
    )
    assert response.status_code == 200, response.text
    after = response.json()
    assert (after["name"], after["schedule_enabled"]) == ("renamed", False)
    unchanged = ("waf_log_group_arn", "alb_arn", "github_repository", "github_token_set")
    assert {k: after[k] for k in unchanged} == {k: before[k] for k in unchanged}


def test_adding_an_alb_to_an_existing_monitor(client, allowed):
    monitor = setup(client)
    response = client.put(f"/monitoring/{monitor['id']}/setup", json={"alb_arn": ALB_ARN})
    assert response.status_code == 200, response.text
    assert response.json()["alb_arn"] == ALB_ARN


def test_replacing_an_alb_revokes_the_old_source(client, db_session, allowed):
    monitor = setup(client, alb_arn=ALB_ARN)
    old_id = sources_by_connector(client)["aws_alb"]["id"]
    response = client.put(f"/monitoring/{monitor['id']}/setup", json={"alb_arn": OTHER_ALB})
    assert response.status_code == 200, response.text
    assert response.json()["alb_arn"] == OTHER_ALB
    db_session.expire_all()
    assert db_session.get(EvidenceSource, old_id).status == "revoked"


def test_resubmitting_the_same_alb_does_not_churn_its_source(client, allowed):
    monitor = setup(client, alb_arn=ALB_ARN)
    old_id = sources_by_connector(client)["aws_alb"]["id"]
    client.put(f"/monitoring/{monitor['id']}/setup", json={"alb_arn": ALB_ARN})
    row = db_monitor(client, monitor)
    assert row["context"][ORIGIN_SOURCE_KEY] == old_id


def db_monitor(client, monitor):
    return {"context": client.get(f"/monitoring/{monitor['id']}/context").json()}


def test_removing_the_alb_keeps_the_monitors_waf_history(client, db_session, allowed):
    """Detaching a supplementary source must not delete the baseline it added to."""
    monitor = setup(client, alb_arn=ALB_ARN)
    row = db_session.get(InfrastructureMonitor, monitor["id"])
    from datetime import date

    db_session.add(MonitoringRun(
        monitor_id=row.id, observation_date=date(2026, 9, 14), status="complete",
        metrics={"event_count": 5},
    ))
    db_session.commit()

    response = client.put(f"/monitoring/{monitor['id']}/setup", json={"alb_arn": None})
    assert response.status_code == 200, response.text
    assert response.json()["alb_arn"] is None
    assert db_session.scalar(
        select(func.count()).select_from(MonitoringRun).where(MonitoringRun.monitor_id == row.id)
    ) == 1
    db_session.refresh(row)
    assert row.status == "active"


def test_deleting_the_alb_source_detaches_it_without_pausing_the_monitor(
    client, db_session, allowed
):
    monitor = setup(client, alb_arn=ALB_ARN)
    alb_id = sources_by_connector(client)["aws_alb"]["id"]
    assert client.delete(f"/monitoring/sources/{alb_id}").status_code == 204
    row = db_session.get(InfrastructureMonitor, monitor["id"])
    db_session.refresh(row)
    assert row.status == "active"
    assert ORIGIN_SOURCE_KEY not in row.context


def test_attaching_a_contract_keeps_the_alb_linked(client, allowed):
    monitor = setup(client, alb_arn=ALB_ARN)
    response = client.put(f"/monitoring/{monitor['id']}/setup", json={"openapi": SPEC})
    assert response.status_code == 200, response.text
    assert response.json()["alb_arn"] == ALB_ARN
    assert response.json()["scan_id"]


def test_changing_the_ref_keeps_the_stored_token(client, allowed):
    """Otherwise editing a branch would silently erase the repository's token."""
    monitor = setup(client)
    response = client.put(f"/monitoring/{monitor['id']}/setup", json={"github_ref": "release"})
    assert response.status_code == 200, response.text
    assert response.json()["github_ref"] == "release"
    assert response.json()["github_token_set"] is True


def test_a_different_repository_never_inherits_the_old_token(client, allowed):
    monitor = setup(client)
    response = client.put(
        f"/monitoring/{monitor['id']}/setup", json={"github_repository": "acme/other"}
    )
    assert response.status_code == 200, response.text
    assert response.json()["github_repository"] == "acme/other"
    assert response.json()["github_token_set"] is False


def test_replacing_the_token_is_accepted_and_never_echoed(client, allowed):
    monitor = setup(client)
    response = client.put(
        f"/monitoring/{monitor['id']}/setup", json={"github_token": NEW_TOKEN}
    )
    assert response.status_code == 200, response.text
    assert response.json()["github_token_set"] is True
    assert NEW_TOKEN not in response.text and TOKEN not in response.text


def test_removing_the_repository(client, allowed):
    monitor = setup(client)
    response = client.put(f"/monitoring/{monitor['id']}/setup", json={"github_repository": None})
    assert response.status_code == 200, response.text
    assert response.json()["github_repository"] is None
    context = client.get(f"/monitoring/{monitor['id']}/context").json()
    assert "repository" not in context and "repository_source_id" not in context


@pytest.mark.parametrize(
    "body",
    [
        {"target_binding": "https://elsewhere.test"},
        {"waf_log_group_arn": WAF_ARN},
        {"name": None},
        {"openapi": SPEC, "scan_id": "00000000-0000-0000-0000-000000000000"},
    ],
)
def test_identity_fields_and_contradictions_are_refused(client, allowed, body):
    monitor = setup(client)
    assert client.put(f"/monitoring/{monitor['id']}/setup", json=body).status_code == 422


def test_a_refused_edit_changes_nothing(client, allowed, monkeypatch):
    monitor = setup(client, alb_arn=ALB_ARN)
    before = client.get(f"/monitoring/{monitor['id']}/setup").json()
    monkeypatch.setattr(settings, "monitoring_aws_load_balancers", ALB_ARN)  # OTHER_ALB no longer
    response = client.put(
        f"/monitoring/{monitor['id']}/setup", json={"name": "renamed", "alb_arn": OTHER_ALB}
    )
    assert response.status_code == 422
    assert client.get(f"/monitoring/{monitor['id']}/setup").json() == before


def test_editing_is_tenant_scoped(client, allowed, monkeypatch):
    monkeypatch.setattr(settings, "api_keys", "alice:a-key,bob:b-key")
    alice, bob = {"X-API-Key": "a-key"}, {"X-API-Key": "b-key"}
    created = client.post("/monitoring/setup", headers=alice, json={
        "name": "m", "target_binding": TARGET, "waf_log_group_arn": WAF_ARN,
    })
    assert created.status_code == 201, created.text
    path = f"/monitoring/{created.json()['id']}/setup"
    assert client.get(path, headers=bob).status_code == 404
    assert client.put(path, headers=bob, json={"name": "x"}).status_code == 404


def test_every_ui_monitoring_mutation_leaves_an_audit_row(client, allowed):
    monitor = setup(client)
    mid = monitor["id"]
    assert client.put(f"/monitoring/{mid}/setup", json={"alb_arn": ALB_ARN}).status_code == 200
    assert client.put(
        f"/monitoring/{mid}/triage", json={"fingerprint": "a" * 64, "disposition": "suppressed"}
    ).status_code == 200
    assert client.post(f"/monitoring/{mid}/cancel").status_code == 200
    rows = client.get("/workspace/audit").json()
    actions = [row["action"] for row in rows]
    for action in (
        "monitoring.monitor_created",
        "monitoring.setup_updated",
        "monitoring.observation_triaged",
        "monitoring.collection_cancelled",
    ):
        assert action in actions, actions
    # Value-free: the GitHub token never reaches the audit trail.
    assert TOKEN not in str(rows)
