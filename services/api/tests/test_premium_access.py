"""Premium entitlement is a tenant fact, exposed beside the deployment probes.

`GET /capabilities` answers two different questions: what *this deployment* can
run (cached, network probes) and what *this tenant* may run (a plan decision,
never cached). The pentest report is the one headline output the plan gates, so
it is checked here too — a gated deliverable that is free over HTTP is not gated.
"""
from __future__ import annotations

from fastapi.testclient import TestClient

from app.core.config import settings


def test_capabilities_separates_deployment_from_tenant(client: TestClient, monkeypatch):
    monkeypatch.setattr(settings, "premium_tenants", "someone-else")

    body = client.get("/capabilities").json()

    # The deployment's opt-in passes are unchanged by the plan.
    assert "passes" in body and isinstance(body["passes"], dict)
    premium = body["premium"]
    assert premium["available"] is False
    assert premium["plan"] == "free"
    # A locked feature must say how to unlock it, not just that it is locked.
    assert premium["reason"] and "premium" in premium["reason"].lower()


def test_capabilities_reports_premium_for_an_entitled_tenant(client: TestClient, monkeypatch):
    monkeypatch.setattr(settings, "premium_tenants", "*")

    premium = client.get("/capabilities").json()["premium"]

    assert premium == {"available": True, "plan": "premium", "reason": None}


def test_pentest_report_is_refused_on_the_free_plan(
    client: TestClient, new_scan, monkeypatch
):
    monkeypatch.setattr(settings, "premium_tenants", "someone-else")
    sid = new_scan()

    r = client.get(f"/scans/{sid}/report.pentest")

    assert r.status_code == 402
    assert r.json()["detail"] == "premium tier required"


def test_pentest_report_is_a_deliverable_on_the_premium_plan(
    client: TestClient, new_scan, monkeypatch
):
    monkeypatch.setattr(settings, "premium_tenants", "*")
    sid = new_scan()

    r = client.get(f"/scans/{sid}/report.pentest")

    assert r.status_code == 200
    assert r.headers["content-type"].startswith("text/markdown")


def test_the_other_exports_stay_available_on_every_plan(
    client: TestClient, new_scan, monkeypatch
):
    """Only the headline pentest deliverable is gated."""
    monkeypatch.setattr(settings, "premium_tenants", "someone-else")
    sid = new_scan()

    assert client.get(f"/scans/{sid}/export").status_code == 200
    assert client.get(f"/scans/{sid}/report.pdf").status_code == 200
    assert client.get(f"/scans/{sid}/report.html").status_code == 200
