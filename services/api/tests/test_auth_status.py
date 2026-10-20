"""The connection probe the web UI uses before it can talk to the API.

`/auth/status` answers two questions cheaply: is a key required, and which
tenant did the presented key resolve to. It exists because `/capabilities`
probes sidecars and is the wrong endpoint to block a first paint on.
"""
from __future__ import annotations

from fastapi.testclient import TestClient

from app.core.config import settings


def test_auth_status_reports_the_open_dev_posture(client: TestClient):
    body = client.get("/auth/status").json()

    assert body == {
        "tenant": "default",
        "auth_required": False,
        "role": "admin",
        "user": None,
    }


def test_auth_status_identifies_the_tenant_behind_a_key(client: TestClient, monkeypatch):
    monkeypatch.setattr(settings, "api_keys", "acme:key-one")

    body = client.get("/auth/status", headers={"X-API-Key": "key-one"}).json()

    assert body == {
        "tenant": "acme",
        "auth_required": True,
        "role": "admin",
        "user": None,
    }


def test_auth_status_refuses_a_missing_key_when_one_is_required(
    client: TestClient, monkeypatch
):
    monkeypatch.setattr(settings, "api_keys", "acme:key-one")

    r = client.get("/auth/status")

    assert r.status_code == 401
    assert r.json()["detail"] == "missing or invalid API key"


def test_auth_status_refuses_a_wrong_key(client: TestClient, monkeypatch):
    monkeypatch.setattr(settings, "api_keys", "acme:key-one")

    assert client.get("/auth/status", headers={"X-API-Key": "nope"}).status_code == 401


def test_api_key_required_when_configured(client, monkeypatch):
    from app.core import auth

    monkeypatch.setattr(auth.settings, "api_keys", "sekret-key")
    # No key → 401.
    assert client.get("/scans").status_code == 401
    # Correct key via X-API-Key → allowed.
    assert client.get("/scans", headers={"X-API-Key": "sekret-key"}).status_code == 200
    # Correct key via bearer → allowed.
    assert (
        client.get("/scans", headers={"Authorization": "Bearer sekret-key"}).status_code
        == 200
    )
    # Wrong key → 401.
    assert client.get("/scans", headers={"X-API-Key": "nope"}).status_code == 401
