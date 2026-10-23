"""Dev-only examples on the bundled target, so a demo needs no typing."""

import json

import pytest

from app.core.config import settings
from app.scans import examples as setup

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
