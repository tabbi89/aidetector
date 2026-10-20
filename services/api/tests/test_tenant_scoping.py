"""Tenant isolation: a scan created under one API key is invisible to another.

When ``api_keys`` maps keys to tenants, every scan carries the creating tenant and
reads/lists are scoped to it, so one tenant can neither see nor act on another's
scans. Cross-tenant access returns 404 (existence is hidden, not merely 403)."""
from __future__ import annotations

import pytest


@pytest.fixture
def two_tenants(monkeypatch):
    from app.core import auth

    monkeypatch.setattr(auth.settings, "api_keys", "acme:key-a,globex:key-b")
    return {"X-API-Key": "key-a"}, {"X-API-Key": "key-b"}


def test_scan_is_isolated_to_creating_tenant(client, two_tenants):
    acme, globex = two_tenants

    r = client.post("/scans", json={"target_base_url": "http://t"}, headers=acme)
    assert r.status_code == 201
    sid = r.json()["id"]

    # The owner reads it; the other tenant gets 404 (not 403 — existence hidden).
    assert client.get(f"/scans/{sid}", headers=acme).status_code == 200
    assert client.get(f"/scans/{sid}", headers=globex).status_code == 404


def test_list_is_scoped_to_tenant(client, two_tenants):
    acme, globex = two_tenants

    sid = client.post(
        "/scans", json={"target_base_url": "http://t"}, headers=acme
    ).json()["id"]

    acme_ids = {s["id"] for s in client.get("/scans", headers=acme).json()}
    globex_ids = {s["id"] for s in client.get("/scans", headers=globex).json()}
    assert sid in acme_ids
    assert sid not in globex_ids


def test_cross_tenant_mutation_is_blocked(client, two_tenants):
    acme, globex = two_tenants

    sid = client.post(
        "/scans", json={"target_base_url": "http://t"}, headers=acme
    ).json()["id"]

    # A write path (spec upload) as the wrong tenant is refused at the 404 gate,
    # before any parsing happens.
    r = client.post(
        f"/scans/{sid}/spec", json={"content": "{}"}, headers=globex
    )
    assert r.status_code == 404
    # ...and the scan is untouched for the real owner.
    assert client.get(f"/scans/{sid}", headers=acme).status_code == 200


def test_cross_tenant_delete_is_blocked(client, two_tenants):
    acme, globex = two_tenants

    sid = client.post(
        "/scans", json={"target_base_url": "http://t"}, headers=acme
    ).json()["id"]

    # Deleting someone else's scan hits the same 404 gate — and leaves it intact.
    assert client.delete(f"/scans/{sid}", headers=globex).status_code == 404
    assert client.get(f"/scans/{sid}", headers=acme).status_code == 200
    assert client.delete(f"/scans/{sid}", headers=acme).status_code == 200


def test_missing_key_is_unauthorized(client, two_tenants):
    # With keys configured, no key at all is 401 (before any tenant scoping).
    assert client.get("/scans").status_code == 401
