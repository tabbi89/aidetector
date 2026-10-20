"""The parse report a spec upload returns, and what a re-upload preserves.

A spec that parses is not the same as a spec that was read whole: the parser is
deliberately lenient, so path items and method keys it cannot turn into
operations are dropped. These tests pin the report the wizard shows
(operations, skips, warnings) and the rule that replacing a spec never
re-enables an endpoint the user unchecked.
"""
from __future__ import annotations

import json

from tests.conftest import MINIMAL_SPEC


def test_report_counts_operations_and_is_quiet_for_a_clean_spec(client, new_scan):
    sid = new_scan()
    r = client.post(f"/scans/{sid}/spec", json={"content": MINIMAL_SPEC})
    assert r.status_code == 200, r.text
    body = r.json()
    # Existing fields stay: the report is an addition, not a replacement.
    assert [o["path"] for o in body["operations"]] == ["/accounts/{id}", "/search"]
    report = body["spec_report"]
    assert report["operations"] == 2 and report["skipped"] == []
    # MINIMAL_SPEC omits `responses`; the validator's complaint is reported, not hidden.
    assert report["warnings"] == ["'responses' is a required property"]


def test_report_names_every_dropped_item_with_a_reason(client, new_scan):
    sid = new_scan()
    spec = json.dumps(
        {
            "openapi": "3.0.0",
            "info": {"title": "demo", "version": "1"},
            "paths": {
                "/ok": {"summary": "fine", "parameters": [], "get": {}},
                "/broken": "not an object",
                "/weird": {
                    "x-internal": {"handler": "skip me"},
                    "connect": {},
                    "get": "not an object",
                },
            },
        }
    )
    r = client.post(f"/scans/{sid}/spec", json={"content": spec})
    assert r.status_code == 200, r.text
    report = r.json()["spec_report"]
    assert report["operations"] == 1
    # Reserved path-item keys (summary, parameters) are metadata, not skips.
    assert report["skipped"] == [
        {"path": "/broken", "method": None, "reason": "path item is not an object"},
        {"path": "/weird", "method": "X-INTERNAL", "reason": "not an HTTP method"},
        {"path": "/weird", "method": "CONNECT", "reason": "not an HTTP method"},
        {"path": "/weird", "method": "GET", "reason": "operation is not an object"},
    ]


def test_report_carries_the_routing_warnings_the_event_log_gets(client, new_scan):
    sid = new_scan("http://t/api")
    spec = json.dumps(
        {
            "openapi": "3.0.0",
            "info": {"title": "demo", "version": "1"},
            "servers": [{"url": "https://api.example.test/v1"}],
            "paths": {"/ok": {"get": {}}},
        }
    )
    r = client.post(f"/scans/{sid}/spec", json={"content": spec})
    assert r.status_code == 200, r.text
    warnings = r.json()["spec_report"]["warnings"]
    assert any("/v1" in w and "/api" in w for w in warnings)
    events = client.get(f"/scans/{sid}/events").json()
    assert [e["message"] for e in events if e["stage"] == "spec_warning"] == warnings


def test_reupload_keeps_disabled_operations_disabled(client, scan_with_spec):
    sid = scan_with_spec()
    ops = client.get(f"/scans/{sid}").json()["operations"]
    off = next(o for o in ops if o["path"] == "/search")
    client.patch(
        f"/scans/{sid}/operations",
        json={"operations": [{"id": off["id"], "enabled": False}]},
    )

    r = client.post(f"/scans/{sid}/spec", json={"content": MINIMAL_SPEC})
    assert r.status_code == 200, r.text
    enabled = {(o["method"], o["path"]): o["enabled"] for o in r.json()["operations"]}
    assert enabled[("GET", "/search")] is False
    assert enabled[("GET", "/accounts/{id}")] is True


def test_reupload_does_not_carry_a_disable_onto_a_changed_path(client, scan_with_spec):
    sid = scan_with_spec()
    ops = client.get(f"/scans/{sid}").json()["operations"]
    off = next(o for o in ops if o["path"] == "/accounts/{id}")
    client.patch(
        f"/scans/{sid}/operations",
        json={"operations": [{"id": off["id"], "enabled": False}]},
    )

    renamed = json.dumps(
        {
            "openapi": "3.0.0",
            "info": {"title": "demo", "version": "2"},
            "paths": {"/accounts/{account_id}": {"get": {}}},
        }
    )
    r = client.post(f"/scans/{sid}/spec", json={"content": renamed})
    assert r.status_code == 200, r.text
    assert [o["enabled"] for o in r.json()["operations"]] == [True]
