"""End-to-end scan API tests (DB-backed; skipped if Postgres is down)."""
from __future__ import annotations

import json

from sqlalchemy import event

from app.models.scan import ScanRun
from tests.conftest import MINIMAL_SPEC


def test_scan_lifecycle(client):
    # create
    r = client.post("/scans", json={"target_base_url": "http://target:9000"})
    assert r.status_code == 201, r.text
    scan = r.json()
    assert scan["status"] == "draft"
    assert scan["operations"] == []
    sid = scan["id"]

    # ingest spec → operations enumerated
    r = client.post(f"/scans/{sid}/spec", json={"content": MINIMAL_SPEC})
    assert r.status_code == 200, r.text
    ops = r.json()["operations"]
    assert len(ops) == 2
    assert {(o["method"], o["path"]) for o in ops} == {
        ("GET", "/accounts/{id}"),
        ("GET", "/search"),
    }

    # re-upload is idempotent
    r = client.post(f"/scans/{sid}/spec", json={"content": MINIMAL_SPEC})
    assert len(r.json()["operations"]) == 2

    # add two credential roles; secret never returned
    for name, role in [("alice", "user"), ("admin", "admin")]:
        r = client.post(
            f"/scans/{sid}/credentials",
            json={
                "name": name,
                "role": role,
                "auth_type": "bearer",
                "secret": f"{name}-token",
            },
        )
        assert r.status_code == 201, r.text
        assert "secret" not in r.json()
        assert "secret_ref" not in r.json()

    # detail reflects everything
    d = client.get(f"/scans/{sid}").json()
    assert len(d["operations"]) == 2
    assert len(d["credential_profiles"]) == 2

    # list includes it
    assert any(s["id"] == sid for s in client.get("/scans").json())


def test_bad_spec_is_422(client, new_scan):
    sid = new_scan()
    r = client.post(f"/scans/{sid}/spec", json={"content": "not a spec"})
    assert r.status_code == 422


def test_spec_reupload_replaces_operations(client, scan_with_spec):
    sid = scan_with_spec()

    smaller = json.dumps(
        {"openapi": "3.0.0", "info": {"title": "demo", "version": "2"},
         "paths": {"/only": {"get": {}}}}
    )
    r = client.post(f"/scans/{sid}/spec", json={"content": smaller})
    ops = r.json()["operations"]
    assert [(o["method"], o["path"]) for o in ops] == [("GET", "/only")]


def test_spec_text_is_persisted_and_returned(client, new_scan):
    sid = new_scan()
    assert client.get(f"/scans/{sid}").json()["spec_text"] is None

    client.post(f"/scans/{sid}/spec", json={"content": MINIMAL_SPEC})
    assert client.get(f"/scans/{sid}").json()["spec_text"] == MINIMAL_SPEC


def test_credential_update_and_delete(client, db_session, new_scan):
    from app.core.vault import decrypt
    from app.models.credential import CredentialProfile

    sid = new_scan()
    cred = client.post(
        f"/scans/{sid}/credentials",
        json={"name": "alice", "role": "user", "auth_type": "bearer",
              "secret": "old-token"},
    ).json()
    assert "secret" not in cred

    # metadata-only update keeps the stored secret
    r = client.patch(
        f"/scans/{sid}/credentials/{cred['id']}",
        json={"name": "alice2", "role": "admin", "auth_type": "bearer"},
    )
    assert r.status_code == 200, r.text
    assert r.json()["name"] == "alice2"
    assert "secret" not in r.json()
    db_session.expire_all()
    assert decrypt(db_session.get(CredentialProfile, cred["id"]).secret_ref) == "old-token"

    # a provided secret replaces the stored one
    client.patch(
        f"/scans/{sid}/credentials/{cred['id']}",
        json={"name": "alice2", "role": "admin", "auth_type": "bearer",
              "secret": "new-token"},
    )
    db_session.expire_all()
    assert decrypt(db_session.get(CredentialProfile, cred["id"]).secret_ref) == "new-token"

    # delete removes it; repeat delete and foreign ids 404
    assert client.delete(f"/scans/{sid}/credentials/{cred['id']}").status_code == 200
    assert client.delete(f"/scans/{sid}/credentials/{cred['id']}").status_code == 404
    assert client.get(f"/scans/{sid}").json()["credential_profiles"] == []


def test_credential_edit_blocked_while_running(client, db_session, new_scan):
    from app.models.scan import Scan, ScanStatus

    sid = new_scan()
    cred = client.post(
        f"/scans/{sid}/credentials",
        json={"name": "alice", "role": "user", "auth_type": "bearer", "secret": "t"},
    ).json()
    scan = db_session.get(Scan, sid)
    scan.status = ScanStatus.running
    db_session.commit()

    body = {"name": "x", "role": "y", "auth_type": "bearer"}
    assert client.patch(f"/scans/{sid}/credentials/{cred['id']}", json=body).status_code == 409
    assert client.delete(f"/scans/{sid}/credentials/{cred['id']}").status_code == 409
    assert client.post(f"/scans/{sid}/credentials", json={**body, "secret": "s"}).status_code == 409


def test_spec_upload_blocked_while_running(client, db_session, scan_with_spec):
    from app.models.scan import Scan, ScanStatus

    sid = scan_with_spec()
    scan = db_session.get(Scan, sid)
    scan.status = ScanStatus.running
    db_session.commit()

    r = client.post(f"/scans/{sid}/spec", json={"content": MINIMAL_SPEC})
    assert r.status_code == 409


def test_missing_scan_is_404(client):
    r = client.get("/scans/00000000-0000-0000-0000-000000000000")
    assert r.status_code == 404


def test_run_requires_authorization(client, scan_with_spec):
    sid = scan_with_spec()
    # missing / false authorization → 403, no scan queued
    r = client.post(f"/scans/{sid}/run", json={"authorized": False})
    assert r.status_code == 403
    assert client.get(f"/scans/{sid}").json()["status"] == "draft"


def test_run_requires_spec(client, new_scan):
    sid = new_scan()
    r = client.post(f"/scans/{sid}/run", json={"authorized": True})
    assert r.status_code == 400


def test_operation_selection_defaults_enabled_and_can_toggle(client, new_scan):
    sid = new_scan()
    ops = client.post(f"/scans/{sid}/spec", json={"content": MINIMAL_SPEC}).json()[
        "operations"
    ]
    # New operations default to enabled/in-scope.
    assert all(o["enabled"] for o in ops)

    # Disable one operation via the bulk endpoint.
    target = ops[0]
    r = client.patch(
        f"/scans/{sid}/operations",
        json={"operations": [{"id": target["id"], "enabled": False}]},
    )
    assert r.status_code == 200, r.text
    by_id = {o["id"]: o for o in r.json()["operations"]}
    assert by_id[target["id"]]["enabled"] is False
    assert by_id[ops[1]["id"]]["enabled"] is True  # untouched stays enabled


def test_run_rejected_when_all_operations_disabled(client, new_scan):
    sid = new_scan()
    ops = client.post(f"/scans/{sid}/spec", json={"content": MINIMAL_SPEC}).json()[
        "operations"
    ]
    client.patch(
        f"/scans/{sid}/operations",
        json={"operations": [{"id": o["id"], "enabled": False} for o in ops]},
    )
    r = client.post(f"/scans/{sid}/run", json={"authorized": True})
    assert r.status_code == 400
    assert "operation" in r.json()["detail"].lower()


def test_edit_target_base_url(client):
    sid = client.post(
        "/scans", json={"target_base_url": "http://localhost:9000"}
    ).json()["id"]

    r = client.patch(
        f"/scans/{sid}",
        json={"target_base_url": "https://onboarding.taluspay-staging.com"},
    )
    assert r.status_code == 200, r.text
    assert r.json()["target_base_url"] == "https://onboarding.taluspay-staging.com"

    # persisted
    assert (
        client.get(f"/scans/{sid}").json()["target_base_url"]
        == "https://onboarding.taluspay-staging.com"
    )


def test_edit_scan_request_rate(client):
    sid = client.post(
        "/scans", json={"target_base_url": "http://localhost:9000"}
    ).json()["id"]

    assert client.get(f"/scans/{sid}").json()["requests_per_second"] == 10
    changed = client.put(
        f"/scans/{sid}/request-rate", json={"requests_per_second": 2}
    )
    assert changed.status_code == 200
    assert changed.json()["requests_per_second"] == 2
    assert client.get(f"/scans/{sid}").json()["requests_per_second"] == 2

    assert client.put(
        f"/scans/{sid}/request-rate", json={"requests_per_second": 0}
    ).status_code == 422


def test_delete_scan_removes_it_and_its_children(client, db_session, scan_with_spec):
    from app.models.credential import CredentialProfile
    from app.models.scan import Operation

    sid = scan_with_spec()
    client.post(
        f"/scans/{sid}/credentials",
        json={"name": "alice", "role": "user", "auth_type": "bearer", "secret": "t"},
    )

    assert client.delete(f"/scans/{sid}").status_code == 200
    assert client.get(f"/scans/{sid}").status_code == 404
    assert client.delete(f"/scans/{sid}").status_code == 404
    assert sid not in {s["id"] for s in client.get("/scans").json()}

    # children cascade away with the scan — including the encrypted secrets
    db_session.expire_all()
    assert db_session.query(Operation).filter_by(scan_id=sid).count() == 0
    assert db_session.query(CredentialProfile).filter_by(scan_id=sid).count() == 0


def test_delete_scan_blocked_while_running(client, db_session, new_scan):
    from app.models.scan import Scan, ScanStatus

    sid = new_scan()
    scan = db_session.get(Scan, sid)
    scan.status = ScanStatus.running
    db_session.commit()

    assert client.delete(f"/scans/{sid}").status_code == 409
    assert client.get(f"/scans/{sid}").status_code == 200


def test_credential_grant_fields_round_trip(client, db_session, new_scan):
    """A grant credential stores its non-secret config and still hides the secret."""
    from app.core.vault import decrypt
    from app.domain.enums import GrantType
    from app.models.credential import CredentialProfile

    sid = new_scan()
    cred = client.post(
        f"/scans/{sid}/credentials",
        json={
            "name": "svc", "role": "service", "auth_type": "bearer",
            "secret": "the-client-secret",
            "grant_type": "client_credentials",
            "token_url": "https://auth.example.com/oauth/token",
            "grant_params": {"client_id": "svc", "scope": "read"},
        },
    ).json()
    assert cred["grant_type"] == "client_credentials"
    assert cred["token_url"].endswith("/oauth/token")
    assert cred["grant_params"] == {"client_id": "svc", "scope": "read"}
    # The sensitive half is never echoed, grant or not.
    assert "secret" not in cred and "the-client-secret" not in str(cred)

    row = db_session.get(CredentialProfile, cred["id"])
    assert row.grant_type == GrantType.client_credentials
    assert decrypt(row.secret_ref) == "the-client-secret"


def test_credential_defaults_to_static_grant(client, new_scan):
    sid = new_scan()
    cred = client.post(
        f"/scans/{sid}/credentials",
        json={"name": "a", "role": "user", "auth_type": "bearer", "secret": "t"},
    ).json()
    assert cred["grant_type"] == "static"
    assert cred["grant_params"] == {}


def test_credential_grant_url_rejects_cloud_metadata(client, new_scan):
    """A grant ``token_url`` is egress — cloud metadata is refused at write time."""
    sid = new_scan()
    r = client.post(
        f"/scans/{sid}/credentials",
        json={
            "name": "svc", "role": "service", "auth_type": "bearer",
            "secret": "sh", "grant_type": "client_credentials",
            "token_url": "http://169.254.169.254/latest/meta-data",
            "grant_params": {"client_id": "svc"},
        },
    )
    assert r.status_code == 422
    assert "token_url" in r.json()["detail"]


def test_credential_refresh_url_rejects_cloud_metadata(client, new_scan):
    """A ``refresh_url`` is egress too — the same guard applies at write time."""
    sid = new_scan()
    r = client.post(
        f"/scans/{sid}/credentials",
        json={
            "name": "svc", "role": "service", "auth_type": "bearer",
            "secret": "sh",
            "refresh_url": "http://metadata.google.internal/",
            "refresh_secret": "rs",
        },
    )
    assert r.status_code == 422
    assert "refresh_url" in r.json()["detail"]


def test_har_upload_via_spec_endpoint_produces_operations(client, new_scan):
    """A HAR file goes through the same /spec endpoint and yields operations."""
    import json

    sid = new_scan()
    har = json.dumps({"log": {"entries": [
        {"request": {"method": "GET", "url": "https://api.test/orders/12345",
                     "queryString": []},
         "response": {"status": 200, "content": {}}},
        {"request": {"method": "POST", "url": "https://api.test/orders",
                     "queryString": [],
                     "postData": {"mimeType": "application/json",
                                  "text": json.dumps({"sku": "x", "qty": 2})}},
         "response": {"status": 201, "content": {}}},
    ]}})
    r = client.post(f"/scans/{sid}/spec", json={"content": har})
    assert r.status_code == 200, r.text
    ops = {(o["method"], o["path"]) for o in r.json()["operations"]}
    assert ("GET", "/orders/{id}") in ops
    assert ("POST", "/orders") in ops
    # The stored spec_text is the synthesised OpenAPI, not the raw HAR.
    assert '"openapi"' in r.json()["spec_text"]


def test_premium_run_requires_a_premium_tenant(client, new_scan, monkeypatch):
    """premium:true is refused unless the caller's tenant may use the tier."""
    from app.core.config import settings

    sid = new_scan()  # no spec yet, but the premium gate fires first
    monkeypatch.setattr(settings, "premium_tenants", "")
    r = client.post(f"/scans/{sid}/run", json={"authorized": True, "premium": True})
    assert r.status_code == 402
    assert "premium" in r.json()["detail"].lower()

    monkeypatch.setattr(settings, "premium_tenants", "default")
    # Premium now passes, so the next gate (no spec) answers instead.
    r = client.post(f"/scans/{sid}/run", json={"authorized": True, "premium": True})
    assert r.status_code == 400


def test_resource_refinement_requires_both_explicit_gates(client, new_scan, monkeypatch):
    """AI recreate loops need premium and write approval in addition to authorization."""
    from app.core.config import settings

    monkeypatch.setattr(settings, "premium_tenants", "*")
    sid = new_scan()  # no spec: a valid approval reaches that later gate

    r = client.post(
        f"/scans/{sid}/run",
        json={"authorized": True, "mutate": True, "resource_refine": True},
    )
    assert r.status_code == 422
    assert "premium:true" in r.json()["detail"]

    r = client.post(
        f"/scans/{sid}/run",
        json={"authorized": True, "premium": True, "resource_refine": True},
    )
    assert r.status_code == 422
    assert "requires writes" in r.json()["detail"]

    r = client.post(
        f"/scans/{sid}/run",
        json={
            "authorized": True,
            "premium": True,
            "mutate": True,
            "resource_refine": True,
        },
    )
    assert r.status_code == 400
    assert "spec" in r.json()["detail"]


def test_tenant_is_premium_wildcard_and_explicit():
    from app.core.config import Settings

    assert Settings(premium_tenants="*").tenant_is_premium("anyone") is True
    assert Settings(premium_tenants="alice,bob").tenant_is_premium("alice") is True
    assert Settings(premium_tenants="alice,bob").tenant_is_premium("eve") is False
    assert Settings(premium_tenants="").tenant_is_premium("alice") is False


# ---- Run trace ----------------------------------------------------------------


def _run_with_trace(db_session, scan_id, rows):
    from app.models.scan import ScanRun

    run = ScanRun(scan_id=scan_id, run_number=1, status="completed", mutations=rows)
    db_session.add(run)
    db_session.commit()
    return run


def test_run_listing_reports_the_trace_size_without_shipping_it(client, db_session, new_scan):
    """A run's trace is hundreds of rows; the listing returns every run."""
    scan_id = new_scan()
    rows = [
        {"sequence": i + 1, "method": "GET", "route": "/x", "check": "bola",
         "request": {}, "response": {"status": 200, "body": "y" * 500}}
        for i in range(250)
    ]
    _run_with_trace(db_session, scan_id, rows)

    listed = client.get(f"/scans/{scan_id}/runs").json()

    assert listed[0]["trace_count"] == 250
    assert "mutations" not in listed[0]


def test_run_trace_pages_oldest_first(client, db_session, new_scan):
    scan_id = new_scan()
    rows = [
        {"sequence": i + 1, "method": "GET", "route": "/x", "check": "bola",
         "request": {}, "response": {"status": 200}}
        for i in range(250)
    ]
    _run_with_trace(db_session, scan_id, rows)

    first = client.get(f"/scans/{scan_id}/runs/1/trace?limit=100").json()
    assert first["total"] == 250
    assert [r["sequence"] for r in first["rows"]] == list(range(1, 101))

    second = client.get(f"/scans/{scan_id}/runs/1/trace?offset=100&limit=100").json()
    assert [r["sequence"] for r in second["rows"]] == list(range(101, 201))

    tail = client.get(f"/scans/{scan_id}/runs/1/trace?offset=240&limit=100").json()
    assert len(tail["rows"]) == 10


def test_run_trace_rejects_an_unknown_run(client, new_scan):
    assert client.get(f"/scans/{new_scan()}/runs/99/trace").status_code == 404


def test_run_trace_reads_rows_archived_before_the_new_fields_existed(
    client, db_session, new_scan
):
    """Old rows have no identity/pass/elapsed_ms — they must still deserialize."""
    scan_id = new_scan()
    _run_with_trace(db_session, scan_id, [
        {"sequence": 1, "method": "POST", "route": "/x", "check": "write_authz",
         "request": {"headers": {}, "query_fields": [], "json_shape": None,
                     "content_bytes": 0},
         "response": {"status": 201, "headers": {}, "content_type": "",
                      "body_bytes": 0, "json_shape": None}},
    ])

    page = client.get(f"/scans/{scan_id}/runs/1/trace").json()

    assert page["rows"][0]["identity"] == "anonymous"
    assert page["rows"][0]["pass"] == "engine"
    assert page["rows"][0]["elapsed_ms"] is None
    assert page["rows"][0]["response"]["body_omitted"] is False
    assert page["rows"][0]["error"] is None


def test_run_trace_names_the_transport_error_of_a_request_that_got_no_response(
    client, db_session, new_scan
):
    scan_id = new_scan()
    _run_with_trace(db_session, scan_id, [
        {"sequence": 1, "method": "GET", "route": "/users/{id}", "check": "bola",
         "error": "ReadTimeout", "request": {}, "response": {"status": None}},
    ])

    row = client.get(f"/scans/{scan_id}/runs/1/trace").json()["rows"][0]

    assert row["error"] == "ReadTimeout"
    assert row["response"]["status"] is None


def test_runs_list_does_not_select_the_full_trace(client, db_session, db_engine, make_scan):
    scan = make_scan()
    db_session.add(
        ScanRun(
            scan_id=scan.id,
            run_number=1,
            status="completed",
            mutations=[{"synthetic": "row"}],
        )
    )
    db_session.commit()
    queries: list[str] = []

    def capture(conn, cursor, statement, parameters, context, executemany):
        queries.append(statement)

    event.listen(db_engine, "before_cursor_execute", capture)
    try:
        response = client.get(f"/scans/{scan.id}/runs")
    finally:
        event.remove(db_engine, "before_cursor_execute", capture)
    assert response.status_code == 200, response.text
    selects = [q for q in queries if "scan_runs.mutations" in q]
    assert not any("scan_runs.mutations," in q for q in selects)
