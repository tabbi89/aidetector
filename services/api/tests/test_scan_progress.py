"""The lightweight progress poll: volatile fields only, tenant-scoped."""
from __future__ import annotations

from sqlalchemy import event

from app.core.config import settings
from app.models.scan import ScanStatus


def test_progress_returns_only_the_volatile_fields(client, make_scan, db_session):
    scan = make_scan()
    scan.status = ScanStatus.running
    scan.progress = 42
    scan.cost_cents = 7
    db_session.commit()

    response = client.get(f"/scans/{scan.id}/progress")
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["id"] == str(scan.id)
    assert body["status"] == "running"
    assert body["progress"] == 42
    assert body["cost_cents"] == 7
    # The detail read loads the scan's collections; this poll must not.
    for absent in (
        "operations",
        "credential_profiles",
        "spec_text",
        "findings",
        "events",
        "managed_config",
    ):
        assert absent not in body


def test_progress_is_one_select(client, make_scan, db_engine, monkeypatch):
    """The endpoint is O(1): the row, and nothing eager-loaded around it."""
    scan = make_scan()
    # Keyed, as a deployment is: the keyless open posture spends one lookup
    # asking whether a password admin has closed it, which is not this route's.
    monkeypatch.setattr(settings, "api_keys", "default:key-d")
    statements: list[str] = []

    def record(conn, cursor, statement, parameters, context, executemany):
        statements.append(statement)

    event.listen(db_engine, "before_cursor_execute", record)
    try:
        assert (
            client.get(
                f"/scans/{scan.id}/progress", headers={"X-API-Key": "key-d"}
            ).status_code
            == 200
        )
    finally:
        event.remove(db_engine, "before_cursor_execute", record)

    selects = [s for s in statements if s.lstrip().upper().startswith("SELECT")]
    assert len(selects) == 1, selects


def test_progress_is_scoped_to_the_caller_tenant(
    client, make_scan, db_session, monkeypatch
):
    scan = make_scan()
    scan.tenant_id = "acme"
    db_session.commit()
    monkeypatch.setattr(settings, "api_keys", "acme:key-a,beta:key-b")

    assert (
        client.get(
            f"/scans/{scan.id}/progress", headers={"X-API-Key": "key-a"}
        ).status_code
        == 200
    )
    assert (
        client.get(
            f"/scans/{scan.id}/progress", headers={"X-API-Key": "key-b"}
        ).status_code
        == 404
    )
