"""Self-contract checks: in-process API, dedicated DB, no scanner/tool execution."""
from __future__ import annotations

import uuid
from datetime import timedelta
from unittest.mock import Mock

import httpx
import pytest
import schemathesis
from hypothesis import HealthCheck, given, settings
from schemathesis.core.failures import FailureGroup
from schemathesis.generation import GenerationMode
from schemathesis.specs.openapi.checks import (
    content_type_conformance,
    response_headers_conformance,
    response_schema_conformance,
    status_code_conformance,
)

from app.core.config import settings as app_settings
from app.domain.enums import Severity
from app.main import app
from app.models.finding import Finding
from app.models.scan import Scan, ScanRun, ScanStatus
from tests.conftest import MINIMAL_SPEC

# Explicit checks only: auth/stateful checks may make follow-up requests.
CHECKS = [status_code_conformance, content_type_conformance,
          response_headers_conformance, response_schema_conformance]
SCHEMA = schemathesis.openapi.from_dict(app.openapi())


@pytest.fixture
def contract_client(client, monkeypatch):
    from app.engine import ai_phases
    from app.workers import tasks

    monkeypatch.setattr(app_settings, "api_keys", "default:contract-key")
    monkeypatch.setattr(app_settings, "premium_tenants", "default")
    client.headers["X-API-Key"] = "contract-key"
    dispatch = Mock()
    monkeypatch.setattr(tasks.run_scan_task, "delay", dispatch)
    # The local runner's post-upload AI analysis would spend tokens.
    monkeypatch.setattr(tasks.analyze_local_run, "delay", Mock())
    monkeypatch.setattr(ai_phases, "answer_question", lambda *_: "Controlled contract answer")
    # Even an accidental direct call cannot execute a target scan or scheduler.
    def forbidden(*_args, **_kwargs):
        pytest.fail("Contract test attempted scanner/scheduler execution")

    monkeypatch.setattr(tasks, "run_scan", forbidden)
    monkeypatch.setattr(tasks, "dispatch_scheduled_scans", forbidden)
    yield client, dispatch


def validate(client, method, route, *, ids=None, body=None, status=200):
    options = {"body": body, "media_type": "application/json"} if body is not None else {}
    case = SCHEMA[route][method].Case(path_parameters=ids, **options)
    # Call TestClient directly. Generated servers/links can never select a transport.
    path = route
    for key, value in (ids or {}).items():
        path = path.replace("{" + key + "}", str(value))
    response = client.request(method, path, json=body)
    assert response.status_code == status, response.text
    case.validate_response(response, checks=CHECKS)
    return response.json()


def test_seeded_authenticated_wire_contracts(contract_client, db_session):
    client, dispatch = contract_client
    validate(client, "GET", "/health")
    scan = validate(client, "POST", "/scans", body={"target_base_url": "http://127.0.0.1"},
                    status=201)
    ids = {"scan_id": scan["id"]}
    assert scan["cancel_requested"] is False
    assert scan["requests_per_second"] == 10
    validate(client, "POST", "/scans/{scan_id}/spec", ids=ids, body={"content": MINIMAL_SPEC})
    cred = validate(client, "POST", "/scans/{scan_id}/credentials", ids=ids, status=201,
                    body={"name": "a", "role": "user", "auth_type": "bearer", "secret": "sentinel"})
    assert "sentinel" not in str(cred)
    assert cred["grant_params"] == {} and cred["header_name"] is None
    validate(client, "PATCH", "/scans/{scan_id}/credentials/{cred_id}",
             ids={**ids, "cred_id": cred["id"]},
             body={"name": "renamed", "role": "user", "auth_type": "bearer"})

    row = db_session.get(Scan, scan["id"])
    finding = Finding(scan_id=row.id, check="bola", severity=Severity.high, title="Fixture",
                      evidence={"route": "/items/{id}"})
    db_session.add(finding)
    for number in (1, 2):
        db_session.add(ScanRun(scan_id=row.id, run_number=number, status="completed",
                              findings_snapshot=[{"check": "bola", "severity": "high",
                                                  "title": "Fixture", "verdict": "unreviewed"}],
                              coverage=[{"method": "GET", "path": "/items"}],
                              plan=[{"method": "GET", "path": "/items"}]))
    db_session.commit()
    for route in ("/scans", "/scans/{scan_id}", "/scans/{scan_id}/progress",
                  "/scans/{scan_id}/findings",
                  "/scans/{scan_id}/runs", "/scans/{scan_id}/coverage",
                  "/scans/{scan_id}/diff", "/scans/{scan_id}/cost"):
        validate(client, "GET", route, ids=ids)
    validate(client, "PATCH", "/scans/{scan_id}/findings/{finding_id}",
             ids={**ids, "finding_id": str(finding.id)}, body={"verdict": "confirmed"})
    validate(client, "POST", "/scans/{scan_id}/ask", ids=ids, body={"question": "What changed?"})
    validate(client, "PUT", "/scans/{scan_id}/schedule", ids=ids, body={"minutes": 0})
    validate(
        client,
        "PUT",
        "/scans/{scan_id}/request-rate",
        ids=ids,
        body={"requests_per_second": 2},
    )
    validate(client, "POST", "/scans/{scan_id}/run", ids=ids,
             body={"authorized": True}, status=202)
    dispatch.assert_called_once()
    cancelled = validate(client, "POST", "/scans/{scan_id}/cancel", ids=ids)
    assert cancelled["cancel_requested"] is True
    polled = validate(client, "GET", "/scans/{scan_id}", ids=ids)
    assert polled["cancel_requested"] is True
    assert polled["requests_per_second"] == 2
    assert polled["status"] == "queued"  # Dispatch is mocked: no worker has stopped it yet.
    validate(client, "GET", "/scans/{scan_id}/events", ids=ids)


@pytest.mark.parametrize("mode", [GenerationMode.POSITIVE, GenerationMode.NEGATIVE])
def test_generated_create_requests_obey_response_contract(contract_client, mode):
    client, _ = contract_client
    operation = SCHEMA["/scans"]["POST"]

    @given(case=operation.as_strategy(generation_mode=mode, headers={}, query={}))
    @settings(max_examples=12, deadline=None, derandomize=True,
              # Schemathesis rejects internal candidates that still satisfy this
              # small request schema; retain a bounded number of accepted examples.
              suppress_health_check=[HealthCheck.too_slow, HealthCheck.filter_too_much])
    def exercise(case):
        if isinstance(case.body, bytes):
            # Syntax fuzzing emits raw JSON bytes, not an object for json.dumps.
            response = client.post("/scans", content=case.body,
                                   headers={"Content-Type": "application/json"})
            assert response.status_code in (400, 422)
        else:
            response = client.post("/scans", json=case.body)
            assert response.status_code == (201 if mode == GenerationMode.POSITIVE else 422)
        case.validate_response(response, checks=CHECKS)

    exercise()


def test_generated_authorized_runs_can_only_reach_stub_dispatch(contract_client, db_session):
    client, dispatch = contract_client
    scan = client.post("/scans", json={"target_base_url": "http://127.0.0.1"}).json()
    sid = scan["id"]
    client.post(f"/scans/{sid}/spec", json={"content": MINIMAL_SPEC})
    operation = SCHEMA["/scans/{scan_id}/run"]["POST"]

    @given(case=operation.as_strategy(headers={}, query={}, path_parameters={"scan_id": sid}))
    @settings(max_examples=12, deadline=None, derandomize=True)
    def exercise(case):
        # Each example has its own lifecycle state, even though Hypothesis reuses fixtures.
        db_session.expire_all()
        row = db_session.get(Scan, sid)
        row.status = ScanStatus.draft
        db_session.commit()
        case.body["authorized"] = True
        # The schema cannot express that resource refinement requires premium and
        # mutate (the route answers 422 without them), so satisfy it like authorized.
        if case.body.get("resource_refine"):
            case.body.update(premium=True, mutate=True)
        response = client.post(f"/scans/{sid}/run", json=case.body)
        assert response.status_code == 202
        case.validate_response(response, checks=CHECKS)

    exercise()
    assert dispatch.call_count >= 1


@pytest.mark.parametrize("body", [{}, {"target_base_url": ""}, {"target_base_url": None}])
def test_invalid_requests_have_documented_validation_response(contract_client, body):
    client, dispatch = contract_client
    validate(client, "POST", "/scans", body=body, status=422)
    dispatch.assert_not_called()


@pytest.mark.parametrize("defect", ["missing", "enum", "nullability"])
def test_conformance_gate_rejects_broken_server_response(defect):
    from app.api.schemas import ScanOut

    payload = ScanOut(
        id=uuid.UUID(int=1), tenant_id="default", target_base_url="http://target.test",
        status=ScanStatus.draft, progress=0, cost_cents=0, created_at="2026-01-01T00:00:00Z",
        cancel_requested=False,
        requests_per_second=10,
    ).model_dump(mode="json")
    case = SCHEMA["/scans/{scan_id}"]["GET"].Case(
        path_parameters={"scan_id": str(uuid.UUID(int=1))}
    )
    request = httpx.Request("GET", "http://test/scans/1")
    baseline = httpx.Response(200, json=payload, request=request)
    baseline.elapsed = timedelta(0)
    case.validate_response(baseline, checks=CHECKS)
    if defect == "missing":
        del payload["target_base_url"]
    elif defect == "enum":
        payload["status"] = "invented"
    else:
        payload["progress"] = None
    response = httpx.Response(200, json=payload, request=httpx.Request("GET", "http://test/scans/1"))
    response.elapsed = timedelta(0)
    with pytest.raises(FailureGroup):
        case.validate_response(response, checks=CHECKS)


def test_output_schema_requires_serialized_defaults_without_changing_input_requirements():
    schemas = app.openapi()["components"]["schemas"]
    assert "confidence" in schemas["FindingOut"]["required"]
    assert "grant_params" in schemas["CredentialOut"]["required"]
    assert "grant_params" not in schemas["CredentialCreate"]["required"]
    assert schemas["RunRequest"]["required"] == ["authorized"]


def test_schema_context_wire_contracts(contract_client):
    client, _ = contract_client
    scan = validate(client, "POST", "/scans", body={"target_base_url": "http://127.0.0.1"},
                    status=201)
    ids = {"scan_id": scan["id"]}
    route = "/scans/{scan_id}/schema-context"
    assert validate(client, "GET", route, ids=ids) == {"latest": None, "snapshot": None}
    assert validate(client, "DELETE", route, ids=ids) == {"removed": 0}
    # There is no route that saves a database connection any more.
    assert client.put(f"/scans/{scan['id']}/database-connection", json={}).status_code in {
        404, 405,
    }
