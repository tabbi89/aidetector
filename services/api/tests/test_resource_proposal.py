"""J1: AI-proposed resource bodies — validation and the setup fallback."""
from __future__ import annotations

from types import SimpleNamespace

from app.ai.types import Usage
from app.domain.enums import AuthType
from app.engine.base import HttpProbe, ResolvedCredential, ScanContext, TargetOperation
from app.engine.resource_bootstrap import provision
from app.engine.resource_proposal import proposal_payload, validate_body


def _producer(*params: dict) -> TargetOperation:
    return TargetOperation(id="create", method="POST", path="/v1/things", params=list(params))


def test_validate_body_accepts_declared_fields():
    op = _producer(
        {"name": "email", "in": "body", "required": True, "schema": {"type": "string"}},
        {"name": "lead", "in": "body", "schema": {"type": "object"}},
    )
    body, reason = validate_body(op, {"email": "a@b.co", "lead": {"status": "NEW"}})
    assert body == {"email": "a@b.co", "lead": {"status": "NEW"}}
    assert reason == ""


def test_validate_body_rejects_undeclared_field():
    op = _producer({"name": "email", "in": "body", "schema": {"type": "string"}})
    body, reason = validate_body(op, {"email": "a@b.co", "role": "admin"})
    assert body is None
    assert "undeclared" in reason


def test_validate_body_rejects_missing_required():
    op = _producer({"name": "email", "in": "body", "required": True, "schema": {"type": "string"}})
    body, reason = validate_body(op, {})
    assert body is None
    assert "required" in reason


def test_validate_body_rejects_wrong_type():
    op = _producer({"name": "count", "in": "body", "schema": {"type": "integer"}})
    body, reason = validate_body(op, {"count": "not-an-int"})
    assert body is None
    assert "schema" in reason


def test_validate_body_rejects_enum_out_of_range():
    op = _producer(
        {"name": "status", "in": "body", "schema": {"type": "string", "enum": ["A", "B"]}}
    )
    body, reason = validate_body(op, {"status": "C"})
    assert body is None


def test_validate_body_rejects_non_object():
    op = _producer({"name": "email", "in": "body", "schema": {"type": "string"}})
    body, _ = validate_body(op, [1, 2])
    assert body is None


def test_proposal_payload_is_value_free_and_includes_schema():
    op = _producer(
        {
            "name": "email",
            "in": "body",
            "required": True,
            "schema": {"type": "string", "format": "email"},
        },
    )
    spec = {
        "paths": {
            "/v1/things": {
                "post": {
                    "requestBody": {
                        "content": {
                            "application/json": {"schema": {"$ref": "#/components/schemas/Thing"}}
                        }
                    }
                }
            }
        },
        "components": {"schemas": {"Thing": {"type": "object", "required": ["email"]}}},
    }
    payload = proposal_payload(op, spec)
    assert payload["method"] == "POST"
    assert payload["path"] == "/v1/things"
    assert payload["fields"] == [
        {"name": "email", "required": True, "schema": {"type": "string", "format": "email"}}
    ]
    assert payload["request_schema"] == {"$ref": "#/components/schemas/Thing"}
    assert "components" in payload



def test_proposal_schema_is_found_behind_a_spec_server_path():
    # The parsed route is ``/v1/things``; the spec key is ``/things`` under a
    # ``/v1`` server. The declared body must still be found.
    op = _producer({"name": "email", "in": "body", "required": True})
    spec = {
        "openapi": "3.0.0",
        "servers": [{"url": "https://api.example.test/v1"}],
        "paths": {"/things": {"post": {"requestBody": {"content": {
            "application/json": {"schema": {"type": "object", "required": ["email"]}},
        }}}}},
    }
    assert op.path == "/v1/things"
    assert proposal_payload(op, spec)["request_schema"] == {
        "type": "object", "required": ["email"],
    }

class _Proposer:
    def __init__(self, body):
        self._body = body
        self.calls = 0
        self.seen = None

    def propose_resource(self, payload):
        self.calls += 1
        self.seen = payload
        return self._body


class _Broken:
    def propose_resource(self, payload):
        raise RuntimeError("no runtime")


class RecordingClient:
    def __init__(self):
        self.requests = []

    def request(self, method, url, **kwargs):
        self.requests.append({"method": method, "url": url, **kwargs})
        if method == "POST" and url == "/v1/merchants":
            body = kwargs.get("json") or {}
            if str(body.get("email", "")).endswith("@example.invalid"):
                return SimpleNamespace(status_code=422, headers={}, text="{}", content=b"{}")
            return SimpleNamespace(
                status_code=201,
                headers={},
                text='{"id":"merchant-ai"}',
                content=b'{"id":"merchant-ai"}',
            )
        if method == "GET" and url == "/v1/merchants/merchant-ai":
            return SimpleNamespace(
                status_code=200,
                headers={},
                text='{"id":"merchant-ai"}',
                content=b'{"id":"merchant-ai"}',
            )
        return SimpleNamespace(status_code=200, headers={}, text="[]", content=b"[]")


def _ctx(client, operations, *, refine=True, attempts=3):
    credential = ResolvedCredential("admin", "admin", AuthType.header, "Authorization", "token")
    probe = HttpProbe(client, operations=operations, credentials=[credential], max_requests=20)
    return ScanContext(
        base_url="http://target", operations=operations, credentials=[credential],
        probe=probe, allow_mutation=True, resource_refine=refine,
        resource_attempts=attempts,
    )


def _merchant_ops():
    return [
        TargetOperation(
            id="create-merchant", method="POST", path="/v1/merchants",
            params=[{"name": "email", "in": "body", "schema": {"type": "string"}}],
        ),
        TargetOperation(
            id="get-merchant", method="GET", path="/v1/merchants/{merchant_id}",
            params=[{"name": "merchant_id", "in": "path", "required": True}],
        ),
        TargetOperation(
            id="get-statements", method="GET", path="/v1/statements/{merchantId}",
            params=[{"name": "merchantId", "in": "path", "required": True}],
        ),
    ]


def test_provision_falls_back_to_ai_when_deterministic_seed_fails():
    operations = _merchant_ops()
    client = RecordingClient()
    ctx = _ctx(client, operations)
    proposer = _Proposer({"email": "merchant@shop.com"})

    notes = provision(ctx, planner=proposer)

    assert proposer.calls == 1
    assert ctx.resource_ids == {"merchant": "merchant-ai"}
    assert any("AI-proposed body" in note for note in notes)
    assert ctx.created_resources == [
        {
            "resource": "merchant",
            "create_method": "POST",
            "create_path": "/v1/merchants",
            "read_method": "GET",
            "read_path": "/v1/merchants/{merchant_id}",
            "status": "verified",
            "via_ai": True,
            "cleanup": "none",
            "source": "ai",
            "attempts": [
                {"number": 1, "source": "deterministic", "status": 422, "error": "{}"},
                {"number": 2, "source": "ai", "status": 201},
            ],
        }
    ]
    urls = [r["url"] for r in client.requests]
    assert urls == ["/v1/merchants", "/v1/merchants", "/v1/merchants/merchant-ai"]
    assert client.requests[0]["json"]["email"].endswith("@example.invalid")
    assert client.requests[1]["json"] == {"email": "merchant@shop.com"}


def test_provision_rejects_ai_body_with_undeclared_field():
    operations = _merchant_ops()
    client = RecordingClient()
    ctx = _ctx(client, operations)
    proposer = _Proposer({"role": "admin"})

    notes = provision(ctx, planner=proposer)

    assert proposer.calls == 1
    assert ctx.resource_ids == {}
    assert any("proposal rejected" in n for n in notes)
    # Only the deterministic attempt went out; the AI body was never sent.
    assert [r["url"] for r in client.requests] == ["/v1/merchants"]


def test_provision_keeps_deterministic_failure_when_ai_unavailable():
    operations = _merchant_ops()
    client = RecordingClient()
    ctx = _ctx(client, operations)

    notes = provision(ctx, planner=_Broken())

    assert ctx.resource_ids == {}
    assert any("resource setup failed" in n for n in notes)


class _SequenceProposer:
    def __init__(self):
        self.calls = 0
        self.seen = []

    def propose_resource(self, payload):
        self.calls += 1
        self.seen.append(payload)
        if self.calls == 1:
            return {"email": "still-invalid@example.invalid"}
        return {"email": "merchant@shop.com"}


def test_provision_refines_twice_from_sanitized_failed_responses():
    operations = _merchant_ops()
    client = RecordingClient()
    ctx = _ctx(client, operations, attempts=3)
    proposer = _SequenceProposer()

    provision(
        ctx,
        planner=proposer,
        schema_context={"tables": [{"name": "merchants", "columns": ["email"]}]},
    )

    assert proposer.calls == 2
    assert ctx.resource_ids == {"merchant": "merchant-ai"}
    assert proposer.seen[0]["previous_response"]["status"] == 422
    assert proposer.seen[0]["previous_response"]["error_excerpt"] == "{}"
    assert proposer.seen[0]["database_schema_metadata"]["tables"][0]["name"] == "merchants"
    resource = ctx.created_resources[0]
    assert [attempt["status"] for attempt in resource["attempts"]] == [422, 422, 201]
    assert [attempt["source"] for attempt in resource["attempts"]] == [
        "deterministic", "ai", "ai"
    ]


def test_provision_reports_ai_usage_for_the_token_ledger():
    operations = _merchant_ops()
    client = RecordingClient()
    ctx = _ctx(client, operations, attempts=2)
    usage = Usage("claude-test", "propose_resource", 12, 4)

    class MeteredProposer:
        def propose_resource(self, payload):
            return {"email": "merchant@shop.com"}, [usage]

    recorded = []
    provision(ctx, planner=MeteredProposer(), on_ai_usage=recorded.extend)

    assert recorded == [usage]


def test_provision_does_not_refine_without_explicit_gate():
    operations = _merchant_ops()
    client = RecordingClient()
    ctx = _ctx(client, operations, refine=False)
    proposer = _Proposer({"email": "merchant@shop.com"})

    provision(ctx, planner=proposer)

    assert proposer.calls == 0
    assert len(client.requests) == 1
