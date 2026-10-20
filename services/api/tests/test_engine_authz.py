"""Authorization checks against the in-process vulnerable app.

BOLA and BFLA are the reason a scan takes two credential roles, so most of these
turn on what changes when the identity does.
"""
from __future__ import annotations

import json
from types import SimpleNamespace

from fastapi import FastAPI, Header
from fastapi.responses import JSONResponse
from fastapi.testclient import TestClient

from app.domain.enums import AuthType
from app.engine.base import (
    HttpProbe,
    ResolvedCredential,
    TargetOperation,
)
from app.engine.checks.auth import BrokenAuthCheck
from tests import factories
from tests.vulnapp import vulnapp

OPERATIONS = factories.engine_operations()
CREDS = factories.two_identities()


def _run_all():
    return factories.run_registry(OPERATIONS, credentials=CREDS)


def test_bola_is_flagged_on_shared_object():
    bola = [f for f in _run_all() if f.check == "bola"]
    assert bola
    assert bola[0].owasp_id == "API1:2023"
    assert "/accounts/" in bola[0].evidence["path"]


def test_bola_fires_when_responses_carry_volatile_metadata():
    """A real API stamps a fresh timestamp/request-id on every response, so two
    identities reading the *same* object get different raw bodies. The old raw
    ``==`` comparison missed this; the normalised comparison must not."""
    from app.engine.checks.authz import BolaCheck

    op = TargetOperation(
        id="op-invoice",
        method="GET",
        path="/invoices/{invoice_id}",
        params=[{"name": "invoice_id", "in": "path", "required": True}],
    )
    findings = factories.run_one(BolaCheck(), [op], credentials=CREDS)
    bola = [f for f in findings if f.check == "bola"]
    assert bola, "BOLA missed because a volatile field differed between reads"
    assert bola[0].evidence["path"] == "/invoices/1"


def test_bfla_on_admin_endpoint():
    bfla = [f for f in _run_all() if f.check == "bfla"]
    assert bfla
    assert bfla[0].owasp_id == "API5:2023"
    assert bfla[0].evidence["identity"] == "alice"  # low-priv reached admin op


def test_evidence_names_identities_even_when_roles_match():
    """Two users can share a role; the finding must still say which is which."""
    creds = [
        factories.credential("alice", "user"),
        factories.credential("bob", "user", "bob-token"),
    ]
    bola = [
        f
        for f in factories.run_registry(OPERATIONS, credentials=creds)
        if f.check == "bola"
    ]
    assert bola, "two same-role credentials should still be compared"
    assert {
        bola[0].evidence["identity_a"],
        bola[0].evidence["identity_b"],
    } == {"alice", "bob"}


def test_broken_auth_uses_the_configured_api_key_header():
    app = FastAPI()

    @app.get("/account")
    def account(x_api_key: str | None = Header(default=None)):
        if x_api_key is None:
            return JSONResponse({"detail": "unauthorized"}, status_code=401)
        # VULN: any non-empty API key is accepted.
        return {"account": "alice"}

    from app.engine.checks.auth import BrokenAuthCheck

    op = factories.operation("GET", "/account", auth_scope="apiKey")
    credential = ResolvedCredential(
        "alice", "user", AuthType.api_key, "X-API-Key", "valid-key"
    )
    ctx = factories.scan_context(
        [op], credentials=[credential], client=TestClient(app)
    )

    findings = BrokenAuthCheck().run(ctx)

    assert findings and findings[0].evidence["bypass_class"] == "random_token"
    forged_row = ctx.probe.mutations[-1]
    assert "x-api-key" in forged_row["request"]["headers"]
    assert "authorization" not in forged_row["request"]["headers"]


def test_bola_no_credentials_is_noop():
    probe = HttpProbe(TestClient(vulnapp))
    ctx = factories.scan_context(OPERATIONS, credentials=[], probe=probe)
    from app.engine.checks.authz import BolaCheck

    check = BolaCheck()
    assert check.run(ctx) == []
    assert check.inapplicable(ctx) == (
        "no usable credential supplied — BOLA needs an authenticated identity"
    )


def test_bfla_harvests_uuid_instead_of_probing_synthetic_one():
    from app.engine.checks.authz import BflaCheck

    object_id = "1ab52d43-2a57-45ad-bdf2-dc76fd61db68"
    operations = [
        TargetOperation(id="users", method="GET", path="/admin/users"),
        TargetOperation(
            id="user",
            method="GET",
            path="/admin/users/{userId}",
            params=[{"name": "userId", "in": "path", "required": True}],
            auth_scope="admin",
        ),
    ]
    seen: list[str] = []

    class Client:
        def request(self, method, url, **kwargs):
            seen.append(url)
            headers = kwargs.get("headers", {})
            if url == "/admin/users":
                body, status = json.dumps([{"userId": object_id}]), 200
            elif url == f"/admin/users/{object_id}":
                status = 401 if not headers else 200
                body = '{"user":"shared"}' if status == 200 else '{}'
            else:
                status, body = 404, "{}"
            return SimpleNamespace(
                status_code=status, headers={}, text=body, content=body.encode()
            )

    probe = HttpProbe(Client(), operations=operations, credentials=CREDS)
    ctx = factories.scan_context(
        operations, credentials=CREDS, probe=probe
    )
    findings = BflaCheck().run(ctx)

    assert findings
    assert findings[0].evidence["path"] == f"/admin/users/{object_id}"
    assert findings[0].evidence["ids_harvested"] is True
    assert "/admin/users/1" not in seen


def test_bola_single_identity_degrades_to_sibling_lead():
    """APIs with exactly one account and no roles: BOLA cannot prove cross-
    tenant access, so it reports a LOW sibling-probing lead instead of no-oping."""
    from app.engine.checks.authz import BolaCheck

    ops = OPERATIONS + [
        TargetOperation(id="op-acct-list", method="GET", path="/accounts", params=[]),
    ]
    probe = HttpProbe(TestClient(vulnapp), operations=ops)
    ctx = factories.scan_context(ops, credentials=CREDS[:1], # single identity
        probe=probe)
    findings = BolaCheck().run(ctx)
    assert findings, "single-identity BOLA should produce a sibling lead"
    f = findings[0]
    assert f.owasp_id == "API1:2023"
    assert f.severity.value == "low"
    assert f.evidence["mode"] == "single-identity"
    # The harvest read found a real id, and the sibling id was reachable.
    assert f.evidence["baseline_harvested"] is True
    assert f.evidence["baseline_id"] == "1"
    assert f.evidence["sibling_id"] == "2"
    assert f.evidence["sibling_status"] == 200


def test_bola_matches_camelcase_id_params():
    """Real specs mix snake_case and camelCase; the id matcher must take both."""
    from app.engine.checks.authz import BolaCheck

    op = TargetOperation(
        id="op-acct-camel",
        method="GET",
        path="/accounts/{accountId}",
        params=[{"name": "accountId", "in": "path", "required": True}],
    )
    ctx = factories.scan_context([op], credentials=CREDS)
    findings = BolaCheck().run(ctx)
    assert findings, "camelCase id param must be treated as an object op"
    assert findings[0].owasp_id == "API1:2023"


def test_bola_resolves_related_resource_ids_for_dependent_routes():
    """A merchant collection can provide the ID needed by statement routes.

    The API does not need a synthetic ``1`` statement/merchant ID when the spec
    describes the collection and parent read. This is the dependency shape used
    by ``/statements/{merchantId}/download/{statementId}``.
    """
    from app.engine.checks.authz import _harvest_dependency_ids

    merchants = TargetOperation(id="merchant-list", method="GET", path="/v1/merchants")
    statements = TargetOperation(
        id="statement-list", method="GET", path="/v1/statements/{merchantId}",
        params=[{"name": "merchantId", "in": "path", "required": True}],
    )
    download = TargetOperation(
        id="statement-download", method="GET",
        path="/v1/statements/{merchantId}/download/{statementId}",
        params=[
            {"name": "merchantId", "in": "path", "required": True},
            {"name": "statementId", "in": "path", "required": True},
        ],
    )

    class Client:
        def request(self, method, url, **kwargs):
            if url == "/v1/merchants":
                body = '[{"id":"merchant-42"}]'
            elif url == "/v1/statements/merchant-42":
                body = '[{"statementId":"statement-9"}]'
            else:
                body = "[]"
            return SimpleNamespace(status_code=200, headers={}, text=body, content=body.encode())

    operations = [merchants, statements, download]
    probe = HttpProbe(Client(), operations=operations, max_requests=10)
    ctx = factories.scan_context(operations, credentials=CREDS, probe=probe)
    values = _harvest_dependency_ids(ctx, CREDS[0], download, {}, {})

    assert values == {"merchantId": "merchant-42", "statementId": "statement-9"}
    assert probe.count == 2


def test_destructive_delete_probe_is_gated_by_mutation():
    from app.engine.checks.auth import BrokenAuthCheck

    op = TargetOperation(
        id="w-del", method="DELETE", path="/admin/widgets/{widget_id}",
        params=[{"name": "widget_id", "in": "path", "required": True}],
    )
    # Default scan: DELETE is never probed — no request is even sent.
    ctx = factories.scan_context([op], credentials=CREDS)
    probe = ctx.probe
    assert BrokenAuthCheck().run(ctx) == []
    assert probe.count == 0

    # Under mutate:true the DELETE is probed: an anonymous baseline (rejected)
    # then a forged token (accepted) → a broken-auth finding.
    ctx2 = factories.scan_context([op], credentials=CREDS, allow_mutation=True)
    probe2 = ctx2.probe
    findings = BrokenAuthCheck().run(ctx2)
    assert probe2.count >= 2  # anon baseline + at least one forgery
    assert findings and findings[0].owasp_id == "API2:2023"
    assert findings[0].evidence["bypass_class"]


def test_broken_auth_skips_public_endpoint():
    # /health returns 200 for anon; marking it auth-scoped makes it look
    # protected, but the baseline (anon accepted) proves there is nothing to
    # bypass — so no finding.
    op = TargetOperation(
        id="op-health", method="GET", path="/health", params=[], auth_scope="bearer"
    )
    creds = [ResolvedCredential("u", "user", AuthType.header, "Authorization", "t")]
    ctx = factories.scan_context([op], credentials=creds)
    assert BrokenAuthCheck().run(ctx) == []


def _scoped_app(body):
    """An API whose object route answers every authenticated caller with ``body``."""
    app = FastAPI()

    @app.get("/monitors/{monitor_id}/checks")
    def checks(monitor_id: str, authorization: str | None = Header(default=None)):
        if not authorization:
            return JSONResponse({"error": "sign in"}, status_code=401)
        return JSONResponse(body(monitor_id) if callable(body) else body)

    return app


def test_identical_empty_responses_are_not_bola():
    """A workspace-scoped query answers a foreign monitor with ``[]`` — for every
    caller. Both identities getting the same empty list is the API doing it
    right, and was reported as a verified cross-identity read."""
    from app.engine.checks.authz import BolaCheck

    op = TargetOperation(
        id="op-checks", method="GET", path="/monitors/{monitor_id}/checks",
        params=[{"name": "monitor_id", "in": "path", "required": True}],
    )
    for empty in ([], {}, None, {"items": [], "total": 0}):
        findings = factories.run_one(
            BolaCheck(), [op], credentials=CREDS, client=TestClient(_scoped_app(empty))
        )
        assert not [f for f in findings if f.severity == "high"], empty
    # Control: the object's own data, returned to both, still is BOLA.
    def leaked(monitor_id: str) -> list[dict]:
        return [{"id": f"c-{monitor_id}", "monitor_id": monitor_id, "latency_ms": 181}]

    findings = factories.run_one(
        BolaCheck(), [op], credentials=CREDS, client=TestClient(_scoped_app(leaked))
    )
    assert any(f.severity == "high" for f in findings)
