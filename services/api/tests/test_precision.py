"""The precision gate: every registered check, against a target that is fine.

``tests/vulnapp.py`` proves the checks *fire*. This proves they stay quiet. Both
halves are needed and only one existed: recall without precision is the failure
mode a scanner dies of, because a report where most findings are noise gets
ignored — and the real finding goes with it.

``tests/safeapp.py`` answers the same routes as ``vulnapp`` and does everything
right. The whole registry runs against it under the most aggressive settings the
engine offers (mutation and premium on, two identities), and any finding outside
:data:`ALLOWED` fails this test.

**When this test fails**, the question is which of two things happened:

1. A check got a new signal that misfires on correct behaviour. Fix the check —
   that is the bug this test exists to catch, and it would otherwise reach users
   as noise in every report.
2. ``safeapp`` genuinely is weak in the way the finding says. Fix ``safeapp``.

Adding a :class:`Waiver` to :data:`ALLOWED` is the third option and almost always
the wrong one. Each waiver states why the finding is *correct* against a hardened
target and is scoped as narrowly as that reason allows; without such a reason it
is an admission of a false positive, not a waiver.
"""
from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

from fastapi.testclient import TestClient

from app.engine.checks import ALL_CHECKS
from tests import factories, safeapp
from tests.safeapp import safeapp as safe_app


@dataclass(frozen=True)
class Waiver:
    """One class of finding that is *correct* against this hardened target.

    Scoped as tightly as the reason allows — by check, and where possible by
    route or by a predicate — so waiving the one case a route legitimately earns
    does not blind the gate to the same check misfiring everywhere else.

    ``reason`` is not documentation, it is the entry's justification. A waiver
    whose reason does not explain why a *correct* API produces this finding is
    an unacknowledged false positive, and ``test_every_waiver_carries_a_reason``
    holds the line on that.
    """

    check: str
    reason: str
    routes: frozenset[str] = frozenset()
    when: Callable[[Any], bool] | None = None

    def covers(self, finding: Any, mount: str = "") -> bool:
        """``mount`` is a server path the app is served under, stripped first."""
        if finding.check != self.check:
            return False
        if self.routes:
            route = finding.evidence.get("route") or finding.evidence.get("path")
            if mount and isinstance(route, str) and route.startswith(f"{mount}/"):
                route = route[len(mount):]
            if route not in self.routes:
                return False
        return self.when is None or self.when(finding)


#: Routes that render caller input back into their own response. Escaped
#: correctly — but a marker-reflection lead is about *reachability*, and input
#: does reach the response here. Every other route in the safe app answers with
#: data it owns, so the waivers below stay narrow.
_RENDERING_ROUTES = frozenset({"/search", "/lookup", "/profiles/{handle}"})

ALLOWED: tuple[Waiver, ...] = (
    Waiver(
        check="tls_config",
        reason=(
            "The in-process test transport is http:// — a TestClient has no TLS "
            "to inspect, so 'not served over TLS' is necessarily true. This is a "
            "property of the harness, not of the application."
        ),
    ),
    Waiver(
        check="reflected_injection",
        when=lambda f: bool(f.evidence.get("error_surface")),
        reason=(
            "A typed path parameter rejected with 422 echoes the value it could "
            "not parse. The check already recognises this and reports it at info "
            "with error_surface=true, which is the correct handling; the finding "
            "describes the framework's error envelope, not a sink."
        ),
    ),
    Waiver(
        check="reflected_injection",
        routes=_RENDERING_ROUTES,
        reason=(
            "These routes render the caller's own search term into their HTML "
            "response, escaped. Escaping neutralises the markup, but the payload "
            "still reaches the response body, which is exactly what a reflection "
            "lead reports — heuristically, and explicitly not as exploitation."
        ),
    ),
    Waiver(
        check="signature_injection",
        routes=_RENDERING_ROUTES,
        reason=(
            "Same rendering routes, same reason: reflection of an escaped payload "
            "into a rendered page. No backend error signature is matched on any "
            "of these, which is the signal this check actually exists for."
        ),
    ),
)


def _operations():
    """The safe app's surface, in the shape the engine consumes.

    ``auth_scope`` is set on the privileged routes because the safe app's *spec*
    is correct too: ``design_review`` reads the declared scope, and a spec that
    omits it on an admin route is a genuine finding about the document.
    """
    op = factories.operation
    return [
        op("GET", "/accounts/{account_id}", id="s-account"),
        op("GET", "/accounts", id="s-accounts", params=[]),
        op("GET", "/catalog", id="s-catalog",
           params=[{"name": "limit", "in": "query", "required": False,
                    "schema": {"type": "integer"}}]),
        op("POST", "/admin/users/{user_id}/promote", id="s-promote",
           auth_scope="admin"),
        op("GET", "/admin/audit", id="s-admin-audit", params=[], auth_scope="admin"),
        op("GET", "/users/{user_id}", id="s-user"),
        op("GET", "/search", id="s-search",
           params=[{"name": "q", "in": "query", "required": False}]),
        op("GET", "/lookup", id="s-lookup",
           params=[{"name": "name", "in": "query", "required": False}]),
        op("GET", "/profiles/{handle}", id="s-profile"),
        op("GET", "/compute", id="s-compute",
           params=[{"name": "expr", "in": "query", "required": False}]),
        op("GET", "/fetch", id="s-fetch",
           params=[{"name": "url", "in": "query", "required": False}]),
        op("GET", "/widgets/{widget_id}", id="s-widget"),
        op("PUT", "/widgets/{widget_id}", id="s-widget-put",
           params=[{"name": "widget_id", "in": "path", "required": True},
                   {"name": "name", "in": "body", "schema": {"type": "string"}}]),
        op("POST", "/widgets", id="s-widget-create",
           params=[{"name": "name", "in": "body", "schema": {"type": "string"}}]),
        op("DELETE", "/widgets/{widget_id}", id="s-widget-delete"),
        op("POST", "/orders", id="s-order",
           params=[{"name": "ref", "in": "body", "schema": {"type": "string"}}]),
        op("POST", "/checkout", id="s-checkout",
           params=[{"name": "item", "in": "body", "schema": {"type": "string"}}]),
        op("POST", "/projects", id="s-project",
           params=[{"name": "name", "in": "body", "schema": {"type": "string"}}]),
        op("POST", "/projects/{project_id}/items", id="s-item",
           params=[{"name": "project_id", "in": "path", "required": True},
                   {"name": "label", "in": "body", "schema": {"type": "string"}}]),
        op("GET", "/projects/{project_id}/items/{item_id}", id="s-item-read"),
        op("DELETE", "/projects/{project_id}/items/{item_id}", id="s-item-delete"),
        op("POST", "/login", id="s-login",
           params=[{"name": "username", "in": "body", "schema": {"type": "string"}}]),
        op("GET", "/monitors", id="s-monitors", params=[]),
        op("GET", "/monitors/{id}", id="s-monitor"),
        op("GET", "/incidents", id="s-incidents", params=[]),
        op("GET", "/incidents/{id}", id="s-incident"),
        op("GET", "/health", id="s-health", params=[]),
    ]


def _scan_the_safe_app(**kwargs):
    safeapp.reset_state()
    operations = _operations()
    ctx = factories.scan_context(
        operations,
        client=TestClient(safe_app),
        credentials=factories.two_identities(),
        **kwargs,
    )
    findings = []
    for check in ALL_CHECKS:
        findings.extend(factories.run_check(check, ctx))
    return findings


def _unexpected(findings, mount: str = ""):
    return [f for f in findings if not any(w.covers(f, mount) for w in ALLOWED)]


def _describe(findings) -> str:
    return "\n".join(
        f"  {f.check} [{f.severity.value}/{f.confidence.value}] {f.title}"
        f"\n    evidence: {f.evidence}"
        for f in findings
    )


def test_a_default_scan_of_a_correct_api_reports_nothing():
    """The common case: no opt-ins, so only the read-only checks run."""
    unexpected = _unexpected(_scan_the_safe_app())
    assert not unexpected, "false positives on a hardened target:\n" + _describe(unexpected)


def test_the_most_aggressive_scan_of_a_correct_api_reports_nothing():
    """Everything on: mutation, premium, two identities — the widest surface."""
    unexpected = _unexpected(_scan_the_safe_app(allow_mutation=True, premium=True))
    assert not unexpected, "false positives on a hardened target:\n" + _describe(unexpected)


#: The safe app's public reads, documented as it actually answers them, under
#: a server path. A spec like this is how real APIs ship — ``servers:
#: [{url: https://host/api/v1}]`` — and the vulnapp/safeapp specs above carry
#: no prefix, so without this a check that ignored the prefix stayed invisible
#: here while every one of its findings in production was a frontend 404.
_JSON_OBJECT = {"content": {"application/json": {"schema": {"type": "object"}}}}
_PREFIXED_SPEC: dict[str, Any] = {
    "openapi": "3.0.0",
    "info": {"title": "safe", "version": "1"},
    "servers": [{"url": "https://api.example.test/api/v1"}],
    "paths": {
        "/catalog": {"get": {
            "parameters": [{"name": "limit", "in": "query", "required": False,
                            "schema": {"type": "integer"}}],
            "responses": {
                "200": {"description": "page", **_JSON_OBJECT},
                "422": {"description": "invalid limit", **_JSON_OBJECT},
            },
        }},
        "/compute": {"get": {
            "parameters": [{"name": "expr", "in": "query", "required": False,
                            "schema": {"type": "string"}}],
            "responses": {"200": {"description": "result", **_JSON_OBJECT}},
        }},
        "/health": {"get": {
            "responses": {"200": {"description": "up", **_JSON_OBJECT}},
        }},
    },
}


def test_a_scan_of_a_correct_api_under_a_server_path_reports_nothing():
    """The spec's server path is honoured by every check, schema fuzzing included.

    The API lives under ``/api/v1``; everything else is a frontend that answers
    an HTML 404. A check that sends to the bare spec key lands on that page and
    reports it — undocumented 404, wrong content type — which is noise.
    """
    from starlette.applications import Starlette
    from starlette.responses import HTMLResponse
    from starlette.routing import Mount, Route

    from app.specs.parser import parse_operations

    frontend_hits: list[str] = []

    async def frontend_404(request):
        frontend_hits.append(request.url.path)
        return HTMLResponse("<html>not found</html>", status_code=404)

    site = Starlette(routes=[
        Mount("/api/v1", app=safe_app),
        Route("/{rest:path}", frontend_404, methods=["GET", "POST", "PUT", "PATCH", "DELETE"]),
    ])
    parsed = {
        (op.method, op.path)
        for op in parse_operations(_PREFIXED_SPEC, target_base_url=factories.BASE_URL)
    }
    operations = [
        factories.operation(
            op.method, f"/api/v1{op.path}", id=op.id, params=op.params,
            auth_scope=op.auth_scope,
        )
        for op in _operations()
    ]
    assert parsed <= {(op.method, op.path) for op in operations}

    safeapp.reset_state()
    ctx = factories.scan_context(
        operations,
        client=TestClient(site),
        credentials=factories.two_identities(),
        spec=_PREFIXED_SPEC,
        fuzz_cases=24,
    )
    findings = []
    for check in ALL_CHECKS:
        findings.extend(factories.run_check(check, ctx))

    assert not frontend_hits, f"requests ignored the server path: {sorted(set(frontend_hits))}"
    fuzzed = sum(
        counts.get("schema_fuzz", 0) for counts in ctx.probe.coverage.values()
    )
    assert fuzzed, "schema_fuzz sent nothing, so this proves nothing about it"
    unexpected = _unexpected(findings, mount="/api/v1")
    assert not unexpected, "false positives on a hardened target:\n" + _describe(unexpected)


def test_bfla_needs_two_identities_and_an_authenticated_boundary():
    """A lone admin and a public admin-looking route are not BFLA evidence."""
    from app.engine.checks.authz import BflaCheck

    operations = _operations()
    single_admin = [factories.credential("admin", "admin")]
    ctx = factories.scan_context(
        operations, client=TestClient(safe_app), credentials=single_admin
    )

    assert BflaCheck().run(ctx) == []
    assert ctx.probe.count == 0

    public_op = factories.operation("GET", "/admin/status", id="s-admin-status")
    public_ctx = factories.scan_context(
        [public_op], client=TestClient(safe_app), credentials=factories.two_identities()
    )
    assert BflaCheck().run(public_ctx) == []
    assert public_ctx.probe.count == 1  # anonymous baseline proves it is public


def test_the_gate_would_notice_a_real_weakness():
    """A precision gate that cannot fail proves nothing — so prove it can.

    The same operations against the *vulnerable* app must produce findings the
    allowlist does not cover. Without this, a bug that made every check return
    nothing would leave both tests above passing.
    """
    from tests.vulnapp import vulnapp

    operations = _operations()
    ctx = factories.scan_context(
        operations, client=TestClient(vulnapp), credentials=factories.two_identities()
    )
    findings = []
    for check in ALL_CHECKS:
        findings.extend(factories.run_check(check, ctx))
    assert _unexpected(findings), "the gate cannot distinguish a weak target from a strong one"


def test_every_waiver_carries_a_reason():
    """A waiver without a stated reason is an unacknowledged false positive."""
    for waiver in ALLOWED:
        assert len(waiver.reason.strip()) > 60, (
            f"{waiver.check}'s reason is too thin to review: {waiver.reason!r}"
        )


def test_no_waiver_is_dead():
    """A waiver nothing matches is stale — the check changed and this did not.

    Left in place it silently widens the gate's blind spot for the next finding
    that happens to match, so it fails here instead.
    """
    findings = _scan_the_safe_app(allow_mutation=True, premium=True)
    unused = [w for w in ALLOWED if not any(w.covers(f) for f in findings)]
    assert not unused, (
        "waivers that matched nothing — remove them:\n"
        + "\n".join(f"  {w.check} {sorted(w.routes) or '(any route)'}" for w in unused)
    )
