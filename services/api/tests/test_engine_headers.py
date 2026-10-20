"""The per-endpoint header sweep and the pure scoring rules behind it.

``security_headers`` and ``info_disclosure`` share one sweep, memoised on the
context, so an endpoint is probed once even though checks run concurrently.
The scoring in ``header_policy`` is pure and tested directly.
"""
from __future__ import annotations

from app.engine.base import (
    TargetOperation,
)
from tests import factories

OPERATIONS = factories.engine_operations()
CREDS = factories.two_identities()


def _run_check(check, operations, *, allow_mutation=False):
    return factories.run_one(
        check, operations, credentials=CREDS, allow_mutation=allow_mutation
    )


def test_info_disclosure_flags_debug_headers():
    from app.engine.checks.misconfig import InfoDisclosureCheck

    op = TargetOperation(id="op-debug", method="GET", path="/debuginfo", params=[])
    findings = _run_check(InfoDisclosureCheck(), [op])
    assert len(findings) == 1
    f = findings[0]
    assert f.check == "info_disclosure"
    assert f.owasp_id == "API8:2023"
    assert f.severity.value == "low"
    assert "x-debug-id" in f.evidence["headers"]
    assert "x-trace-id" in f.evidence["headers"]


def test_security_headers_reports_hygiene_separately():
    from app.engine.checks.misconfig import SecurityHeadersCheck

    op = TargetOperation(id="op-health", method="GET", path="/health", params=[])
    findings = _run_check(SecurityHeadersCheck(), [op])
    severities = {f.severity.value for f in findings}
    assert "medium" in severities, "core hardening headers missing → medium"
    assert "low" in severities, "permissions-policy missing → low hygiene finding"
    hygiene = next(f for f in findings if f.severity.value == "low")
    assert "permissions-policy" in hygiene.evidence["missing"]


def test_security_headers_sweeps_every_endpoint():
    """Per-endpoint, not one representative request: a hardened endpoint must
    stay out of the findings its unhardened neighbour earns."""
    from app.engine.checks.misconfig import SecurityHeadersCheck

    ops = [
        TargetOperation(id="op-health", method="GET", path="/health", params=[]),
        TargetOperation(id="op-hardened", method="GET", path="/hardened", params=[]),
    ]
    ctx = factories.scan_context(ops, credentials=CREDS)
    probe = ctx.probe
    findings = SecurityHeadersCheck().run(ctx)
    assert probe.count == 2, "one request per endpoint"

    core = next(f for f in findings if f.severity.value == "medium")
    assert core.evidence["probed_endpoints"] == 2
    assert core.evidence["affected_endpoints"] == ["GET /health"]
    assert core.operation_id == "op-health", "a single-endpoint group links its operation"
    assert set(core.evidence["missing"]) == {
        "x-content-type-options",
        "x-frame-options",
        "content-security-policy",
        "referrer-policy",
    }


def test_security_headers_flags_weak_values_and_permissive_cors():
    from app.engine.checks.misconfig import SecurityHeadersCheck

    op = TargetOperation(id="op-legacy", method="GET", path="/legacy", params=[])
    findings = _run_check(SecurityHeadersCheck(), [op])
    by_sev = {f.severity.value: f for f in findings}

    cors = by_sev["high"].evidence["weak"]["access-control-allow-origin"]
    assert cors["observed"].startswith("https://aidx-"), "throwaway Origin echoed back"
    assert "Credentials" in by_sev["high"].description

    weak = by_sev["medium"].evidence["weak"]
    assert "ALLOWALL" in weak["x-frame-options"]["problem"]
    assert "'unsafe-inline'" in weak["content-security-policy"]["problem"]
    assert "referrer-policy" in weak
    # Cookie flags are reported; the cookie's value never is.
    assert "HttpOnly" in weak["set-cookie"]["problem"]
    assert "s3cr3t" not in str(by_sev["medium"].evidence)


def test_header_sweep_is_shared_between_checks():
    from app.engine.checks.misconfig import InfoDisclosureCheck, SecurityHeadersCheck

    ops = [
        TargetOperation(id="op-health", method="GET", path="/health", params=[]),
        TargetOperation(id="op-debug", method="GET", path="/debuginfo", params=[]),
    ]
    ctx = factories.scan_context(ops, credentials=CREDS)
    probe = ctx.probe
    assert SecurityHeadersCheck().run(ctx)
    assert probe.count == 2
    leaks = InfoDisclosureCheck().run(ctx)
    # The sweep is reused; the only request of its own is the one trailing-slash
    # probe that looks for a redirect naming an internal host.
    assert probe.count == 3, "the second header check reuses the sweep"
    assert leaks[0].evidence["affected_endpoints"] == ["GET /debuginfo"]


# Every hardening header the policy knows about, each set to a good value.
# Mirrors the /hardened endpoint in vulnapp.py.
_HARDENED = {
    "x-content-type-options": "nosniff",
    "x-frame-options": "DENY",
    "content-security-policy": "default-src 'self'",
    "referrer-policy": "no-referrer",
    "permissions-policy": "geolocation=()",
    "cross-origin-opener-policy": "same-origin",
    "cross-origin-resource-policy": "same-origin",
    "cross-origin-embedder-policy": "require-corp",
    "x-permitted-cross-domain-policies": "none",
    "document-policy": "document-write=?0",
    "integrity-policy": "blocked-destinations=(script)",
    "origin-agent-cluster": "?1",
    "x-dns-prefetch-control": "off",
    "x-download-options": "noopen",
}


def test_analyze_headers_scores_hygiene_values_not_just_presence():
    """A hygiene header set to the value that defeats it is not a pass."""
    from app.engine.header_policy import analyze_headers

    weakened = {
        **_HARDENED,
        "cross-origin-resource-policy": "cross-origin",
        "x-permitted-cross-domain-policies": "all",
        "origin-agent-cluster": "?0",
        # A report-to tail must not defeat the value comparison.
        "cross-origin-opener-policy": 'same-origin; report-to="coop"',
    }
    issues = analyze_headers(weakened, https=False)
    assert {i.header for i in issues} == {
        "cross-origin-resource-policy",
        "x-permitted-cross-domain-policies",
        "origin-agent-cluster",
    }
    assert all(i.kind == "weak" and i.severity.value == "low" for i in issues)


def test_analyze_headers_ignores_clear_site_data_and_upgrade_insecure_requests():
    """Neither is a per-response hardening header, so neither may fire a
    'missing' finding on every endpoint."""
    from app.engine.header_policy import analyze_headers

    assert analyze_headers(_HARDENED, https=False) == []


def test_analyze_headers_scores_hsts_only_over_https():
    from app.engine.header_policy import analyze_headers

    hardened = _HARDENED
    assert analyze_headers(hardened, https=False) == []

    missing = analyze_headers(hardened, https=True)
    assert [(i.header, i.kind) for i in missing] == [
        ("strict-transport-security", "missing")
    ]

    weak = analyze_headers({**hardened, "strict-transport-security": "max-age=300"}, https=True)
    assert weak[0].kind == "weak"
    assert "max-age=300" in weak[0].detail and "includeSubDomains" in weak[0].detail

    assert (
        analyze_headers(
            {**hardened, "strict-transport-security": "max-age=31536000; includeSubDomains"},
            https=True,
        )
        == []
    )


def test_analyze_disclosure_headers_only_flags_versioned_banners():
    from app.engine.header_policy import analyze_disclosure_headers

    assert analyze_disclosure_headers({"Server": "nginx"}) == []
    assert analyze_disclosure_headers({"X-Request-Id": "abc"}) == []
    issues = analyze_disclosure_headers({"Server": "nginx/1.18.0", "X-Powered-By": "Express"})
    assert {i.header for i in issues} == {"server", "x-powered-by"}
    assert all(i.kind == "banner" and i.severity.value == "low" for i in issues)


def test_csp_with_nonce_or_hash_is_not_an_unsafe_inline_defect():
    """A nonce or hash makes browsers ignore ``unsafe-inline`` — the header is
    then correctly hardened, not weak."""
    from app.engine.header_policy import analyze_headers

    def csp_issues(value):
        return [
            i for i in analyze_headers({"content-security-policy": value})
            if i.header == "content-security-policy"
        ]

    for value in (
        "script-src 'nonce-abc123' 'unsafe-inline'",
        "script-src 'sha256-abc123' 'unsafe-inline'",
        "script-src 'strict-dynamic' 'unsafe-inline'",
    ):
        assert csp_issues(value) == [], value
    # No nonce/hash: the flag stays.
    assert csp_issues("script-src 'unsafe-inline'") != []


def test_an_insecure_cookie_is_not_masked_by_a_secure_sibling():
    """Two Set-Cookie headers, one without Secure, must not inherit the other's
    Secure flag through comma-joining."""
    from app.engine.header_policy import analyze_headers

    raw = "session=s3cr3t; Path=/\ncsrf=token; Secure"
    issues = analyze_headers({"set-cookie": raw}, https=True)
    cookie_issues = [i for i in issues if i.header == "set-cookie"]
    names = {i.observed for i in cookie_issues}
    assert names == {"session", "csrf"}
    # The session cookie lacks Secure; the csrf cookie has it.
    by_name = {i.observed: i.detail for i in cookie_issues}
    assert "Secure" in by_name["session"]
    assert "Secure" not in by_name["csrf"]


def test_cors_reflection_ignores_case_and_trailing_slash():
    """Echoing the probe Origin with a trailing slash or different case is still
    reflecting it."""
    from app.engine.header_policy import analyze_headers

    probe = "https://aidx-123.example"
    for echoed in ("https://aidx-123.example/", "HTTPS://aidx-123.example"):
        issues = analyze_headers(
            {"access-control-allow-origin": echoed}, probe_origin=probe
        )
        assert any(i.kind == "permissive" for i in issues), echoed
