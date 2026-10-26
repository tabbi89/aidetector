"""Reflection-tier leads: which sinks are reached, and how a hit is graded.

The engine only proves a marker came back, never that it executed, so these
assert on the *grading* as much as on the detection — an error-surface
reflection must stay informational, and body sinks must stay behind `mutate`.
"""
from __future__ import annotations

from fastapi.testclient import TestClient

from app.engine.base import (
    HttpProbe,
    TargetOperation,
)
from tests import factories
from tests.vulnapp import vulnapp

OPERATIONS = factories.engine_operations()
CREDS = factories.two_identities()


def _run_all():
    return factories.run_registry(OPERATIONS, credentials=CREDS)


def _run_check(check, operations, *, allow_mutation=False):
    return factories.run_one(
        check, operations, credentials=CREDS, allow_mutation=allow_mutation
    )


class _LiveOob:
    """An active but empty OOB client — enough for the SSRF 'accepted' gate.

    The check only reads ``ctx.oob.active`` to decide whether a silent 200 on a
    url-shaped parameter is reportable; it never polls or builds a callback here.
    """

    active = True


def test_reflected_xss_marker_comes_back():
    xss = [f for f in _run_all() if f.check == "reflected_injection"]
    assert xss
    on_q = [f for f in xss if f.evidence["param"] == "q"]
    assert on_q, "expected a reflected payload on the 'q' query param"
    assert on_q[0].evidence["reflected"] is True
    assert on_q[0].evidence["location"] == "query"


def test_an_escaped_reflection_is_not_a_lead():
    """A target that HTML-escapes what it echoes is behaving correctly: the
    payload's metacharacters came back encoded, so no injection lead fires."""
    import html

    from fastapi import FastAPI
    from fastapi.responses import HTMLResponse
    from fastapi.testclient import TestClient

    from app.engine.checks.injection import ReflectedInjectionCheck

    app = FastAPI()

    @app.get("/search")
    def search(q: str = ""):
        return HTMLResponse(f"<html><body>{html.escape(q)}</body></html>")

    op = TargetOperation(id="op-escaped", method="GET", path="/search",
                         params=[{"name": "q", "in": "query", "required": False}])
    ctx = factories.scan_context(
        [op], credentials=CREDS,
        probe=HttpProbe(TestClient(app), operations=[op]),
    )
    assert ReflectedInjectionCheck().run(ctx) == [], (
        "correctly-escaped output must not be reported as a reflection lead"
    )


def test_ssti_command_and_traversal_reflections_are_not_leads():
    """Those families prove nothing by a bare echo — they are confirmed by the
    arithmetic oracle / OAST, so reflected_injection never flags them, even when
    the target echoes the payload verbatim into its body."""
    from fastapi import FastAPI
    from fastapi.responses import PlainTextResponse
    from fastapi.testclient import TestClient

    from app.engine.checks.injection import ReflectedInjectionCheck

    app = FastAPI()

    @app.get("/echo")
    def echo(x: str = ""):
        # Echoes raw, but as text/plain: {{ }} ;echo ../ are all inert here.
        return PlainTextResponse(f"you said: {x}")

    op = TargetOperation(id="op-echo", method="GET", path="/echo",
                         params=[{"name": "x", "in": "query", "required": False}])
    findings = []
    for seed in range(12):
        ctx = factories.scan_context(
            [op], credentials=CREDS, seed=seed,
            probe=HttpProbe(TestClient(app), operations=[op]),
        )
        findings += ReflectedInjectionCheck().run(ctx)
    families = {f.evidence.get("family") for f in findings}
    assert not (families & {"ssti", "cmdi", "traversal"}), (
        f"SSTI/command/traversal must not be reflection leads; saw {families}"
    )


def test_crlf_is_a_lead_only_when_it_splits_a_response_header():
    """CRLF matters when it injects a response header, not when it echoes into
    the body. The check confirms via the response headers and marks it verified."""
    from fastapi import FastAPI
    from fastapi.responses import JSONResponse
    from fastapi.testclient import TestClient

    from app.engine.checks.injection import ReflectedInjectionCheck
    from app.engine.payloads import Payload, PayloadProvider

    app = FastAPI()

    @app.get("/redirect")
    def redirect(url: str = ""):
        # VULN: percent-decodes the value (as many real sinks do) and copies it
        # into response headers, so an embedded CRLF splits the response.
        from urllib.parse import unquote

        headers: dict[str, str] = {}
        for line in unquote(url).split("\r\n"):
            name, sep, value = line.partition(":")
            if sep and name.strip() and name.strip() != "url":
                headers[name.strip()] = value.strip()
        return JSONResponse({"ok": True}, headers=headers)

    op = TargetOperation(id="op-redirect", method="GET", path="/redirect",
                         params=[{"name": "url", "in": "query", "required": False}])
    ctx = factories.scan_context(
        [op], credentials=CREDS,
        probe=HttpProbe(TestClient(app), operations=[op]),
    )
    # Draw only the CRLF family so the probe lands its header payload here.
    ctx.payload_provider = PayloadProvider(
        [Payload("crlf", "%0d%0aX-aidx{m}:1", True)]
    )
    findings = ReflectedInjectionCheck().run(ctx)
    crlf = [f for f in findings if f.evidence.get("family") == "crlf"]
    assert crlf, "a response-splitting CRLF must be reported"
    assert crlf[0].confidence.value == "verified"


def test_reflected_injection_fuzzes_path_params():
    from app.engine.checks.injection import ReflectedInjectionCheck

    op = TargetOperation(
        id="op-profile",
        method="GET",
        path="/profiles/{handle}",
        params=[{"name": "handle", "in": "path", "required": True}],
    )
    findings = _run_check(ReflectedInjectionCheck(), [op])
    assert findings, "expected a reflected payload via the path segment"
    assert findings[0].evidence["location"] == "path"
    assert findings[0].evidence["param"] == "handle"


def test_reflected_injection_fuzzes_json_body_on_post():
    from app.engine.checks.injection import ReflectedInjectionCheck

    op = TargetOperation(
        id="op-notes",
        method="POST",
        path="/notes",
        params=[{"name": "title", "in": "body", "required": True}],
    )
    findings = _run_check(ReflectedInjectionCheck(), [op], allow_mutation=True)
    assert findings, "expected a reflected payload via the JSON body field"
    assert findings[0].evidence["location"] == "body"
    assert findings[0].evidence["param"] == "title"


def test_missing_endpoint_is_blocked_before_injection():
    """A marker echoed only by a framework's 404 error envelope is not an
    injection lead — it is downgraded to informational error-surface noise."""
    from app.engine.checks.injection import ReflectedInjectionCheck

    op = TargetOperation(
        id="op-missing",
        method="GET",
        path="/does-not-exist/{item}",
        params=[{"name": "item", "in": "path", "required": True}],
    )
    findings = _run_check(ReflectedInjectionCheck(), [op])
    assert findings == [], "a rejected baseline must not become a reflection finding"


def test_reflection_on_success_response_keeps_lead_severity():
    from app.engine.checks.injection import ReflectedInjectionCheck

    op = TargetOperation(
        id="op-profile2",
        method="GET",
        path="/profiles/{handle}",
        params=[{"name": "handle", "in": "path", "required": True}],
    )
    findings = _run_check(ReflectedInjectionCheck(), [op])
    assert findings
    f = findings[0]
    assert f.evidence["status"] < 400
    assert f.evidence["error_surface"] is False
    assert f.severity.value in ("medium", "high")


def test_signature_injection_flags_ldap_error():
    sig = [f for f in _run_all() if f.check == "signature_injection"]
    ldap = [f for f in sig if f.evidence.get("family") == "ldap"]
    assert ldap, "expected an LDAP signature lead"
    # The /lookup endpoint leaks a JNDI error -> the stronger (medium) signal.
    errs = [f for f in ldap if f.evidence.get("error_signature")]
    assert errs, "expected an LDAP error-signature match from /lookup"
    f = errs[0]
    assert f.severity.value == "medium"
    assert f.owasp_id == "CWE-74"
    assert "javax.naming" in f.evidence["response_sample"]


class _CollectorOob:
    """In-memory OAST client: reads the vulnapp's simulated outbound fetches.

    Implements the OobClient interface so the engine's OOB path is exercised
    end-to-end without a real interactsh server or network callback.
    """

    active = True
    _host = "oast.test"

    def __init__(self, outbound):
        self._outbound = outbound

    def payload_url(self, token):
        return f"http://{token}.{self._host}/{token}"

    def payload_domain(self, token):
        return f"{token}.{self._host}"

    def poll(self):
        from app.engine.oob import Interaction

        seen = []
        for url in self._outbound:
            host = url.split("//", 1)[-1].split("/", 1)[0]
            token = host.split(".", 1)[0]
            seen.append(Interaction(protocol="http", token=token,
                                    source_ip="127.0.0.1", raw=url))
        return seen


def test_signature_injection_flags_json_reflection():
    sig = [f for f in _run_all() if f.check == "signature_injection"]
    js = [f for f in sig if f.evidence.get("family") == "json"]
    assert js, "expected a JSON injection reflection lead"
    assert any(f.evidence.get("reflected") for f in js)
    assert all(f.owasp_id == "CWE-74" for f in js)


def test_ssrf_body_sink_requires_mutation():
    """Webhook/callback URLs live in request bodies on real APIs; the SSRF
    check reaches them only under the mutate opt-in (a body write changes state)."""
    from app.engine.checks.ssrf import SsrfCheck

    op = TargetOperation(
        id="op-webhook",
        method="POST",
        path="/webhook",
        params=[{"name": "callback", "in": "body", "required": False}],
    )
    ctx = factories.scan_context([op], credentials=CREDS)
    probe = ctx.probe
    assert SsrfCheck().run(ctx) == []
    assert probe.count == 0  # default scan never writes

    ctx2 = factories.scan_context(
        [op],
        credentials=CREDS,
        probe=HttpProbe(TestClient(vulnapp),
        operations=[op]),
        allow_mutation=True,
        oob=_LiveOob(),
    )
    findings = SsrfCheck().run(ctx2)
    assert findings, "body url-sink must be probed under mutate:true"
    assert findings[0].owasp_id == "API7:2023"
    assert findings[0].evidence["location"] == "body"
    assert findings[0].evidence["param"] == "callback"


# ---- Where a reflection is not evidence ---------------------------------------


def _sig_attempt(payload: str, body: str, status: int):
    from app.engine.base import ProbeResult, TargetOperation
    from app.engine.injection_probe import Attempt
    from app.engine.spec_values import InjectionPoint

    return Attempt(
        op=TargetOperation(id="op", method="GET", path="/x"),
        point=InjectionPoint(name="q", location="query", schema={}),
        index=0,
        needle="aidxdeadbeef",
        value=payload,
        path="/x",
        response=ProbeResult(status=status, headers={}, text=body, elapsed_ms=1.0),
    )


def test_signature_injection_ignores_a_reflection_inside_a_4xx():
    """A validation envelope echoing what it rejected is not a query-layer hit.

    Every typed path parameter in a Pydantic/FastAPI app does this, so reporting
    it produced more findings than the rest of the engine combined.
    """
    from app.engine.checks.signature_injection import SignatureInjectionCheck
    from app.engine.signatures import SIGNATURE_CLASSES

    xpath = next(sc for sc in SIGNATURE_CLASSES if sc.family == "xpath")
    body = '{"detail":[{"msg":"unable to parse","input":"\' or aidxdeadbeef"}]}'
    attempt = _sig_attempt("' or aidxdeadbeef", body, status=422)

    assert SignatureInjectionCheck()._judge(attempt, xpath) is None


def test_signature_injection_keeps_a_reflection_inside_a_5xx():
    """A 5xx means the payload got *through* validation and broke something.

    The cut is at 4xx deliberately: a well-handled rejection is noise, an
    unhandled server error is the opposite.
    """
    from app.engine.checks.signature_injection import SignatureInjectionCheck
    from app.engine.signatures import SIGNATURE_CLASSES

    xpath = next(sc for sc in SIGNATURE_CLASSES if sc.family == "xpath")
    attempt = _sig_attempt("' or aidxdeadbeef", "boom ' or aidxdeadbeef", status=500)

    assert SignatureInjectionCheck()._judge(attempt, xpath) is not None


def test_signature_injection_keeps_an_error_signature_at_any_status():
    """The error signature is the signal this check exists for."""
    from app.engine.checks.signature_injection import SignatureInjectionCheck
    from app.engine.signatures import SIGNATURE_CLASSES

    ldap = next(sc for sc in SIGNATURE_CLASSES if sc.family == "ldap")
    body = "javax.naming.NamingException: Bad search filter"
    hit = SignatureInjectionCheck()._judge(_sig_attempt("aidxdeadbeef)(", body, 400), ldap)

    assert hit is not None
    assert hit.evidence["error_signature"]


def test_an_error_signature_without_a_nearby_marker_is_a_weak_lead():
    """A loose signature can appear for reasons unrelated to the payload; only a
    marker sitting beside it proves the backend answered *this* payload."""
    from app.engine.checks.signature_injection import SignatureInjectionCheck
    from app.engine.signatures import SIGNATURE_CLASSES

    ldap = next(sc for sc in SIGNATURE_CLASSES if sc.family == "ldap")
    body = "javax.naming.NamingException: Bad search filter"
    hit = SignatureInjectionCheck()._judge(_sig_attempt("aidxdeadbeef)(", body, 500), ldap)

    assert hit is not None
    assert hit.severity.value == "low", "no co-located marker → the weaker signal"
    assert hit.evidence["confirmed"] is False


def test_an_error_signature_beside_the_marker_is_the_strong_signal():
    from app.engine.checks.signature_injection import SignatureInjectionCheck
    from app.engine.signatures import SIGNATURE_CLASSES

    ldap = next(sc for sc in SIGNATURE_CLASSES if sc.family == "ldap")
    body = "javax.naming.NamingException: Bad search filter for aidxdeadbeef"
    hit = SignatureInjectionCheck()._judge(_sig_attempt("aidxdeadbeef)(", body, 500), ldap)

    assert hit is not None
    assert hit.severity.value == "medium", "co-located marker → the stronger signal"
    assert hit.evidence["confirmed"] is True


def test_signature_injection_ignores_a_json_validation_envelope():
    """A malformed request body the framework rejects echoes the framework's own
    json error ('Expecting value'), not the backend's interpreter. It must not
    read as a JSON-injection error signature."""
    from app.engine.checks.signature_injection import SignatureInjectionCheck
    from app.engine.signatures import SIGNATURE_CLASSES

    json_class = next(sc for sc in SIGNATURE_CLASSES if sc.family == "json")
    # The shape FastAPI/Pydantic returns for a body it could not parse.
    body = (
        '{"detail":[{"type":"json_invalid","loc":["body"],"msg":"JSON decode error",'
        '"input":{},"ctx":{"error":"Expecting value: line 1 column 1 (char 0)"}}]}'
    )
    attempt = _sig_attempt('aidxdeadbeef","injected":"aidxdeadbeef', body, status=422)

    assert SignatureInjectionCheck()._judge(attempt, json_class) is None


# ---- SSRF: a refusal is not a candidate ---------------------------------------


def test_ssrf_does_not_flag_a_target_that_refuses_the_internal_url():
    """Validating the parameter is the correct behaviour, not a finding.

    The module always claimed to be conservative; the code flagged every
    url-named parameter regardless of what came back.
    """
    from fastapi import FastAPI
    from fastapi.responses import JSONResponse
    from fastapi.testclient import TestClient

    from app.engine.checks.ssrf import SsrfCheck
    from tests import factories

    app = FastAPI()

    @app.get("/fetch")
    def fetch(url: str = ""):
        return JSONResponse({"detail": "url fetching is not supported"}, status_code=400)

    ops = [factories.operation("GET", "/fetch", id="op-fetch",
                               params=[{"name": "url", "in": "query", "required": False}])]
    ctx = factories.scan_context(ops, client=TestClient(app))

    assert factories.run_check(SsrfCheck(), ctx) == []


def test_ssrf_flags_a_target_that_accepts_the_internal_url():
    """Accepted without complaint: a blind SSRF is possible, so it is reported
    only when an out-of-band collector can confirm it."""
    from fastapi import FastAPI
    from fastapi.testclient import TestClient

    from app.engine.checks.ssrf import SsrfCheck
    from tests import factories

    app = FastAPI()

    @app.get("/fetch")
    def fetch(url: str = ""):
        return {"ok": True}

    ops = [factories.operation("GET", "/fetch", id="op-fetch",
                               params=[{"name": "url", "in": "query", "required": False}])]
    ctx = factories.scan_context(ops, client=TestClient(app), oob=_LiveOob())

    findings = factories.run_check(SsrfCheck(), ctx)
    assert len(findings) == 1
    assert findings[0].evidence["reflected"] is False


def test_ssrf_suppresses_accepted_without_a_live_oob_collector():
    """A silent 200 is indistinguishable from a URL-storing endpoint, so without
    an OAST collector the 'accepted' lead is noise and must not be reported."""
    from fastapi import FastAPI
    from fastapi.testclient import TestClient

    from app.engine.checks.ssrf import SsrfCheck
    from tests import factories

    app = FastAPI()

    @app.get("/fetch")
    def fetch(url: str = ""):
        return {"ok": True}

    ops = [factories.operation("GET", "/fetch", id="op-fetch",
                               params=[{"name": "url", "in": "query", "required": False}])]
    ctx = factories.scan_context(ops, client=TestClient(app))  # no OOB

    assert factories.run_check(SsrfCheck(), ctx) == []


def test_ssrf_does_not_treat_a_meta_data_mention_as_reflection():
    """The loose ``meta-data`` substring used to fire on any response that merely
    mentioned the AWS metadata service. Only the exact internal marker counts."""
    from fastapi import FastAPI
    from fastapi.testclient import TestClient

    from app.engine.checks.ssrf import SsrfCheck
    from tests import factories

    app = FastAPI()

    @app.get("/fetch")
    def fetch(url: str = ""):
        return {"help": "see the AWS meta-data service docs"}

    ops = [factories.operation("GET", "/fetch", id="op-fetch",
                               params=[{"name": "url", "in": "query", "required": False}])]
    ctx = factories.scan_context(ops, client=TestClient(app), oob=_LiveOob())

    findings = factories.run_check(SsrfCheck(), ctx)
    assert len(findings) == 1
    assert findings[0].evidence["reflected"] is False, (
        "a 'meta-data' mention is not proof the injected URL was consumed"
    )
