"""What a target gives away about its transport: internal redirect targets and a
cleartext twin of an HTTPS API.

Both rules are pure and tested directly; the check-level tests bind a small
in-process app through a ``TestClient`` that does *not* follow redirects — the
production transport never does (``transport.py``), and a redirect that was
followed has no ``Location`` left to read.
"""
from __future__ import annotations

import pytest
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse, RedirectResponse, Response
from fastapi.testclient import TestClient

from app.engine.base import TargetOperation
from app.engine.checks.misconfig import InfoDisclosureCheck
from app.engine.checks.tls import TlsConfigCheck, cleartext_exposure
from app.engine.header_policy import analyze_redirect_headers
from tests import factories

PUBLIC = "https://api.example.test"
ITEMS = TargetOperation(id="op-items", method="GET", path="/items", params=[])


def _ctx(app: FastAPI, base_url: str = PUBLIC):
    ctx = factories.scan_context([ITEMS], client=TestClient(app, follow_redirects=False))
    ctx.base_url = base_url
    return ctx


# ---- analyze_redirect_headers --------------------------------------------------


@pytest.mark.parametrize(
    "location",
    [
        "/items/",  # relative: the client stays on the origin it used
        "https://api.example.test/items/",  # same origin
        "https://api.example.test:443/items/",  # same origin, explicit port
        "http://api.example.test/items/",  # scheme switch on the standard port
        "https://login.example.com/authorize?code=x",  # a public destination
        "not a url",
    ],
)
def test_redirect_to_the_public_origin_or_elsewhere_is_quiet(location: str):
    assert analyze_redirect_headers({"Location": location}, PUBLIC) == []


@pytest.mark.parametrize(
    ("location", "observed"),
    [
        ("http://10.0.0.7:8080/items/?session=abc", "http://10.0.0.7:8080"),
        ("http://127.0.0.1/items/", "http://127.0.0.1:80"),
        ("http://backend:8000/items/", "http://backend:8000"),
        ("http://orders.svc.cluster.local/items/", "http://orders.svc.cluster.local:80"),
        ("https://api.example.test:4200/items/", "https://api.example.test:4200"),
        ("http://[fd00::1]:9000/items/", "http://[fd00::1]:9000"),
    ],
)
def test_redirect_naming_an_internal_host_or_port_is_reported(location: str, observed: str):
    issues = analyze_redirect_headers({"Location": location}, PUBLIC)
    assert len(issues) == 1
    issue = issues[0]
    assert (issue.header, issue.kind, issue.severity.value) == ("location", "internal", "low")
    # Scheme, host and port only: a redirect's path and query can carry a
    # session id or an OAuth code, and none of that belongs in a finding.
    assert issue.observed == observed


def test_content_location_is_read_too():
    issues = analyze_redirect_headers({"Content-Location": "http://10.1.2.3/x"}, PUBLIC)
    assert [i.header for i in issues] == ["content-location"]


def test_sibling_hosts_are_not_a_leak_when_scanning_inside_the_network():
    base = "http://10.0.0.5:8000"
    assert analyze_redirect_headers({"Location": "http://10.0.0.6:8000/x"}, base) == []
    # The scanned host on a port the client never used is still one.
    assert analyze_redirect_headers({"Location": "http://10.0.0.5:9000/x"}, base)


# ---- info_disclosure over a live sweep ------------------------------------------


def _slash_redirect_app() -> FastAPI:
    app = FastAPI()

    @app.get("/items")
    def items():
        return [{"id": 1}]

    @app.get("/items/")
    def items_slash():
        # A framework's trailing-slash redirect built from the upstream Host.
        return RedirectResponse("http://backend:8000/items?page=2", status_code=307)

    return app


def test_trailing_slash_redirect_to_an_upstream_host_is_reported():
    ctx = _ctx(_slash_redirect_app())
    findings = InfoDisclosureCheck().run(ctx)

    assert len(findings) == 1
    f = findings[0]
    assert f.check == "info_disclosure"
    assert f.confidence.value == "verified"
    assert f.title.startswith("Internal address disclosed in redirect target")
    assert f.evidence["headers"] == {"location": "http://backend:8000"}
    assert f.evidence["affected_endpoints"] == ["GET /items/"]
    assert "page=2" not in f.description
    assert "X-Forwarded" in f.remediation
    # The sweep's one request, plus exactly one for the toggled slash.
    assert ctx.probe.count == 2


def test_redirect_to_the_same_origin_stays_quiet():
    app = FastAPI()

    @app.get("/items")
    def items():
        return [{"id": 1}]

    @app.get("/items/")
    def items_slash():
        return RedirectResponse(f"{PUBLIC}/items", status_code=307)

    assert InfoDisclosureCheck().run(_ctx(app)) == []


# ---- cleartext_exposure ---------------------------------------------------------


@pytest.mark.parametrize(
    ("status", "location", "https_status"),
    [
        (426, None, 200),
        (301, "https://api.example.test/items", 200),
        (308, "HTTPS://api.example.test/items", 200),
        (404, None, 200),  # a default vhost on port 80, not the API
        (400, None, 401),
    ],
)
def test_refused_or_upgraded_cleartext_is_quiet(status, location, https_status):
    assert cleartext_exposure(status, location, https_status) is None


@pytest.mark.parametrize(
    ("status", "location", "https_status"),
    [
        (200, None, 200),
        (204, None, None),
        (301, "/items/", 200),  # redirects, but stays on http://
        (302, "http://api.example.test/login", 200),
        (401, None, 401),  # the API's own auth layer answered on port 80
    ],
)
def test_serving_on_cleartext_is_reported(status, location, https_status):
    assert cleartext_exposure(status, location, https_status)


# ---- tls_config over a live probe -----------------------------------------------


def _twin_app(*, cleartext: Response | None) -> tuple[FastAPI, list[dict[str, str]]]:
    """The sweep reaches it as ``testserver``; the cleartext probe as the base
    host. ``cleartext`` is what the http:// twin answers (None → serve the API)."""
    app = FastAPI()
    seen: list[dict[str, str]] = []

    @app.get("/items")
    def items(request: Request):
        if request.url.hostname == "api.example.test":
            seen.append(dict(request.headers))
            if cleartext is not None:
                return cleartext
        return JSONResponse([{"id": 1}])

    return app, seen


@pytest.fixture
def no_handshake(monkeypatch):
    monkeypatch.setattr(TlsConfigCheck, "_handshake", lambda self, h, p, a=None: (None, None, None))


def test_https_api_also_served_over_cleartext_is_reported(no_handshake):
    app, seen = _twin_app(cleartext=None)
    findings = TlsConfigCheck().run(_ctx(app))

    assert len(findings) == 1
    f = findings[0]
    assert f.check == "tls_config"
    assert f.severity.value == "medium"
    assert f.title == "API reachable over cleartext HTTP (api.example.test)"
    assert f.evidence["probed"] == "http://api.example.test/items"
    assert "port 80" in f.remediation
    # The request crossed the network unencrypted: it must not carry a credential.
    assert len(seen) == 1
    assert "authorization" not in seen[0]


def test_cleartext_upgrade_required_is_quiet(no_handshake):
    app, seen = _twin_app(cleartext=Response(status_code=426))
    assert TlsConfigCheck().run(_ctx(app)) == []
    assert len(seen) == 1


def test_non_standard_https_port_is_not_probed_over_cleartext(no_handshake):
    app, seen = _twin_app(cleartext=None)
    assert TlsConfigCheck().run(_ctx(app, "https://api.example.test:8443")) == []
    assert seen == []
