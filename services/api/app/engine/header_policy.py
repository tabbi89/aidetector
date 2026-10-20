"""Response-header policy — the pure analyser behind the per-endpoint sweep.

Like ``analyze_tls`` in ``engine/checks/tls.py`` this module holds no I/O: it
takes one endpoint's response headers and returns the issues they carry, so the
rules are unit-testable without a target. ``engine/checks/misconfig.py`` is the
thin shell that probes each endpoint and turns these issues into findings.

Findings derived from here are **verified** in the engine's confidence tiers —
the header either is or isn't there, and its value either does or doesn't say
what it should. Nothing here is a reflection lead.

Three independent analyses:

- :func:`analyze_headers` — hardening. Presence *and* value quality, because a
  header that is present but permissive (``X-Frame-Options: ALLOWALL``,
  ``script-src 'unsafe-inline' *``, ``max-age=300``) buys nothing. Also covers
  the CORS response triplet and ``Set-Cookie`` attributes.
- :func:`analyze_disclosure_headers` — leakage. Debug/trace correlation ids and
  server/framework version banners.
- :func:`analyze_redirect_headers` — leakage through a redirect target that
  names an internal host, address or port.

Cookie *values* are never surfaced: only the cookie name and the attributes it
is missing reach a finding.
"""
from __future__ import annotations

import ipaddress
import re
from collections.abc import Mapping
from dataclasses import dataclass
from urllib.parse import urlsplit

from app.domain.enums import Severity


@dataclass(frozen=True)
class HeaderIssue:
    """One problem with one response header on one endpoint.

    ``kind`` drives both grouping and finding titles:
    ``missing`` | ``weak`` | ``permissive`` | ``cookie`` | ``debug`` | ``banner`` |
    ``internal``.
    """

    header: str
    kind: str
    severity: Severity
    detail: str
    observed: str | None = None


# ---- Hardening headers we expect ---------------------------------------------

# The core set. Missing one of these is a medium; a permissive value is too,
# since a header that allows everything is worth no more than its absence.
_CORE = {
    "x-content-type-options": "prevents MIME sniffing",
    "x-frame-options": "prevents clickjacking via framing",
    "content-security-policy": "restricts script/content sources",
    "referrer-policy": "controls referrer leakage",
}

# Browser-hardening headers that matter less for a pure JSON API — reported at
# low severity so the medium finding stays focused on the core set.
#
# Two headers are deliberately absent and must stay absent:
#
# - ``Clear-Site-Data`` is a logout/revocation instruction, not a hardening
#   header. It is correct for a sign-out response and wrong everywhere else, so
#   "missing" is not a defect a per-endpoint sweep can assert.
# - ``Upgrade-Insecure-Requests`` is a *request* header (and a CSP directive);
#   as a response header it has no standard meaning. The equivalent server-side
#   control is HSTS, which the core set already covers.
_HYGIENE = {
    "permissions-policy": "restricts powerful browser features (camera, mic, geolocation)",
    "cross-origin-opener-policy": "isolates the browsing context from cross-origin popups",
    "cross-origin-resource-policy": "restricts which origins may embed this response",
    "cross-origin-embedder-policy": "blocks loading cross-origin resources without opt-in",
    "x-permitted-cross-domain-policies": "denies legacy Flash/PDF cross-domain policy files",
    "document-policy": "disables legacy per-document behaviour such as document.write",
    "integrity-policy": "requires Subresource Integrity, blocking scripts with no valid hash",
    "origin-agent-cluster": "requests an origin-keyed agent cluster, isolating the origin",
    "x-dns-prefetch-control": "stops the browser pre-resolving linked hostnames",
    "x-download-options": "stops legacy IE opening a download in the site's own context",
}

# Values that defeat the point of the header being set at all — the first token
# must be one of these. Headers absent from this table are presence-only,
# because their value space is too open-ended to score generically
# (permissions-policy allow-lists, document-policy / integrity-policy configs).
_HYGIENE_EXPECTED = {
    "cross-origin-opener-policy": ({"same-origin", "same-origin-allow-popups"}, "same-origin"),
    "cross-origin-embedder-policy": ({"require-corp", "credentialless"}, "require-corp"),
    "cross-origin-resource-policy": ({"same-origin", "same-site"}, "same-origin"),
    "x-permitted-cross-domain-policies": ({"none"}, "none"),
    "x-dns-prefetch-control": ({"off"}, "off"),
    "origin-agent-cluster": ({"?1"}, "?1"),
    "x-download-options": ({"noopen"}, "noopen"),
}

_HSTS = "strict-transport-security"
_HSTS_WHY = "enforces HTTPS and blocks downgrade attacks"
_MIN_HSTS_MAX_AGE = 31_536_000  # one year

_XFO_OK = {"deny", "sameorigin"}
_WEAK_REFERRER = {"unsafe-url", "no-referrer-when-downgrade"}


def _norm(headers: Mapping[str, str]) -> dict[str, str]:
    return {k.lower(): (v or "").strip() for k, v in headers.items()}


def _first_token(value: str) -> str:
    """The directive itself, dropping any ``; report-to=…`` / ``, …`` tail."""
    return value.split(";")[0].split(",")[0].strip().lower()


def _parse_csp(value: str) -> dict[str, list[str]]:
    """Split a CSP into ``directive -> source list`` (lowercased)."""
    out: dict[str, list[str]] = {}
    for raw in value.lower().split(";"):
        parts = raw.split()
        if parts:
            out[parts[0]] = parts[1:]
    return out


def _csp_problems(value: str) -> list[str]:
    directives = _parse_csp(value)
    script = directives.get("script-src", directives.get("default-src"))
    problems: list[str] = []
    if script is None:
        problems.append("no default-src or script-src directive")
        return problems
    if "*" in script or "http:" in script or "https:" in script:
        problems.append("script sources allow any origin")
    # ``unsafe-inline`` is only a defect when no nonce/hash/strict-dynamic makes
    # browsers ignore it — a CSP using a nonce or hash is correctly hardened.
    if "'unsafe-inline'" in script and not any(
        source.startswith("'nonce-")
        or source.startswith("'sha")
        or source == "'strict-dynamic'"
        for source in script
    ):
        problems.append("script sources allow 'unsafe-inline'")
    if "'unsafe-eval'" in script:
        problems.append("script sources allow 'unsafe-eval'")
    return problems


def _hsts_problems(value: str) -> list[str]:
    v = value.lower()
    m = re.search(r"max-age\s*=\s*\"?(\d+)", v)
    age = int(m.group(1)) if m else 0
    problems: list[str] = []
    if age < _MIN_HSTS_MAX_AGE:
        problems.append(f"max-age={age} is below the recommended {_MIN_HSTS_MAX_AGE} (1 year)")
    if "includesubdomains" not in v:
        problems.append("no includeSubDomains, so subdomains are still reachable over HTTP")
    return problems


def _normalize_origin(origin: str) -> str:
    """An origin down to its comparable form: scheme and host, lowercased,
    default port stripped, path/query dropped.

    A target that echoes the probe Origin with a trailing slash, different case,
    or an explicit ``:443`` is still reflecting the same origin — an exact string
    compare misses all three.
    """
    parts = urlsplit(origin.strip())
    netloc = parts.netloc.lower()
    if parts.scheme.lower() == "https" and netloc.endswith(":443"):
        netloc = netloc[:-4]
    elif parts.scheme.lower() == "http" and netloc.endswith(":80"):
        netloc = netloc[:-3]
    return f"{parts.scheme.lower()}://{netloc}"


def _cors_issues(h: Mapping[str, str], probe_origin: str | None) -> list[HeaderIssue]:
    """CORS response triplet. The sweep sends a throwaway ``Origin``, so a target
    that echoes it back is reflecting *any* origin, not just an allow-listed one."""
    acao = h.get("access-control-allow-origin")
    if acao is None:
        return []
    credentialed = h.get("access-control-allow-credentials", "").lower() == "true"
    reflected = bool(probe_origin) and _normalize_origin(acao) == _normalize_origin(
        probe_origin or ""
    )

    if reflected:
        return [
            HeaderIssue(
                header="access-control-allow-origin",
                kind="permissive",
                severity=Severity.high if credentialed else Severity.medium,
                detail=(
                    "the target echoes back any Origin it is sent"
                    + (
                        ", together with Access-Control-Allow-Credentials: true — "
                        "any site can read authenticated responses from a victim's browser"
                        if credentialed
                        else ", so its origin allow-list is effectively open"
                    )
                ),
                observed=acao,
            )
        ]
    if acao == "*" and credentialed:
        return [
            HeaderIssue(
                header="access-control-allow-origin",
                kind="permissive",
                severity=Severity.high,
                detail=(
                    "wildcard origin combined with Access-Control-Allow-Credentials: true; "
                    "browsers reject the pair, but non-browser and lenient clients do not"
                ),
                observed="*",
            )
        ]
    if acao == "*":
        return [
            HeaderIssue(
                header="access-control-allow-origin",
                kind="permissive",
                severity=Severity.low,
                detail="any origin may read this response cross-site",
                observed="*",
            )
        ]
    if acao.lower() == "null":
        return [
            HeaderIssue(
                header="access-control-allow-origin",
                kind="permissive",
                severity=Severity.medium,
                detail="the 'null' origin is granted access; sandboxed iframes and "
                "local files present it",
                observed="null",
            )
        ]
    return []


def _cookie_issues(raw: str, *, https: bool) -> list[HeaderIssue]:
    """Session-cookie attributes, one issue per cookie line.

    The probe joins repeated ``Set-Cookie`` headers with a newline (see
    ``engine/base.py:_response_headers``) so an insecure cookie cannot inherit a
    sibling's ``Secure`` flag. Only the cookie *name* is surfaced — never its
    value.
    """
    issues: list[HeaderIssue] = []
    for line in raw.split("\n"):
        name = line.split("=", 1)[0].strip() or "cookie"
        attrs = line.lower()
        missing = []
        if "httponly" not in attrs:
            missing.append("HttpOnly")
        if https and "secure" not in attrs:
            missing.append("Secure")
        if "samesite" not in attrs:
            missing.append("SameSite")
        if not missing:
            continue
        issues.append(
            HeaderIssue(
                header="set-cookie",
                kind="cookie",
                severity=Severity.medium,
                detail=f"cookie '{name}' is set without " + ", ".join(missing),
                observed=name,
            )
        )
    return issues


def analyze_headers(
    headers: Mapping[str, str],
    *,
    https: bool = False,
    probe_origin: str | None = None,
) -> list[HeaderIssue]:
    """Score one endpoint's response headers. Pure — no I/O, no context."""
    h = _norm(headers)
    issues: list[HeaderIssue] = []

    for name, why in _CORE.items():
        value = h.get(name)
        if value is None or value == "":
            issues.append(HeaderIssue(name, "missing", Severity.medium, why))
            continue
        problems = _core_value_problems(name, value)
        if problems:
            issues.append(
                HeaderIssue(name, "weak", Severity.medium, "; ".join(problems), value[:200])
            )

    # HSTS is only meaningful over HTTPS — over plaintext the header is ignored.
    if https:
        value = h.get(_HSTS)
        if not value:
            issues.append(HeaderIssue(_HSTS, "missing", Severity.medium, _HSTS_WHY))
        else:
            problems = _hsts_problems(value)
            if problems:
                issues.append(
                    HeaderIssue(_HSTS, "weak", Severity.medium, "; ".join(problems), value[:200])
                )

    for name, why in _HYGIENE.items():
        value = h.get(name)
        if not value:
            issues.append(HeaderIssue(name, "missing", Severity.low, why))
            continue
        expected = _HYGIENE_EXPECTED.get(name)
        if expected and _first_token(value) not in expected[0]:
            issues.append(
                HeaderIssue(
                    name,
                    "weak",
                    Severity.low,
                    f"expected '{expected[1]}', got '{value[:60]}' — {why}",
                    value[:200],
                )
            )

    issues.extend(_cors_issues(h, probe_origin))
    if h.get("set-cookie"):
        issues.extend(_cookie_issues(h["set-cookie"], https=https))
    return issues


def _core_value_problems(name: str, value: str) -> list[str]:
    v = value.lower()
    if name == "x-content-type-options":
        return [] if v == "nosniff" else [f"expected 'nosniff', got '{value[:60]}'"]
    if name == "x-frame-options":
        return [] if v in _XFO_OK else [f"expected DENY or SAMEORIGIN, got '{value[:60]}'"]
    if name == "content-security-policy":
        return _csp_problems(v)
    if name == "referrer-policy":
        return [f"'{v}' leaks the full URL cross-origin"] if v in _WEAK_REFERRER else []
    return []


# ---- Disclosure headers -------------------------------------------------------

# Deliberate list-style pattern: x-request-id is common and harmless, so it is
# NOT matched — only headers naming debug/trace/span correlation state.
_DEBUG_HEADER = re.compile(r"debug|trace|span", re.I)

# Banners that name the stack. `server` is only a disclosure when it carries a
# version; a bare 'nginx' tells an attacker nothing they can't fingerprint.
_BANNERS = ("server", "x-powered-by", "x-aspnet-version", "x-aspnetmvc-version", "x-generator")
_VERSIONED = re.compile(r"\d+\.\d+")


def analyze_disclosure_headers(headers: Mapping[str, str]) -> list[HeaderIssue]:
    """Debug/trace correlation ids and stack version banners. Pure."""
    h = _norm(headers)
    issues: list[HeaderIssue] = []
    for name, value in h.items():
        if _DEBUG_HEADER.search(name):
            issues.append(
                HeaderIssue(
                    name,
                    "debug",
                    Severity.low,
                    "internal request-correlation state, which belongs in logs",
                    value[:120],
                )
            )
    for name in _BANNERS:
        banner = h.get(name)
        if not banner:
            continue
        if name == "server" and not _VERSIONED.search(banner):
            continue
        issues.append(
            HeaderIssue(
                name,
                "banner",
                Severity.low,
                "names the server/framework (and version), narrowing an attacker's "
                "search for known CVEs",
                banner[:120],
            )
        )
    return issues


# ---- Redirect targets ---------------------------------------------------------

# Headers that hand the client a URL to go to next. A server building an
# absolute one from its *own* view of the request — the upstream Host, the
# backend port, the scheme behind the TLS terminator — writes its internals
# into the response. The classic cases are a framework's trailing-slash
# redirect behind a proxy that does not forward Host, and nginx's
# ``port_in_redirect`` naming the upstream port.
_REDIRECT_HEADERS = ("location", "content-location")

# Name suffixes that only resolve inside a private network.
_INTERNAL_SUFFIXES = (
    ".local", ".internal", ".localdomain", ".lan", ".corp", ".home.arpa", ".svc",
    ".cluster.local", ".intranet",
)

_DEFAULT_PORT = {"http": 80, "https": 443}


def _internal_host(host: str) -> str | None:
    """Why ``host`` names something inside a private network, or ``None``."""
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        if host == "localhost" or host.endswith(".localhost"):
            return "a loopback name"
        if "." not in host:
            return "a single-label internal hostname"
        if host.endswith(_INTERNAL_SUFFIXES):
            return "an internal-only hostname"
        return None
    if ip.is_loopback:
        return "a loopback address"
    if ip.is_link_local:
        return "a link-local address"
    if ip.is_private:
        return "a private-network address"
    return None


def _origin_of(url: str) -> tuple[str, str, int] | None:
    try:
        parts = urlsplit(url)
        port = parts.port
    except ValueError:
        return None
    scheme = parts.scheme.lower()
    host = (parts.hostname or "").rstrip(".")
    if scheme not in _DEFAULT_PORT or not host:
        return None
    return scheme, host, port or _DEFAULT_PORT[scheme]


def analyze_redirect_headers(headers: Mapping[str, str], base_url: str) -> list[HeaderIssue]:
    """Internal hosts, addresses and ports named in a redirect target. Pure.

    A relative target, or one on the scanned origin, discloses nothing; a
    redirect to some other public host (a login page, a CDN) is a destination,
    not a leak. What is reported is a target naming what only the server's side
    of the proxy can see: a private or loopback address, an internal-only
    hostname, or the scanned host on a port the client never used.

    ``observed`` keeps scheme, host and port only — a redirect's path and query
    can carry a session id or an OAuth code, and none of that is the finding.
    """
    base = _origin_of(base_url)
    if base is None:
        return []
    _, base_host, base_port = base
    base_internal = _internal_host(base_host) is not None
    h = _norm(headers)
    issues: list[HeaderIssue] = []
    for name in _REDIRECT_HEADERS:
        target = _origin_of(h.get(name, ""))
        if target is None:
            continue
        scheme, host, port = target
        if host == base_host:
            # The same port, or a scheme switch onto that scheme's standard
            # port, is the public origin — only an unexpected port is internal.
            if port in (base_port, _DEFAULT_PORT[scheme]):
                continue
            why = f"the scanned host on port {port}, which the client never used"
        elif base_internal:
            # Scanning inside the network: a sibling host is reachable from the
            # client's side too, so naming it gives nothing away.
            continue
        else:
            reason = _internal_host(host)
            if reason is None:
                continue
            why = f"{reason} the client cannot reach"
        shown = f"[{host}]" if ":" in host else host
        issues.append(
            HeaderIssue(
                name,
                "internal",
                Severity.low,
                f"the redirect target names {why} — the server is building URLs "
                "from its own side of the proxy",
                f"{scheme}://{shown}:{port}",
            )
        )
    return issues
