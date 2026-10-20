"""TLS / certificate hygiene — the one check that inspects the transport, not a
response body.

Unlike everything else in the engine, findings here are **verified**: they come
from the actual certificate the target presents and the parameters it negotiates,
not from a reflected marker. It complements the HSTS header check in
``misconfig.py`` and fills the gap left by the runner deliberately using
``httpx(verify=False)`` (so scan targets with self-signed certs still work),
which otherwise hides every certificate problem.

Mechanics: one TLS handshake to the target host to read the leaf certificate and
the negotiated protocol/cipher, plus a best-effort second handshake capped at
TLS 1.1 to detect deprecated-protocol support. These are direct sockets, not
HTTP requests, so they are outside the ``HttpProbe`` request budget (a handful of
connections, not a fuzzing loop).

Over HTTPS it also sends **one** plain ``http://`` GET, with no credentials, to
the same host on port 80 — the first swept route, so the answer can be compared
with the one the HTTPS endpoint gave. That request is an ordinary ``HttpProbe``
call: budget-counted, traced, and validated by the target guard like any other.
A refused connection, a 426, or a redirect to ``https://`` is the right answer;
``cleartext_exposure`` names the others.

``analyze_tls`` and ``cleartext_exposure`` are pure and unit-tested; ``run`` is
the thin shell around them and degrades to no findings on any connection error.
"""
from __future__ import annotations

import logging
import socket
import ssl
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any
from urllib.parse import urlsplit, urlunsplit

from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import dsa, rsa
from cryptography.x509.oid import NameOID

from app.core.target_guard import TargetNotAllowed
from app.domain.enums import Confidence, Severity
from app.engine.base import EngineFinding, ScanContext
from app.engine.checks.misconfig import sweep_headers

log = logging.getLogger("aidetector.tls")

_WEAK_SIG_HASHES = {"md5", "sha1"}
_WEAK_CIPHER_TOKENS = ("RC4", "3DES", "DES", "NULL", "EXPORT", "MD5", "ANON")
_EXPIRY_WARN_DAYS = 15


def _host_matches(host: str, names: list[str]) -> bool:
    """RFC-6125-ish hostname match, including a single leftmost wildcard label."""
    host = host.lower().rstrip(".")
    for raw in names:
        name = raw.lower().rstrip(".")
        if name == host:
            return True
        if name.startswith("*."):
            suffix = name[1:]  # ".example.com"
            if host.endswith(suffix) and host[: -len(suffix)].count(".") == 0:
                return True
    return False


def _cert_names(cert: x509.Certificate) -> list[str]:
    names: list[str] = []
    try:
        san = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
        names.extend(san.value.get_values_for_type(x509.DNSName))
    except x509.ExtensionNotFound:
        pass
    if not names:
        cn = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
        names.extend(a.value for a in cn if isinstance(a.value, str))
    return names


def _f(severity: Severity, title: str, description: str, evidence: dict) -> EngineFinding:
    return EngineFinding(
        check="tls_config",
        confidence=Confidence.verified,
        owasp_id="API8:2023",
        severity=severity,
        title=title,
        description=description,
        evidence=evidence,
    )


@dataclass(frozen=True)
class TlsFacts:
    """Everything the rules below judge, gathered once per host.

    ``names`` is precomputed because two rules need it and reading the SAN
    extension is not free. ``ev`` is the evidence every finding carries, which
    each rule extends with what it looked at.
    """

    host: str
    cert: Any
    negotiated_protocol: str | None
    cipher_name: str | None
    cipher_bits: int | None
    supports_deprecated_tls: bool
    now: datetime
    names: list[str]

    @property
    def ev(self) -> dict[str, Any]:
        return {
            "host": self.host,
            "protocol": self.negotiated_protocol,
            "cipher": self.cipher_name,
        }


#: A rule looks at the facts and either has something to say or does not.
Rule = Callable[[TlsFacts], EngineFinding | None]


def _expired(f: TlsFacts) -> EngineFinding | None:
    not_after = f.cert.not_valid_after_utc
    if not_after >= f.now:
        return None
    return _f(
        Severity.high,
        f"Expired TLS certificate for {f.host}",
        f"The certificate expired on {not_after.isoformat()}.",
        {**f.ev, "not_valid_after": not_after.isoformat()},
    )


def _expiring_soon(f: TlsFacts) -> EngineFinding | None:
    # Was the ``elif`` arm of the expiry check. As a separate rule it must
    # re-assert "not already expired" itself, or an expired certificate would
    # produce both findings.
    not_after = f.cert.not_valid_after_utc
    if not_after < f.now:
        return None
    remaining = (not_after - f.now).days
    if remaining > _EXPIRY_WARN_DAYS:
        return None
    return _f(
        Severity.low,
        f"TLS certificate for {f.host} expires soon",
        f"The certificate expires on {not_after.isoformat()} ({remaining} days).",
        {**f.ev, "not_valid_after": not_after.isoformat()},
    )


def _not_yet_valid(f: TlsFacts) -> EngineFinding | None:
    not_before = f.cert.not_valid_before_utc
    if not_before <= f.now:
        return None
    return _f(
        Severity.medium,
        f"TLS certificate for {f.host} is not yet valid",
        f"The certificate is not valid before {not_before.isoformat()}.",
        {**f.ev, "not_valid_before": not_before.isoformat()},
    )


def _self_signed(f: TlsFacts) -> EngineFinding | None:
    if f.cert.issuer != f.cert.subject:
        return None
    return _f(
        Severity.medium,
        f"Self-signed TLS certificate for {f.host}",
        "The certificate's issuer equals its subject — it is self-signed and "
        "not anchored to a trusted CA.",
        {**f.ev, "issuer": f.cert.issuer.rfc4514_string()},
    )


def _hostname_mismatch(f: TlsFacts) -> EngineFinding | None:
    if not f.names or _host_matches(f.host, f.names):
        return None
    return _f(
        Severity.high,
        f"TLS certificate does not match host {f.host}",
        f"None of the certificate names {f.names} match the target host.",
        {**f.ev, "cert_names": f.names},
    )


def _wildcard(f: TlsFacts) -> EngineFinding | None:
    # Wildcard hygiene: a wildcard cert legitimately matches subdomains, but one
    # compromised key (or one mis-issued subdomain) then exposes every host under
    # the domain — worth a low flag even when the match itself is valid.
    wildcards = sorted({n for n in f.names if n.startswith("*.")})
    if not wildcards:
        return None
    return _f(
        Severity.low,
        f"Wildcard TLS certificate presented by {f.host}",
        f"The certificate is a wildcard ({', '.join(wildcards)}). Prefer "
        "per-host certificates or short-lived automation: a single "
        "compromised key covers every subdomain.",
        {**f.ev, "wildcards": wildcards, "cert_names": f.names},
    )


def _weak_signature(f: TlsFacts) -> EngineFinding | None:
    sig = getattr(f.cert.signature_hash_algorithm, "name", "") or ""
    if sig.lower() not in _WEAK_SIG_HASHES:
        return None
    return _f(
        Severity.medium,
        f"Weak certificate signature algorithm ({sig}) for {f.host}",
        f"The certificate is signed with {sig}, which is cryptographically weak.",
        {**f.ev, "signature_hash": sig},
    )


def _weak_key(f: TlsFacts) -> EngineFinding | None:
    pub = f.cert.public_key()
    key_size = getattr(pub, "key_size", None)
    if not isinstance(pub, rsa.RSAPublicKey | dsa.DSAPublicKey):
        return None
    if not key_size or key_size >= 2048:
        return None
    return _f(
        Severity.medium,
        f"Weak public key ({key_size}-bit) for {f.host}",
        f"The certificate's {key_size}-bit key is below the 2048-bit minimum.",
        {**f.ev, "key_size": key_size},
    )


def _weak_cipher(f: TlsFacts) -> EngineFinding | None:
    upper = (f.cipher_name or "").upper()
    weak = any(t in upper for t in _WEAK_CIPHER_TOKENS)
    if not weak and not (f.cipher_bits is not None and f.cipher_bits < 128):
        return None
    return _f(
        Severity.medium,
        f"Weak TLS cipher negotiated with {f.host}",
        f"The connection negotiated {f.cipher_name} ({f.cipher_bits}-bit).",
        {**f.ev, "cipher_bits": f.cipher_bits},
    )


def _deprecated_protocol(f: TlsFacts) -> EngineFinding | None:
    proto = f.negotiated_protocol or ""
    if proto not in ("SSLv3", "TLSv1", "TLSv1.1") and not f.supports_deprecated_tls:
        return None
    return _f(
        Severity.medium,
        f"Deprecated TLS protocol supported by {f.host}",
        "The server negotiated or accepts TLS 1.1 or older, which is deprecated.",
        {**f.ev, "supports_deprecated_tls": f.supports_deprecated_tls},
    )


#: Evaluation order is report order — the order the single fused function used.
#: Every rule runs; this is not a chain that stops at the first match.
RULES: tuple[Rule, ...] = (
    _expired,
    _expiring_soon,
    _not_yet_valid,
    _self_signed,
    _hostname_mismatch,
    _wildcard,
    _weak_signature,
    _weak_key,
    _weak_cipher,
    _deprecated_protocol,
)


def analyze_tls(
    host: str,
    cert: x509.Certificate,
    *,
    negotiated_protocol: str | None = None,
    cipher_name: str | None = None,
    cipher_bits: int | None = None,
    supports_deprecated_tls: bool = False,
    now: datetime | None = None,
) -> list[EngineFinding]:
    """Turn a presented certificate + negotiated parameters into findings. Pure.

    Nine independent rules over one immutable fact set (:data:`RULES`). They were
    one 100-line function with the highest cyclomatic complexity in the codebase;
    each rule is now testable against only the facts it reads, and a tenth is an
    entry in the tuple rather than an edit to a branch pile.
    """
    facts = TlsFacts(
        host=host,
        cert=cert,
        negotiated_protocol=negotiated_protocol,
        cipher_name=cipher_name,
        cipher_bits=cipher_bits,
        supports_deprecated_tls=supports_deprecated_tls,
        now=now or datetime.now(UTC),
        names=_cert_names(cert),
    )
    return [found for found in (rule(facts) for rule in RULES) if found is not None]


def cleartext_exposure(status: int, location: str | None, https_status: int | None) -> str | None:
    """Why an answer on ``http://`` is a finding, or ``None`` when it refused properly.

    Refusing (a closed port, never reaching this), a 426, or a redirect onto
    ``https://`` all keep the API off cleartext. A 2xx means it served over
    HTTP. So does answering with exactly the status the HTTPS endpoint gave —
    a 401 from the API's own auth layer proves the API is listening on port 80,
    where a default vhost's 404 proves nothing. Pure.
    """
    if status == 426:
        return None
    if 300 <= status < 400:
        if urlsplit(location or "").scheme.lower() == "https":
            return None
        return f"answered {status} with a redirect that stays on cleartext"
    if 200 <= status < 300:
        return f"served a {status} response over cleartext HTTP"
    if https_status is not None and status == https_status:
        return (
            f"answered {status}, the same status as over HTTPS, so the API itself "
            "is listening on port 80"
        )
    return None


_CLEARTEXT_REMEDIATION = (
    "Stop serving the API on port 80 for {host}: close it, or answer every request "
    "there with 426 Upgrade Required or a redirect to https:// that carries no API "
    "behaviour. For an API, refusing beats redirecting — a client that sent a "
    "token to http:// has already leaked it on that first request, and a redirect "
    "only hides the misconfigured client. Keep HSTS on the HTTPS responses so "
    "browsers never try HTTP at all."
)


class TlsConfigCheck:
    key = "tls_config"

    def _cleartext(self, ctx: ScanContext, host: str, base_path: str) -> list[EngineFinding]:
        """One credential-free GET to the ``http://`` twin of the first swept route."""
        seed = next((s for s in sweep_headers(ctx) if s.method == "GET"), None)
        path = seed.path if seed else "/"
        netloc = f"[{host}]" if ":" in host else host
        url = urlunsplit(
            ("http", netloc, base_path.rstrip("/") + "/" + path.lstrip("/"), "", "")
        )
        try:
            # No credentials: this request crosses the network unencrypted, and
            # without an auth header the probe's re-auth retry cannot add one.
            r = ctx.probe.send("GET", url, headers={})
        except Exception:  # noqa: BLE001 — refused/unreachable is the right answer
            return []
        if r is None:
            return []
        location = next((v for k, v in r.headers.items() if k.lower() == "location"), None)
        reason = cleartext_exposure(r.status, location, seed.status if seed else None)
        if reason is None:
            return []
        finding = _f(
            Severity.medium,
            f"API reachable over cleartext HTTP ({host})",
            f"The HTTPS API is also reachable over plain HTTP: GET {url} {reason}. "
            "Any client configured with http:// sends its credentials and data "
            "unencrypted, and nothing tells it so.",
            {"host": host, "scheme": "http", "probed": url, "status": r.status},
        )
        finding.remediation = _CLEARTEXT_REMEDIATION.format(host=host)
        return [finding]

    def run(self, ctx: ScanContext) -> list[EngineFinding]:
        parts = urlsplit(ctx.base_url)
        host = parts.hostname
        if not host:
            return []
        if parts.scheme != "https":
            return [_f(
                Severity.medium, f"Target served over plaintext HTTP ({host})",
                "The target base URL uses http://, so traffic and credentials are "
                "unencrypted in transit.",
                {"host": host, "scheme": parts.scheme},
            )]
        port = parts.port or 443
        # Only on the standard port: for https://host:8443 there is no telling
        # which port its cleartext twin would be on.
        findings = self._cleartext(ctx, host, parts.path) if port == 443 else []

        try:
            # Raw sockets bypass the HTTP transport: use the run's pinned address.
            address = ctx.connect_address(host)
        except TargetNotAllowed:
            return findings
        der, proto, cipher = self._handshake(host, port, address)
        if der is None:
            return findings
        try:
            cert = x509.load_der_x509_certificate(der)
        except Exception:  # noqa: BLE001 — malformed cert; nothing to analyse
            log.warning("could not parse certificate for %s", host, exc_info=True)
            return findings

        cipher_name = cipher[0] if cipher else None
        cipher_bits = cipher[2] if cipher else None
        return findings + analyze_tls(
            host,
            cert,
            negotiated_protocol=proto,
            cipher_name=cipher_name,
            cipher_bits=cipher_bits,
            supports_deprecated_tls=self._accepts_deprecated_tls(host, port, address),
        )

    def _handshake(self, host: str, port: int, address: str | None = None):
        """Return (der_cert_bytes, protocol, cipher_tuple) or (None, None, None)."""
        ctx = ssl.create_default_context()
        ctx.check_hostname = False  # we analyse mismatch ourselves, incl. self-signed
        ctx.verify_mode = ssl.CERT_NONE
        try:
            with socket.create_connection((address or host, port), timeout=10) as sock:
                with ctx.wrap_socket(sock, server_hostname=host) as tls:
                    return tls.getpeercert(binary_form=True), tls.version(), tls.cipher()
        except Exception:  # noqa: BLE001 — unreachable/handshake failure → skip
            log.warning("TLS handshake to %s:%s failed", host, port, exc_info=True)
            return None, None, None

    def _accepts_deprecated_tls(self, host: str, port: int, address: str | None = None) -> bool:
        """Best-effort probe: does the server complete a handshake capped at TLS 1.1?"""
        try:
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            ctx.minimum_version = ssl.TLSVersion.TLSv1
            ctx.maximum_version = ssl.TLSVersion.TLSv1_1
            with socket.create_connection((address or host, port), timeout=10) as sock:
                with ctx.wrap_socket(sock, server_hostname=host):
                    return True
        except Exception:  # noqa: BLE001 — rejected old TLS (good) or can't probe
            return False
