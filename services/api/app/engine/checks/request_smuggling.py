"""HTTP request smuggling / desync (premium): do the front and back end disagree?

A request with ambiguous framing — both Content-Length and Transfer-Encoding — is
read one way by the front-end proxy and another by the origin, so a smuggled
second request hidden inside the first is desynchronised into its own request.
This is the foundation for request-queue poisoning and web-cache poisoning.

The free engine's httpx probe cannot send the exact bytes, so this check opens a
raw socket (like the TLS check) and sends the two classic probes:

- **CL.TE** — the front honours Content-Length, the back Transfer-Encoding.
- **TE.CL** — the front honours Transfer-Encoding, the back Content-Length.

A desync is observed when one connection yields two responses (the smuggled
request was processed). Premium: off unless ``premium: true``.
"""
from __future__ import annotations

import re
import socket
import ssl
from urllib.parse import urlparse

from app.core.target_guard import TargetNotAllowed
from app.domain.enums import Confidence, Severity
from app.engine.base import EngineFinding, ScanContext

#: A response *status line* — ``HTTP/1.x <3-digit code>`` at the start of a line.
#: Matching this (rather than a bare ``HTTP/1.`` substring) keeps a body that
#: merely mentions the token — an error page echoing the request, an HTML page,
#: a redirect chain — from counting as a second response, which would turn a
#: benign reply into a false ``verified``/``high`` smuggling finding.
_STATUS_LINE = re.compile(rb"(?:^|\r\n)HTTP/1\.[01] \d{3}")


def response_count(data: bytes) -> int:
    """How many HTTP/1.x response status lines ``data`` contains."""
    return len(_STATUS_LINE.findall(data))


def is_desync(data: bytes | None) -> bool:
    """A desync is two responses on one connection — the smuggled request ran."""
    return data is not None and response_count(data) >= 2


def cl_te_probe(host: str, path: str) -> bytes:
    """A CL.TE probe: Content-Length framing with a smuggled GET after the chunk end."""
    smuggled = f"GET {path} HTTP/1.1\r\nHost: {host}\r\n\r\n".encode()
    body = b"0\r\n\r\n" + smuggled
    return (
        f"POST {path} HTTP/1.1\r\n"
        f"Host: {host}\r\n"
        f"Content-Length: {len(body)}\r\n"
        "Transfer-Encoding: chunked\r\n"
        "\r\n"
    ).encode() + body


def te_cl_probe(host: str, path: str) -> bytes:
    """A TE.CL probe: chunked framing whose chunk body hides a smuggled GET."""
    smuggled = f"GET {path} HTTP/1.1\r\nHost: {host}\r\n\r\n".encode()
    chunk = f"{len(smuggled):x}\r\n".encode() + smuggled + b"\r\n0\r\n\r\n"
    return (
        f"POST {path} HTTP/1.1\r\n"
        f"Host: {host}\r\n"
        "Content-Length: 4\r\n"
        "Transfer-Encoding: chunked\r\n"
        "\r\n"
    ).encode() + chunk


class RequestSmugglingCheck:
    key = "request_smuggling"
    #: Premium: reserved for the paid tier, off unless ``premium: true``.
    premium = True

    def run(self, ctx: ScanContext) -> list[EngineFinding]:
        if not ctx.premium:
            return []
        parsed = urlparse(ctx.base_url)
        host = parsed.hostname
        if not host:
            return []
        port = parsed.port or (443 if parsed.scheme == "https" else 80)
        path = parsed.path or "/"
        try:
            # A raw socket bypasses the HTTP transport: connect to the run's
            # pinned address, never to a lookup of our own.
            address = ctx.connect_address(host)
        except TargetNotAllowed:
            return []
        findings: list[EngineFinding] = []
        for label, probe in (
            ("cl_te", cl_te_probe(host, path)),
            ("te_cl", te_cl_probe(host, path)),
        ):
            data = self._round_trip(
                host, port, parsed.scheme == "https", probe, address=address
            )
            if is_desync(data):
                findings.append(self._finding(label, host, path))
        return findings

    def _round_trip(
        self,
        host: str,
        port: int,
        use_tls: bool,
        payload: bytes,
        *,
        address: str | None = None,
    ) -> bytes | None:
        try:
            sock = socket.create_connection((address or host, port), timeout=5)
            if use_tls:
                sock = ssl.create_default_context().wrap_socket(sock, server_hostname=host)
            sock.sendall(payload)
            sock.settimeout(2)
            data = b""
            while True:
                chunk = sock.recv(4096)
                if not chunk:
                    break
                data += chunk
        except Exception:  # noqa: BLE001 — an unreachable/refusing target is not a finding
            return None
        finally:
            try:
                sock.close()
            except Exception:  # noqa: BLE001
                pass
        return data

    def _finding(self, label: str, host: str, path: str) -> EngineFinding:
        return EngineFinding(
            check=self.key,
            confidence=Confidence.verified,
            owasp_id="API8:2023",
            severity=Severity.high,
            title=f"HTTP request smuggling ({label.upper()}) on {host}{path}",
            description=(
                f"A {label.upper()} probe produced two responses on one connection, "
                "so the front-end and back-end disagree on request framing. An "
                "attacker can desynchronise the connection to poison the queue or "
                "the shared cache."
            ),
            evidence={"family": label, "host": host, "path": path},
            operation_id=None,
        )
