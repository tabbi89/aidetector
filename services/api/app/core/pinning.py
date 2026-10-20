"""Connect to the address the egress policy judged, not to a second lookup.

``check_target_allowed`` resolves a host and judges the answer, then the HTTP
client resolves it again to connect. Between the two, DNS (a short TTL, a
rebinding resolver) or an edited ``/etc/hosts`` can answer differently: the
guard sees ``127.0.0.1`` and the scan reaches a public machine. A pinned
transport closes that gap by resolving each host once, judging *those*
addresses, and connecting to the address it judged for the rest of the run.

The request keeps its original ``Host`` header and TLS SNI, so the target sees
exactly the request it would have seen without pinning; only the socket's
destination is fixed. ``response.request`` is restored to the original, so
nothing downstream sees an IP where it expects a host name.
"""
from __future__ import annotations

import threading
from collections.abc import Iterable
from ipaddress import IPv4Address, IPv6Address, ip_address

import httpx

from app.core.target_guard import (
    TargetNotAllowed,
    check_resolved,
    is_public_ip,
    resolve_host,
)

_IPAddr = IPv4Address | IPv6Address


class PinPolicy:
    """Which address each host connects to, decided once per host per run.

    ``pins`` seeds hosts whose address was already judged (the scan target,
    cleared by ``app/scans/domains``). ``private_only`` names hosts that were
    exempt from ownership verification *because* they are private: if one of
    them later resolves to a public address it is refused, since that public
    machine was never verified.
    """

    def __init__(
        self,
        *,
        allow_private: bool = True,
        allowlist: Iterable[str] = (),
        pins: dict[str, str] | None = None,
        private_only: Iterable[str] = (),
    ) -> None:
        self._allow_private = allow_private
        self._allowlist = list(allowlist)
        self._pins = {_norm(h): a for h, a in (pins or {}).items()}
        self._private_only = {_norm(h) for h in private_only}
        self._lock = threading.Lock()

    def address_for(self, host: str) -> str:
        """The address to connect to for ``host``; raises when it is out of policy."""
        host = _norm(host)
        literal = _literal(host)
        if literal is not None:
            self._judge(host, [literal])
            return host
        with self._lock:
            pinned = self._pins.get(host)
        if pinned is not None:
            return pinned
        resolved = resolve_host(host)
        if not resolved:
            raise TargetNotAllowed(f"host '{host}' does not resolve")
        self._judge(host, resolved)
        with self._lock:
            # Another request may have pinned it meanwhile; the first answer wins.
            return self._pins.setdefault(host, str(resolved[0]))

    def drift(self, host: str) -> str | None:
        """Why a fresh lookup of ``host`` disagrees with this run's pin, or None.

        For passes that resolve the target themselves (the adjunct tools): they
        cannot be pinned, so they run only while DNS still gives the answer the
        clearance judged.
        """
        host = _norm(host)
        with self._lock:
            pinned = self._pins.get(host)
        resolved = resolve_host(host)
        if host in self._private_only:
            public = next((ip for ip in resolved if is_public_ip(ip)), None)
            if public is not None:
                return (
                    f"'{host}' was cleared as a private target but now resolves to a "
                    f"public address ({public})"
                )
        if pinned is not None and resolved and pinned not in {str(ip) for ip in resolved}:
            return (
                f"'{host}' now resolves to {', '.join(map(str, resolved))}, not the "
                f"address this run checked ({pinned})"
            )
        return None

    def _judge(self, host: str, resolved: list[_IPAddr]) -> None:
        check_resolved(
            host, resolved, allow_private=self._allow_private, allowlist=self._allowlist
        )
        if host in self._private_only:
            public = next((ip for ip in resolved if is_public_ip(ip)), None)
            if public is not None:
                raise TargetNotAllowed(
                    f"host '{host}' was cleared as a private target but now resolves "
                    f"to a public address ({public}); verify ownership to scan it"
                )


def canonical_host(host: str) -> str:
    """One spelling of a host for every comparison: ASCII, lower-case, bare.

    Unicode names are IDNA-encoded the way httpx encodes them for the socket,
    so a pin keyed on ``bücher.example`` and a request for
    ``xn--bcher-kva.example`` are the same host. Two spellings of one host
    would let a lookup miss its pin and resolve afresh.
    """
    host = host.strip().strip("[]").rstrip(".").lower()
    if host and not host.isascii():
        host = httpx.URL(f"http://{host}/").raw_host.decode("ascii")
    return host


def url_host(url: str) -> str:
    """The canonical host of ``url``, or ``""`` when it has none."""
    try:
        raw = httpx.URL(url.strip()).raw_host.decode("ascii")
    except (httpx.InvalidURL, UnicodeError):
        return ""
    return canonical_host(raw)


_norm = canonical_host


def _literal(host: str) -> _IPAddr | None:
    try:
        return ip_address(host.split("%", 1)[0])
    except ValueError:
        return None


def pinned_request(request: httpx.Request, address: str) -> httpx.Request:
    """``request`` aimed at ``address``, keeping its Host header and TLS SNI."""
    # The encoded (IDNA) form: what DNS and SNI see for a unicode name.
    host = request.url.raw_host.decode("ascii")
    if address == host:
        return request
    extensions = dict(request.extensions)
    if request.url.scheme == "https":
        extensions.setdefault("sni_hostname", host)
    # The Host header was set from the original URL when the request was built
    # and is carried over unchanged, so virtual hosting still routes it.
    return httpx.Request(
        request.method,
        request.url.copy_with(host=address),
        headers=request.headers,
        stream=request.stream,
        extensions=extensions,
    )


class PinnedAsyncTransport(httpx.AsyncBaseTransport):
    """An async transport that connects only to addresses ``policy`` pinned."""

    def __init__(
        self, policy: PinPolicy, inner: httpx.AsyncBaseTransport | None = None
    ) -> None:
        self._policy = policy
        # The client's own ``verify`` is ignored once a transport is supplied,
        # so the lab/self-signed TLS posture is set here.
        self._inner = inner or httpx.AsyncHTTPTransport(verify=False)

    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        address = self._policy.address_for(request.url.raw_host.decode("ascii"))
        response = await self._inner.handle_async_request(pinned_request(request, address))
        response.request = request
        return response

    async def aclose(self) -> None:
        await self._inner.aclose()


class PinnedTransport(httpx.BaseTransport):
    """The synchronous twin, for one-off fetches such as the ownership token."""

    def __init__(self, policy: PinPolicy, inner: httpx.BaseTransport | None = None) -> None:
        self._policy = policy
        self._inner = inner or httpx.HTTPTransport(verify=False)

    def handle_request(self, request: httpx.Request) -> httpx.Response:
        address = self._policy.address_for(request.url.raw_host.decode("ascii"))
        response = self._inner.handle_request(pinned_request(request, address))
        response.request = request
        return response

    def close(self) -> None:
        self._inner.close()
