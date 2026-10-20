"""Egress/SSRF guard for scan targets.

An active scanner that will fire real payloads at whatever URL it is handed is a
server-side request forgery primitive if that URL is unvalidated. This module is
the gate: it is enforced at run time (``POST /scans/{id}/run``), the moment the
worker would start reaching out.

Policy, in order:

1. **Scheme** — only ``http`` / ``https``. ``file://``, ``gopher://``, etc. are
   always rejected.
2. **Cloud metadata / link-local** — the metadata addresses in
   :data:`_METADATA_NETS` (``169.254.0.0/16`` and IPv6 link-local, AWS's IPv6
   IMDS, Alibaba's and Azure's host endpoints) are **always** blocked, even when
   private hosts are allowed. There is no legitimate reason to point this tool at
   them. An IPv6 address that *embeds* an IPv4 one (``::ffff:169.254.169.254``,
   6to4, Teredo, NAT64) is judged by the address it embeds as well as by itself —
   otherwise one bracketed literal walks straight past an IPv4-only rule.
3. **Allowlist** — when ``target_allowlist`` is configured it is authoritative:
   the host must match (exact or ``.suffix`` domain) or the target is rejected.
   A match may permit a private target, but never cloud metadata.
4. **Private ranges** — RFC-1918 / loopback / reserved / multicast are allowed
   only when ``target_allow_private`` is set (the local-lab default). When it is
   not, the host must resolve and every resolved address must be global.

Kept import-light and side-effect-free apart from a bounded DNS lookup, so it is
unit-testable without a network for the literal-IP and scheme paths.
"""
from __future__ import annotations

import socket
from ipaddress import IPv4Address, IPv6Address, ip_address, ip_network
from urllib.parse import urlparse

_IPAddr = IPv4Address | IPv6Address

_ALLOWED_SCHEMES = ("http", "https")
_METADATA_NETS = (
    ip_network("169.254.0.0/16"),      # AWS/GCP/Azure/OCI metadata; IPv4 link-local
    ip_network("fe80::/10"),           # IPv6 link-local
    ip_network("fd00:ec2::254/128"),   # AWS IMDS over IPv6
    ip_network("100.100.100.200/32"),  # Alibaba Cloud metadata
    ip_network("168.63.129.16/32"),    # Azure WireServer
)
_METADATA_HOSTNAMES = {
    "metadata.google.internal",
    "metadata",
    "instance-data",
    "instance-data.ec2.internal",
}
# RFC 6052 well-known NAT64 prefix: the low 32 bits are an IPv4 address.
_NAT64_NET = ip_network("64:ff9b::/96")


class TargetNotAllowed(ValueError):
    """Raised when a target URL is refused by the egress policy."""


def _host_matches_allowlist(host: str, allowlist: list[str]) -> bool:
    host = host.lower()
    for entry in allowlist:
        if entry.startswith("."):
            if host == entry[1:] or host.endswith(entry):
                return True
        elif host == entry:
            return True
    return False


def _resolve(host: str) -> list[_IPAddr]:
    """Best-effort DNS resolution to a list of IP objects (empty on failure)."""
    # A bare IP literal resolves to itself without a lookup.
    try:
        return [ip_address(host)]
    except ValueError:
        pass
    try:
        infos = socket.getaddrinfo(host, None, proto=socket.IPPROTO_TCP)
    except socket.gaierror:
        return []
    out: list[_IPAddr] = []
    for info in infos:
        addr = info[4][0]
        try:
            out.append(ip_address(addr.split("%", 1)[0]))
        except ValueError:
            continue
    return out


def _embedded_ipv4(ip: _IPAddr) -> IPv4Address | None:
    """The IPv4 address an IPv6 address carries, if it carries one."""
    if isinstance(ip, IPv4Address):
        return None
    if ip.ipv4_mapped is not None:
        return ip.ipv4_mapped
    if ip.sixtofour is not None:
        return ip.sixtofour
    if ip.teredo is not None:
        return ip.teredo[1]
    if ip in _NAT64_NET:
        return IPv4Address(int(ip) & 0xFFFFFFFF)
    # Deprecated IPv4-compatible form ``::a.b.c.d`` (``::`` and ``::1`` excluded).
    if int(ip) >> 32 == 0 and int(ip) > 1:
        return IPv4Address(int(ip))
    return None


def _addresses(ip: _IPAddr) -> list[_IPAddr]:
    """``ip`` plus any IPv4 address embedded in it — every form a socket may reach."""
    embedded = _embedded_ipv4(ip)
    return [ip] if embedded is None else [ip, embedded]


def _is_metadata(ip: _IPAddr) -> bool:
    return any(addr in net for addr in _addresses(ip) for net in _METADATA_NETS)


#: Public names for the egress rules other destinations share (the local
#: runner's schema reader): one definition of "cloud metadata", not two.
METADATA_HOSTNAMES = frozenset(_METADATA_HOSTNAMES)


def is_metadata_ip(ip: _IPAddr) -> bool:
    """True for a cloud-metadata address, including IPv4 embedded in IPv6."""
    return _is_metadata(ip)


def _is_global(ip: _IPAddr) -> bool:
    return all(addr.is_global and not addr.is_multicast for addr in _addresses(ip))


def is_public_ip(ip: _IPAddr) -> bool:
    """True when ``ip`` (and any IPv4 address it embeds) is publicly routable."""
    return _is_global(ip)


def resolve_host(host: str) -> list[_IPAddr]:
    """Every address ``host`` resolves to; an IP literal resolves to itself."""
    return _resolve(host.lower().rstrip("."))


def host_in_allowlist(host: str, allowlist: list[str]) -> bool:
    """Whether the operator's allowlist names ``host`` (exact or ``.suffix``)."""
    return _host_matches_allowlist(host.lower().rstrip("."), allowlist)


def check_target_allowed(
    url: str,
    *,
    allow_private: bool = True,
    allowlist: list[str] | None = None,
) -> None:
    """Raise :class:`TargetNotAllowed` if ``url`` is out of egress policy.

    Returns ``None`` when the target is permitted.
    """
    allowlist = allowlist or []
    parsed = urlparse(url.strip())
    scheme = (parsed.scheme or "").lower()
    if scheme not in _ALLOWED_SCHEMES:
        raise TargetNotAllowed(
            f"scheme '{scheme or '(none)'}' is not allowed; use http or https"
        )
    host = parsed.hostname
    if not host:
        raise TargetNotAllowed("target has no host")
    # A trailing dot names the same host (``metadata.google.internal.``).
    host = host.lower().rstrip(".")
    if not host:
        raise TargetNotAllowed("target has no host")

    if host in _METADATA_HOSTNAMES:
        raise TargetNotAllowed(f"host '{host}' is a cloud-metadata endpoint")

    check_resolved(
        host, _resolve(host), allow_private=allow_private, allowlist=allowlist
    )


def check_resolved(
    host: str,
    resolved: list[_IPAddr],
    *,
    allow_private: bool = True,
    allowlist: list[str] | None = None,
) -> None:
    """Judge ``host`` by addresses that were already resolved.

    The half of :func:`check_target_allowed` after the lookup, for a caller
    that pins the address it connects to (``core/pinning``): the policy must
    judge the address the socket will use, not a second lookup that DNS can
    answer differently.
    """
    allowlist = allowlist or []
    # Always block cloud metadata, even with private hosts allowed.
    for ip in resolved:
        if _is_metadata(ip):
            raise TargetNotAllowed(
                f"host '{host}' resolves to a cloud-metadata address ({ip})"
            )

    if allowlist:
        if _host_matches_allowlist(host, allowlist):
            return
        raise TargetNotAllowed(f"host '{host}' is not in the target allowlist")

    if allow_private:
        # Local-lab posture: private/loopback targets are intentionally allowed,
        # and an unresolvable lab hostname (e.g. a docker service name) is fine.
        return

    if not resolved:
        raise TargetNotAllowed(
            f"host '{host}' does not resolve; refusing to scan an unknown target"
        )
    for ip in resolved:
        if not _is_global(ip):
            raise TargetNotAllowed(
                f"host '{host}' resolves to a non-public address ({ip}); "
                "private targets are disabled (set target_allow_private to scan a lab)"
            )
