"""Proof that a workspace controls a public scan target.

Two proofs, because each answers a different question:

- **DNS TXT** at ``_aidetector-challenge.<host>`` proves control of the *name*.
  It is not enough alone: whoever owns ``attacker.com`` may point
  ``victim.attacker.com`` at someone else's address, and the TXT check passes.
- **An HTTP token** at ``/.well-known/aidetector-verify/<token>``, fetched from
  the exact address the scan will connect to, proves control of the *machine
  that answers*. Someone else's server does not serve our token, which is what
  defeats pointing a name you own at an address you don't.

A host given as an IP literal has no name to prove, so it answers the HTTP proof
only. DNS is queried over DoH (``domain_verification_doh_url``) rather than the
local resolver, which the person asking may control.

Kept free of the database so the local runner can repeat the HTTP proof from its
own vantage point (``app/runner/main.py``).
"""
from __future__ import annotations

import re
import secrets
from ipaddress import ip_address
from urllib.parse import urlsplit

import httpx

from app.core.pinning import PinnedTransport, PinPolicy, canonical_host, url_host
from app.core.target_guard import TargetNotAllowed, check_resolved

DNS_LABEL = "_aidetector-challenge"
TXT_PREFIX = "aidetector-verify="
WELL_KNOWN = "/.well-known/aidetector-verify/"
#: A token response is one line; anything longer is not ours.
_MAX_BODY = 4096
_TXT_TYPE = 16
_QUOTED = re.compile(r'"((?:[^"\\]|\\.)*)"')


class OwnershipNotProven(TargetNotAllowed):
    """The workspace has not shown it controls this public target."""


def new_token() -> str:
    return secrets.token_hex(16)


def normalize_host(raw: str) -> str:
    """A host as verification stores it: lower-case, no trailing dot or brackets."""
    host = raw.strip().lower().rstrip(".").strip("[]")
    if not host or "/" in host or ":" in host and not is_ip_literal(host):
        raise ValueError("give a host name such as api.example.com, not a URL")
    try:
        return canonical_host(host)
    except (httpx.InvalidURL, UnicodeError) as exc:
        raise ValueError(f"'{raw.strip()}' is not a valid host name") from exc


def is_ip_literal(host: str) -> bool:
    try:
        ip_address(host)
    except ValueError:
        return False
    return True


def dns_record_name(host: str) -> str:
    return f"{DNS_LABEL}.{host}"


def dns_record_value(token: str) -> str:
    return f"{TXT_PREFIX}{token}"


def token_url(target_url: str, token: str) -> str:
    """Where the HTTP proof lives: the target's own origin, never its base path."""
    parts = urlsplit(target_url)
    return f"{parts.scheme}://{parts.netloc}{WELL_KNOWN}{token}"


def _txt_strings(data: str) -> str:
    # DoH JSON returns a TXT record as one or more quoted character-strings;
    # a long value is split across them and means their concatenation.
    chunks = _QUOTED.findall(data)
    return "".join(chunks) if chunks else data.strip()


def check_dns_txt(
    host: str,
    token: str,
    *,
    doh_url: str,
    timeout: float = 5.0,
    transport: httpx.BaseTransport | None = None,
) -> None:
    """Raise :class:`OwnershipNotProven` unless the TXT record carries ``token``."""
    if is_ip_literal(host):
        return
    name = dns_record_name(host)
    try:
        with httpx.Client(timeout=timeout, transport=transport) as client:
            response = client.get(
                doh_url,
                params={"name": name, "type": "TXT"},
                headers={"accept": "application/dns-json"},
            )
        response.raise_for_status()
        payload = response.json()
    except (httpx.HTTPError, ValueError) as exc:
        raise OwnershipNotProven(f"could not query DNS for {name}: {exc}") from exc
    if not isinstance(payload, dict) or payload.get("Status") != 0:
        raise OwnershipNotProven(f"no TXT record at {name}")
    values = [
        _txt_strings(str(answer.get("data", "")))
        for answer in payload.get("Answer") or []
        if isinstance(answer, dict) and answer.get("type") == _TXT_TYPE
    ]
    if dns_record_value(token) not in values:
        raise OwnershipNotProven(
            f"TXT record at {name} does not contain {dns_record_value(token)}"
        )


def check_http_token(
    target_url: str,
    token: str,
    *,
    address: str | None,
    timeout: float = 5.0,
    inner: httpx.BaseTransport | None = None,
    allow_private: bool = True,
) -> None:
    """Raise :class:`OwnershipNotProven` unless ``address`` serves ``token``.

    ``address`` is the pinned address the scan will use. With none (the caller
    could not resolve the host), the fetch resolves once itself and still
    connects only to what it resolved. ``allow_private`` is the egress policy of
    whoever makes the fetch: a pinned address is never re-judged by the
    transport, so it is judged here before anything is dialled.
    """
    url = token_url(target_url, token)
    host = url_host(target_url)
    if address is None:
        # Never let the proof resolve on its own: that lookup would be judged
        # by no egress policy at all.
        raise OwnershipNotProven(f"'{host}' does not resolve, so no address can prove it")
    check_resolved(host, [ip_address(address)], allow_private=allow_private)
    policy = PinPolicy(pins={host: address})
    try:
        with httpx.Client(
            timeout=timeout,
            follow_redirects=False,
            transport=PinnedTransport(policy, inner),
        ) as client, client.stream("GET", url) as response:
            body = b""
            for chunk in response.iter_bytes():
                body += chunk
                if len(body) > _MAX_BODY:
                    break
    except TargetNotAllowed:
        raise
    except httpx.HTTPError as exc:
        raise OwnershipNotProven(f"could not fetch {url}: {exc}") from exc
    if response.status_code != 200:
        status = response.status_code
        hint = (
            " — redirects are not followed, so serve the token on this origin directly"
            if 300 <= status < 400
            else " — nothing is served at this path yet"
            if status == 404
            else ""
        )
        raise OwnershipNotProven(f"{url} answered {status}{hint}")
    text = body[:_MAX_BODY].decode("utf-8", "replace").strip()
    # The bare token is what we ask for; the TXT value is accepted too, because
    # it is the other string the page shows and it carries the same token.
    if text in (token, dns_record_value(token)):
        return
    if token in text:
        raise OwnershipNotProven(
            f"{url} returned the token wrapped in other content — serve it as "
            f"plain text on its own: {token}"
        )
    if not text:
        raise OwnershipNotProven(f"{url} returned an empty body — serve the token: {token}")
    raise OwnershipNotProven(
        f"{url} did not return the verification token — serve exactly: {token}"
    )
