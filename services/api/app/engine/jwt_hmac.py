"""Bounded offline HMAC-key recovery and validly signed JWT probes.

The recovered key exists only as a local loop variable. Callers receive signed
tokens plus labels; no key, key hash, word-list position or token payload is
returned, logged or persisted.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import time
from collections.abc import Callable, Iterable
from dataclasses import dataclass
from typing import Any

from app.engine.jwt_forge import ForgedToken, _bump_privilege, _read

MAX_HMAC_WORDS = 64
MAX_HMAC_SECONDS = 0.05
MAX_TOKEN_BYTES = 8_192

_HASHES: dict[str, Callable[..., Any]] = {
    "HS256": hashlib.sha256,
    "HS384": hashlib.sha384,
    "HS512": hashlib.sha512,
}

# Small and deliberately static: this is a weak-default check, not password
# cracking. Expanding it changes CPU cost and requires a separate review.
DEFAULT_HMAC_WORDLIST: tuple[str, ...] = (
    "secret",
    "password",
    "changeme",
    "jwtsecret",
    "jwt-secret",
    "your-256-bit-secret",
    "supersecret",
    "development",
    "dev-secret",
    "test-secret",
    "weak-jwt-secret-2026",
    "123456",
    "12345678",
    "admin",
    "default",
)


@dataclass(frozen=True)
class HmacProbeSuite:
    valid_control: str
    rejected_control: str
    probes: tuple[ForgedToken, ...]


def _b64url(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def _sign(
    header: dict[str, Any],
    payload: dict[str, Any],
    key: bytes,
    digest: Callable[..., Any],
) -> str:
    encoded_header = _b64url(json.dumps(header, separators=(",", ":")).encode())
    encoded_payload = _b64url(json.dumps(payload, separators=(",", ":")).encode())
    signing_input = f"{encoded_header}.{encoded_payload}".encode()
    signature = _b64url(hmac.new(key, signing_input, digest).digest())
    return f"{encoded_header}.{encoded_payload}.{signature}"


def hmac_probe_suite(
    token: str,
    *,
    wordlist: Iterable[str] = DEFAULT_HMAC_WORDLIST,
    now: int | None = None,
    time_budget: float = MAX_HMAC_SECONDS,
    clock: Callable[[], float] = time.process_time,
) -> HmacProbeSuite | None:
    """Return value-free, validly signed probes when a bounded key search succeeds."""
    if len(token.encode("utf-8", "replace")) > MAX_TOKEN_BYTES:
        return None
    read = _read(token)
    if read is None:
        return None
    header, payload = read
    algorithm = str(header.get("alg", ""))
    digest = _HASHES.get(algorithm)
    if digest is None:
        return None
    try:
        encoded_header, encoded_payload, encoded_signature = token.split(".")
        supplied_signature = base64.urlsafe_b64decode(
            encoded_signature + "=" * (-len(encoded_signature) % 4)
        )
    except (ValueError, TypeError):
        return None
    signing_input = f"{encoded_header}.{encoded_payload}".encode()
    deadline = clock() + max(0.0, min(float(time_budget), MAX_HMAC_SECONDS))
    recovered: bytes | None = None
    for position, candidate in enumerate(wordlist):
        if position >= MAX_HMAC_WORDS or clock() > deadline:
            break
        key = str(candidate).encode()
        if hmac.compare_digest(hmac.new(key, signing_input, digest).digest(), supplied_signature):
            recovered = key
            break
    if recovered is None:
        return None

    current = int(time.time()) if now is None else int(now)
    probes = [
        ForgedToken(
            "weak_hmac_key",
            "a privilege-modified token signed with an offline-recovered weak HMAC "
            "key was accepted",
            _sign(header, _bump_privilege(payload), recovered, digest),
        ),
        ForgedToken(
            "expired_valid_signature",
            "a correctly signed token whose exp claim is in the past was accepted",
            _sign(header, {**payload, "exp": current - 60}, recovered, digest),
        ),
    ]
    future = current + 60
    expires = payload.get("exp")
    if not isinstance(expires, int | float) or expires > future:
        probes.append(
            ForgedToken(
                "future_nbf_valid_signature",
                "a correctly signed token whose nbf claim is in the future was accepted",
                _sign(header, {**payload, "nbf": future}, recovered, digest),
            )
        )

    # Invalid signature over the unchanged claims: a rejected control proving
    # the target does validate signatures before a time-claim result is trusted.
    rejected = f"{encoded_header}.{encoded_payload}.runpentestsInvalidSignature"
    return HmacProbeSuite(token, rejected, tuple(probes))
