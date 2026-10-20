"""Password hashing for workspace sign-in.

stdlib scrypt, so the API image gains no dependency. The stored form carries its
own cost parameters (``scrypt$n$r$p$salt$hash``) so they can be raised later
without invalidating existing hashes; :func:`needs_rehash` says when one is
behind. Verification is constant-time, and a malformed hash verifies as false
rather than raising.
"""
from __future__ import annotations

import base64
import hashlib
import secrets
from functools import cache

_N = 2**15
_R = 8
_P = 1
_DKLEN = 32
# scrypt needs 128 * n * r bytes; leave headroom over the 32 MiB this uses.
_MAXMEM = 64 * 1024 * 1024

MIN_LENGTH = 6
MAX_LENGTH = 256


def _b64(raw: bytes) -> str:
    return base64.b64encode(raw).decode()


def _derive(password: str, salt: bytes, n: int, r: int, p: int) -> bytes:
    return hashlib.scrypt(
        password.encode(), salt=salt, n=n, r=r, p=p, dklen=_DKLEN, maxmem=_MAXMEM
    )


def hash_password(password: str) -> str:
    salt = secrets.token_bytes(16)
    digest = _derive(password, salt, _N, _R, _P)
    return f"scrypt${_N}${_R}${_P}${_b64(salt)}${_b64(digest)}"


def verify_password(password: str, stored: str | None) -> bool:
    if not stored:
        return False
    try:
        scheme, n, r, p, salt, digest = stored.split("$")
        if scheme != "scrypt":
            return False
        expected = base64.b64decode(digest)
        actual = _derive(password, base64.b64decode(salt), int(n), int(r), int(p))
    except (ValueError, TypeError):
        return False
    return secrets.compare_digest(actual, expected)


def needs_rehash(stored: str) -> bool:
    return not stored.startswith(f"scrypt${_N}${_R}${_P}$")


@cache
def dummy_hash() -> str:
    """Verified against when the email is unknown, so a miss costs the same
    scrypt work as a wrong password and response time does not enumerate
    accounts. Built on first use, not at import: every worker imports this."""
    return hash_password(secrets.token_urlsafe(16))
