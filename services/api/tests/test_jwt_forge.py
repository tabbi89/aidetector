"""Forged JWT variants: the bypass classes built from a captured token."""
from __future__ import annotations

import jwt

from app.engine.jwt_forge import forge_from_token


def test_forge_from_non_jwt_is_empty():
    assert forge_from_token("plain-opaque-token") == []


def test_forge_from_jwt_yields_bypass_classes():
    token = jwt.encode({"sub": "u1", "role": "user"}, "s"*32, algorithm="HS256")
    forged = forge_from_token(token)
    labels = {f.label for f in forged}
    # A token with no `kid` cannot carry the kid-injection probe.
    assert labels == {
        "alg_none", "sig_stripped", "sig_tampered", "claims_tampered", "alg_none_case",
    }
    none_tok = next(f for f in forged if f.label == "alg_none").token
    assert jwt.get_unverified_header(none_tok)["alg"] == "none"


def test_alg_none_case_variant_is_capitalised_with_empty_signature():
    """A string-compare block on the literal 'none' is bypassed by 'None'."""
    token = jwt.encode({"sub": "u1"}, "s"*32, algorithm="HS256")
    forged = next(f for f in forge_from_token(token) if f.label == "alg_none_case")
    assert jwt.get_unverified_header(forged.token)["alg"] == "None"
    assert forged.token.endswith("."), "the signature must be empty"


def test_kid_probe_only_appears_when_the_token_names_a_key():
    without = {f.label for f in forge_from_token(jwt.encode({"s": 1}, "k"*32, algorithm="HS256"))}
    assert "kid_empty_key" not in without

    with_kid = jwt.encode(
        {"s": 1}, "k"*32, algorithm="HS256", headers={"kid": "key-1"}
    )
    assert "kid_empty_key" in {f.label for f in forge_from_token(with_kid)}


def test_kid_empty_key_token_is_a_valid_hmac_over_the_empty_key():
    """The probe only works if the signature genuinely verifies with key=b''."""
    import base64
    import hashlib
    import hmac

    token = jwt.encode({"sub": "u1"}, "s"*32, algorithm="HS256", headers={"kid": "k1"})
    forged = next(f for f in forge_from_token(token) if f.label == "kid_empty_key")
    header, payload, sig = forged.token.split(".")
    expected = (
        base64.urlsafe_b64encode(
            hmac.new(b"", f"{header}.{payload}".encode(), hashlib.sha256).digest()
        )
        .rstrip(b"=")
        .decode()
    )
    assert sig == expected
    hdr = jwt.get_unverified_header(forged.token)
    assert hdr["alg"] == "HS256" and "dev/null" in hdr["kid"]
