"""JWT key confusion and header injection (premium, confirmation tier)."""
from __future__ import annotations

from app.domain.enums import AuthType
from app.engine.base import ResolvedCredential, TargetOperation
from app.engine.checks.jwt_confusion import JwtConfusionCheck
from app.engine.jwt_forge import (
    forge_hs256_confusion,
    forge_jku,
    pem_from_jwks,
)
from tests import factories
from tests.fakes import CollectorOob
from tests.vulnapp import OUTBOUND, _jwt_material

JWT_TOKEN = "eyJhbGciOiJSUzI1NiJ9.eyJyb2xlIjoidXNlciJ9.sig"
JWT_OP = TargetOperation(
    id="op-jwt", method="GET", path="/jwt", params=[], auth_scope="bearer"
)


def _cred() -> ResolvedCredential:
    return ResolvedCredential("u", "user", AuthType.bearer, None, JWT_TOKEN)


# ---- the pure forges ----------------------------------------------------------

def test_pem_from_jwks_round_trips():
    import base64

    key, pem = _jwt_material()
    nums = key.public_key().public_numbers()

    def b64url(i: int) -> str:
        return base64.urlsafe_b64encode(
            i.to_bytes((i.bit_length() + 7) // 8, "big")
        ).rstrip(b"=").decode()

    jwks = {"keys": [{"kty": "RSA", "n": b64url(nums.n), "e": b64url(nums.e)}]}
    assert pem_from_jwks(jwks) == pem


def test_forge_hs256_confusion_signs_with_the_public_key():
    import base64
    import hashlib
    import hmac
    import json

    _, pem = _jwt_material()
    forged = forge_hs256_confusion(JWT_TOKEN, pem)
    assert forged is not None
    h, p, s = forged.token.split(".")
    header = json.loads(base64.urlsafe_b64decode(h + "=" * (-len(h) % 4)))
    assert header["alg"] == "HS256"
    expected = hmac.new(pem.encode(), f"{h}.{p}".encode(), hashlib.sha256).digest()
    assert base64.urlsafe_b64decode(s + "=" * (-len(s) % 4)) == expected


def test_forge_jku_sets_the_header():
    import base64
    import json

    forged = forge_jku(JWT_TOKEN, "http://evil.test/jwks")
    assert forged is not None
    h, _, _ = forged.token.split(".")
    header = json.loads(base64.urlsafe_b64decode(h + "=" * (-len(h) % 4)))
    assert header["jku"] == "http://evil.test/jwks"


# ---- the check ----------------------------------------------------------------

def test_premium_check_noops_without_premium():
    ctx = factories.scan_context([JWT_OP], credentials=[_cred()])
    assert JwtConfusionCheck().run(ctx) == []


def test_jku_injection_is_oob_confirmed():
    ctx = factories.scan_context(
        [JWT_OP], credentials=[_cred()], oob=CollectorOob(OUTBOUND), premium=True
    )
    findings = JwtConfusionCheck().run(ctx)
    assert any(f.evidence["bypass_class"] == "jku_injection" for f in findings)


def test_rs256_hs256_confusion_is_confirmed():
    ctx = factories.scan_context([JWT_OP], credentials=[_cred()], premium=True)
    findings = JwtConfusionCheck().run(ctx)
    confusions = [f for f in findings if f.evidence["bypass_class"] == "rs256_hs256_confusion"]
    assert confusions
    assert confusions[0].confidence.value == "verified"
    assert confusions[0].severity.value == "critical"
