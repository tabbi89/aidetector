"""G5: bounded weak-HMAC recovery and controlled JWT time-claim checks."""
from __future__ import annotations

import json
import time

import jwt
import pytest
from fastapi import FastAPI, Header
from fastapi.responses import JSONResponse
from fastapi.testclient import TestClient

from app.domain.enums import AuthType
from app.engine.base import ResolvedCredential
from app.engine.checks.auth import BrokenAuthCheck, _forged_variants
from app.engine.jwt_hmac import MAX_HMAC_WORDS, hmac_probe_suite
from tests import factories

WEAK_KEY = "weak-jwt-secret-2026"
STRONG_KEY = "M9v!zQ2#pL8@xR4$kT7&cN3*eW6_yU1+"


def _token(key: str = WEAK_KEY) -> str:
    now = int(time.time())
    return jwt.encode(
        {"sub": "user-1", "role": "user", "iat": now, "exp": now + 3600},
        key,
        algorithm="HS256",
    )


def _credential(token: str) -> ResolvedCredential:
    return ResolvedCredential("user", "user", AuthType.bearer, None, token)


def _app(*, verify_exp: bool = True, verify_nbf: bool = True) -> FastAPI:
    app = FastAPI()

    @app.get("/account")
    def account(authorization: str | None = Header(default=None)):
        if not authorization or not authorization.startswith("Bearer "):
            return JSONResponse({"detail": "unauthorized"}, status_code=401)
        try:
            claims = jwt.decode(
                authorization.removeprefix("Bearer "),
                WEAK_KEY,
                algorithms=["HS256"],
                options={"verify_exp": verify_exp, "verify_nbf": verify_nbf},
            )
        except jwt.PyJWTError:
            return JSONResponse({"detail": "unauthorized"}, status_code=401)
        return {"role": claims.get("role")}

    return app


def _run(*, verify_exp: bool = True, verify_nbf: bool = True):
    operation = factories.operation("GET", "/account", id="jwt-op", auth_scope="bearer")
    ctx = factories.scan_context(
        [operation],
        credentials=[_credential(_token())],
        client=TestClient(_app(verify_exp=verify_exp, verify_nbf=verify_nbf)),
    )
    return BrokenAuthCheck().run(ctx), ctx


def test_suite_recovers_only_within_word_and_time_bounds():
    token = jwt.encode({"sub": "u"}, "last-key", algorithm="HS256")
    too_late = [f"candidate-{index}" for index in range(MAX_HMAC_WORDS)] + ["last-key"]

    assert hmac_probe_suite(token, wordlist=too_late, clock=lambda: 0.0) is None

    ticks = iter((0.0, 1.0, 1.0))
    assert hmac_probe_suite(
        _token(), wordlist=[WEAK_KEY], time_budget=0.01, clock=lambda: next(ticks)
    ) is None


def test_recovered_key_never_leaves_the_probe_suite():
    suite = hmac_probe_suite(_token(), now=int(time.time()))
    assert suite is not None
    assert not hasattr(suite, "key")
    assert WEAK_KEY not in repr(suite)


def test_expiry_and_nbf_probes_have_valid_signatures():
    suite = hmac_probe_suite(_token(), now=int(time.time()))
    assert suite is not None
    probes = {probe.label: probe.token for probe in suite.probes}

    expired = probes["expired_valid_signature"]
    jwt.decode(expired, WEAK_KEY, algorithms=["HS256"], options={"verify_exp": False})
    with pytest.raises(jwt.ExpiredSignatureError):
        jwt.decode(expired, WEAK_KEY, algorithms=["HS256"])

    future = probes["future_nbf_valid_signature"]
    jwt.decode(future, WEAK_KEY, algorithms=["HS256"], options={"verify_nbf": False})
    with pytest.raises(jwt.ImmatureSignatureError):
        jwt.decode(future, WEAK_KEY, algorithms=["HS256"])


def test_secure_time_validation_reports_only_the_weak_key():
    findings, ctx = _run()
    assert {finding.evidence["bypass_class"] for finding in findings} == {
        "weak_hmac_key"
    }
    assert ctx.probe.count <= 12


def test_validly_signed_expired_token_acceptance_is_verified_with_controls():
    findings, _ = _run(verify_exp=False)
    expired = next(
        finding
        for finding in findings
        if finding.evidence["bypass_class"] == "expired_valid_signature"
    )
    assert expired.evidence["valid_control_status"] == 200
    assert expired.evidence["rejected_control_status"] == 401
    assert expired.confidence.value == "verified"


def test_validly_signed_future_nbf_acceptance_is_verified_with_controls():
    findings, _ = _run(verify_nbf=False)
    future = next(
        finding
        for finding in findings
        if finding.evidence["bypass_class"] == "future_nbf_valid_signature"
    )
    assert future.evidence["valid_control_status"] == 200
    assert future.evidence["rejected_control_status"] == 401


def test_strong_hmac_key_adds_no_dictionary_or_time_probes():
    variants = _forged_variants(
        factories.scan_context(
            [factories.operation("GET", "/account")],
            credentials=[_credential(_token(STRONG_KEY))],
        )
    )
    assert not {
        "weak_hmac_key",
        "expired_valid_signature",
        "future_nbf_valid_signature",
    } & {variant.label for variant in variants}


def test_duplicate_tokens_are_tested_once():
    operation = factories.operation("GET", "/account")
    token = _token()
    one = _forged_variants(
        factories.scan_context([operation], credentials=[_credential(token)])
    )
    duplicate = _forged_variants(
        factories.scan_context(
            [operation], credentials=[_credential(token), _credential(token)]
        )
    )
    assert len(duplicate) == len(one)


def test_jwt_forgeries_preserve_a_custom_authentication_header():
    operation = factories.operation("GET", "/account")
    credential = ResolvedCredential(
        "user", "user", AuthType.api_key, "X-API-Key", _token()
    )
    variants = _forged_variants(
        factories.scan_context([operation], credentials=[credential])
    )

    jwt_variant = next(v for v in variants if v.label != "random_token")
    assert set(jwt_variant.headers) == {"X-API-Key"}


def test_recovered_key_never_reaches_findings_or_logs(caplog):
    findings, _ = _run(verify_exp=False, verify_nbf=False)
    serialized = json.dumps(
        [
            {
                "title": finding.title,
                "description": finding.description,
                "evidence": finding.evidence,
            }
            for finding in findings
        ]
    )
    assert WEAK_KEY not in serialized
    assert WEAK_KEY not in caplog.text
