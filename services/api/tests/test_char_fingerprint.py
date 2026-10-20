"""Characterization: the exact fingerprint every check's findings hash to.

``engine/fingerprint.py`` says changing what goes into a fingerprint is a
compatibility change — every stored one is invalidated, carried triage stops
matching, and one diff reports the affected set as fixed-and-new. Nothing
enforced that. These goldens do: a change to ``DEFAULT_KEYS``, ``IDENTITY_KEYS``,
``_canonical`` or the join fails here first, with the affected checks named.

The samples below are hand-written to mirror what each check actually puts in
``evidence`` — including the shapes the identity rules exist to handle: the
grouped header findings whose titles carry counts, ``reflected_injection``'s
rotating payload, and the ``route``-supersedes-``path`` rule.

**Updating a golden is allowed** — it is a decision, not a chore. Change the
value, and say in the commit message which stored fingerprints it invalidates
and why the trade was worth it.
"""
from __future__ import annotations

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from app.engine.checks import ALL_CHECKS
from app.engine.fingerprint import fingerprint, identity_parts

# check key -> (owasp_id, title, evidence) shaped like the check's real output.
SAMPLES: dict[str, tuple[str, str, dict]] = {
    "bola": (
        "API1:2023",
        "Cross-identity read (BOLA) on GET /accounts/{account_id}",
        {
            "method": "GET",
            "route": "/accounts/{account_id}",
            "path": "/accounts/7",
            "identity_a": "admin",
            "identity_b": "user",
            "anon_status": 401,
            "status_a": 200,
            "status_b": 200,
            "object_ids": ["7", "8"],
            "ids_harvested": True,
            "response_sample": '{"id": 7}',
        },
    ),
    "bfla": (
        "API5:2023",
        "Privileged function open to low privilege (BFLA) on POST /admin/users/{user_id}/promote",
        {
            "method": "POST",
            "route": "/admin/users/{user_id}/promote",
            "path": "/admin/users/1/promote",
            "identity": "user",
            "status": 200,
            "response_sample": '{"ok": true}',
        },
    ),
    "broken_auth": (
        "API2:2023",
        "Forged token accepted on GET /accounts/{account_id}",
        {
            "method": "GET",
            "route": "/accounts/{account_id}",
            "path": "/accounts/1",
            "bypass_class": "alg_none",
            "status": 200,
        },
    ),
    "security_headers": (
        "API8:2023",
        "Missing security headers on 12/40 endpoints",
        {
            "missing": ["content-security-policy", "x-content-type-options"],
            "weak": {"strict-transport-security": "max-age=60"},
            "endpoints": ["GET /a", "GET /b"],
            "affected": 12,
        },
    ),
    "info_disclosure": (
        "API8:2023",
        "Server implementation details disclosed on 3/40 endpoints",
        {
            "headers": {"server": "gunicorn/20.1.0", "x-powered-by": "Express"},
            "endpoints": ["GET /a"],
            "affected": 3,
        },
    ),
    "data_exposure": (
        "API3:2023",
        "Sensitive fields returned by GET /users/{user_id}",
        {
            "issue": "sensitive_fields",
            "path": "/users/1",
            "route": "/users/{user_id}",
            "fields": ["ssn", "password_hash"],
            "families": ["credential", "government_id"],
        },
    ),
    "potential_secrets": (
        "API3:2023",
        "Potential secret detected in the response from GET /profile",
        {
            "source": "response",
            "method": "GET",
            "route": "/profile",
            "detector": "GitHub Token",
            "location": "json/object[0]/text-line-1",
        },
    ),
    "enumeration": (
        "API4:2023",
        "No rate limiting on GET /accounts/{account_id}",
        {
            "method": "GET",
            "route": "/accounts/{account_id}",
            "path": "/accounts/1",
            "issue": "rate_limit",
            "requests": 20,
        },
    ),
    "resource_consumption": (
        "API4:2023",
        "Unbounded page size on GET /catalog ('limit')",
        {
            "method": "GET",
            "path": "/catalog",
            "param": "limit",
            "small_size": 1000,
            "small_count": 1000,
            "large_size": 5000,
            "large_count": 5000,
        },
    ),
    "unsafe_consumption": (
        "API10:2023",
        "Unsafe upstream consumption via 'url' on GET /aggregate",
        {
            "method": "GET",
            "path": "/aggregate",
            "param": "url",
            "location": "query",
            "oob_protocol": "http",
            "oob_source_ip": "127.0.0.1",
            "oob_token": "a0123456789abcdef",
        },
    ),
    "business_flow": (
        "API6:2023",
        "Sensitive business flow without anti-automation on POST /checkout",
        {
            "method": "POST",
            "path": "/checkout",
            "requests": 5,
            "distinct_objects": 5,
            "statuses": [201, 201, 201, 201, 201],
        },
    ),
    "write_authz": (
        "API1:2023",
        "BOLA (write): PUT /widgets/{widget_id} write by 'user' persisted",
        {
            "write": "PUT /widgets/{widget_id}",
            "read_back": "GET /widgets/{widget_id}",
            "field": "name",
            "canary": "aidx0123456789",
            "write_status": 200,
            "writer_identity": "user",
            "reader_identity": "admin",
            "kind": "update",
            "response_sample": "{}",
        },
    ),
    "seeded_bola": (
        "API1:2023",
        "Cross-tenant BOLA: GET /records/{record_id} readable by another identity",
        {
            "method": "GET",
            "route": "/records/{record_id}",
            "path": "GET /records/{record_id}",
            "created_via": "POST /records",
            "canary": "aidx0123456789",
            "anon_status": 401,
            "reader_status": 200,
            "creator_identity": "user",
            "reader_identity": "admin",
            "identity": "admin",
            "cleanup": "deleted",
        },
    ),
    "mass_assignment": (
        "API6:2023",
        "Mass assignment: 'role' is client-writable on PUT /users/{user_id}",
        {
            "method": "PUT",
            "route": "/users/{user_id}",
            "read_back": "GET /users/{user_id}",
            "field": "role",
            "family": "privilege",
            "identity": "user",
            "write_status": 200,
            "declared_body_fields": ["email", "name"],
            "cleanup": "restored",
        },
    ),
    "race_condition": (
        "API4:2023",
        "Race condition on POST /orders: duplicate constraint overrun",
        {
            "method": "POST",
            "route": "/orders",
            "path": "/orders",
            "issue": "limit_overrun",
            "burst": 6,
            "accepted": 4,
        },
    ),
    "reflected_injection": (
        "CWE-74",
        "Reflected XSS via query 'q' on GET /search",
        {
            "family": "xss",
            "path": "/search",
            "route": "/search",
            "param": "q",
            "location": "query",
            "payload": "<script>aidxdeadbeef</script>",
            "status": 200,
            "reflected": True,
            "response_sample": "aidxdeadbeef",
        },
    ),
    "signature_injection": (
        "CWE-74",
        "NoSQL injection lead via query 'name' on GET /lookup",
        {
            "family": "nosql",
            "path": "/lookup",
            "route": "/lookup",
            "param": "name",
            "location": "query",
            "payload": "aidxdeadbeef",
            "status": 500,
            "reflected": False,
            "error_signature": "MongoError",
        },
    ),
    "ssrf": (
        "API7:2023",
        "Possible SSRF via query 'url' on GET /fetch",
        {
            "family": "ssrf",
            "path": "/fetch",
            "route": "/fetch",
            "param": "url",
            "location": "query",
            "payload": "http://169.254.169.254/",
            "status": 200,
            "reflected": True,
        },
    ),
    "oob_injection": (
        "API7:2023",
        "Confirmed blind SSRF via query 'url' on GET /fetch",
        {
            "family": "blind_ssrf",
            "path": "/fetch",
            "route": "/fetch",
            "param": "url",
            "location": "query",
            "payload": "http://token.oast.test/",
            "protocol": "http",
        },
    ),
    "schema_fuzz": (
        "API8:2023",
        "Server error on generated input to GET /compute",
        {
            "method": "GET",
            "route": "/compute",
            "path": "/compute",
            "rule": "server_error",
            "location": "response.status",
            "status": 500,
        },
    ),
    "tls_config": (
        "API8:2023",
        "Expired TLS certificate for example.test",
        {
            "host": "example.test",
            "protocol": "TLSv1.3",
            "cipher": "TLS_AES_256_GCM_SHA384",
            "not_valid_after": "2020-01-01T00:00:00+00:00",
        },
    ),
    "host_header": (
        "API8:2023",
        "Host-header reflection on GET /reset-link",
        {
            "method": "GET",
            "route": "/reset-link",
            "canary_marker": "aidx0000000000000000",
        },
    ),
    "design_review": (
        "API2:2023",
        "Sensitive operation with no declared auth: GET /admin/users",
        {
            "method": "GET",
            "route": "/admin/users",
            "signal": "no_auth",
        },
    ),
    "advanced_rate_limit": (
        "API4:2023",
        "No rate limiting under sustained load on POST /login",
        {
            "method": "POST",
            "path": "/login",
            "requests": 24,
            "statuses": [200],
        },
    ),
    "xxe_confirmation": (
        "CWE-74",
        "XXE external entity confirmed via 'data' on POST /xml",
        {
            "method": "POST",
            "route": "/xml",
            "field": "data",
            "family": "external_entity",
            "payload": "<?xml",
            "oob_protocol": "http",
        },
    ),
    "jwt_confusion": (
        "API2:2023",
        "JWT key confusion on GET /jwt",
        {
            "bypass_class": "rs256_hs256_confusion",
            "method": "GET",
            "route": "/jwt",
        },
    ),
    "deserialization": (
        "API10:2023",
        "Python pickle deserialization confirmed via 'data' on POST /deserialize",
        {
            "method": "POST",
            "route": "/deserialize",
            "field": "data",
            "family": "python_pickle",
            "payload": "cos",
            "oob_protocol": "http",
        },
    ),
    "graphql_introspection": (
        "API8:2023",
        "GraphQL introspection enabled on POST /graphql",
        {
            "method": "POST",
            "route": "/graphql",
            "introspection": True,
        },
    ),
    "graphql_behavior": (
        "API2:2023",
        "GraphQL alias authorization bypass on POST /graphql",
        {
            "method": "POST",
            "route": "/graphql",
            "issue": "alias_auth_bypass",
            "bypass_class": "alias_auth_bypass",
            "owner_control": "success",
            "anonymous_control": "denied",
            "attacker_control": "denied",
            "alternative_status": 200,
        },
    ),
    "request_smuggling": (
        "API8:2023",
        "HTTP request smuggling (CL.TE) on testserver/",
        {
            "family": "cl_te",
            "host": "testserver",
            "path": "/",
        },
    ),
    "grpc_reflection": (
        "API9:2023",
        "gRPC reflection enabled on POST /grpc",
        {
            "method": "POST",
            "route": "/grpc",
            "services": ["grpc.health.v1.Health"],
        },
    ),
    # Not a registered check — an adjunct's findings, which take identity from
    # ``IDENTITY_KEYS["zap"]`` like any other. Shaped like a real *active*-scan
    # alert: the URL carries the payload that triggered it, so ``location`` (the
    # URL with the query stripped, ``zap.alert_location``) is what identity uses
    # and ``url``/``attack``/``evidence`` are deliberately excluded.
    "zap": (
        "API8:2023",
        "SQL Injection",
        {
            "name": "SQL Injection",
            "location": "http://target/v1/items",
            "url": "http://target/v1/items?id=1%27+OR+1%3D1",
            "param": "id",
            "attack": "1' OR 1=1",
            "evidence": "syntax error near",
            "plugin_id": "40018",
            "source": "zap",
        },
    ),
}

GOLDEN_FINGERPRINTS: dict[str, str] = {
    "bfla": "8e3b2127bc884c1267f5956fd5a00d2f",
    "bola": "52fc07460b6ad9c67e8a1e18fafbbf86",
    "broken_auth": "bfef64b1df012b2e0f6b214bddfedb25",
    "data_exposure": "c30fb37f43e7768c8e33473c02d76912",
    "potential_secrets": "dbc3181f9ec7b73a71268882893911dd",
    "enumeration": "d091c2026b27c5369c1732ef5eac5820",
    "resource_consumption": "6e48fc9e6e92ccfa71375f6505375acc",
    "business_flow": "9026deefd0ab7d8b52d12099a73646a2",
    "unsafe_consumption": "0c55383ec037cae04dc169dedff10f5c",
    "info_disclosure": "b325e32551ac04f3aef53d5c3198a71f",
    "mass_assignment": "887e15c8f322145c22c9ddda12ca9e08",
    "oob_injection": "d1c7b6eac6d62afb5e7bd0f7ab3d4830",
    "race_condition": "03c15449ec8c20a3056e6e74da17b085",
    "reflected_injection": "abd528a73dda757b25c78b815820b9ef",
    "schema_fuzz": "901e4031c0cde4952da7acd2462a943c",
    "security_headers": "7d3b8be72920b5e7870eca7cfd17757f",
    "seeded_bola": "00342625f24c60a30ff0ef62b47b868b",
    "signature_injection": "263204405e3db3cd6bc949739bafb2f2",
    "ssrf": "c9533e8bd18f9aa0583db93da8984747",
    "tls_config": "af702e718025a58d64410fdde879b0a1",
    "write_authz": "b69432081b2d970137d11055d5cc5c74",
    "host_header": "ec9555bd0d2bd63fdab2d1061388f4c0",
    "design_review": "641c7e311b6ac872ad6242bee00af7d2",
    "advanced_rate_limit": "84cc06a7478af52905123e94d1ef81e5",
    "xxe_confirmation": "267e6eef0b920f08736299683958d9bb",
    "jwt_confusion": "e72d3a216a059b101d2753ef181a42f5",
    "deserialization": "abd0403706f40861def5a9391c7337c0",
    "graphql_introspection": "cabffe77d3adfc8be55a6bc53a2bf34a",
    "graphql_behavior": "beb9137f14aba7eed0654d5bbf50b233",
    "request_smuggling": "c60ec1246953baf8b0665eca6e3638a1",
    "grpc_reflection": "695286c29fa2cbd0130cd05264ffce6b",
    "zap": "710bd9d7a25ee70d04a0d36dfbaa4847",
}


@pytest.mark.parametrize("check", sorted(GOLDEN_FINGERPRINTS))
def test_fingerprint_is_unchanged(check: str) -> None:
    owasp_id, title, evidence = SAMPLES[check]
    assert fingerprint(check, owasp_id, title, evidence) == GOLDEN_FINGERPRINTS[check], (
        f"the fingerprint for '{check}' changed. Every stored fingerprint for this "
        "check is now invalid: carried triage stops matching and the next diff "
        "reports the affected set as fixed-and-new, once. If that is the intent, "
        "update the golden and say so in the commit message."
    )


def test_every_registered_check_has_a_golden() -> None:
    """A check with no golden is a check whose identity nothing protects.

    Adjunct sources that are not in ``ALL_CHECKS`` (``zap``) are covered too —
    they carry a ``IDENTITY_KEYS`` entry, so they can churn the same way.
    """
    missing = sorted({c.key for c in ALL_CHECKS} - set(GOLDEN_FINGERPRINTS))
    assert not missing, (
        f"checks with no fingerprint golden: {missing}. Add a SAMPLES entry "
        "shaped like the evidence the check emits, then add its fingerprint."
    )


def test_samples_and_goldens_cover_the_same_keys() -> None:
    assert set(SAMPLES) == set(GOLDEN_FINGERPRINTS)


def test_every_identity_override_has_a_golden() -> None:
    """A per-check override in IDENTITY_KEYS is exactly what churns silently."""
    from app.engine.fingerprint import IDENTITY_KEYS

    missing = sorted(set(IDENTITY_KEYS) - set(GOLDEN_FINGERPRINTS))
    assert not missing, (
        f"checks with a custom identity but no golden: {missing}. An override is "
        "the change most likely to invalidate stored fingerprints unnoticed."
    )


def test_route_supersedes_path_in_identity() -> None:
    """Two runs that probed different URLs of one route hash identically.

    The rule that makes triage survive a re-scan: the attacked URL carries a
    rotating payload or a harvested id, the route names the handler.
    """
    base = {"method": "GET", "route": "/accounts/{id}", "param": "q", "location": "query"}
    run_one = fingerprint("bola", "API1:2023", "t", {**base, "path": "/accounts/7"})
    run_two = fingerprint("bola", "API1:2023", "t", {**base, "path": "/accounts/1042"})
    assert run_one == run_two


def test_reflected_injection_identity_excludes_the_payload_family() -> None:
    """Payloads rotate per scan by design, so family must not be identity here.

    Pinned separately from the golden because it is the reason
    ``reflected_injection`` has an ``IDENTITY_KEYS`` override at all.
    """
    base = {"path": "/search", "route": "/search", "param": "q", "location": "query"}
    parts = identity_parts("reflected_injection", "CWE-74", "t", {**base, "family": "xss"})
    assert not any(p.startswith("family=") for p in parts)
    assert fingerprint("reflected_injection", "CWE-74", "t", {**base, "family": "xss"}) == (
        fingerprint("reflected_injection", "CWE-74", "t", {**base, "family": "sqli"})
    )


def test_schema_fuzz_identity_uses_rule_and_structural_location_not_values() -> None:
    base = {
        "method": "GET",
        "route": "/items",
        "rule": "schema",
        "location": "response.body/name",
    }
    first = fingerprint("schema_fuzz", None, "first", {**base, "status": 200})
    assert first == fingerprint(
        "schema_fuzz", None, "second", {**base, "status": 422, "response_sample": "rotated"}
    )
    assert first != fingerprint(
        "schema_fuzz", None, "first", {**base, "rule": "headers"}
    )
    assert first != fingerprint(
        "schema_fuzz", None, "first", {**base, "location": "response.body/id"}
    )


@pytest.mark.parametrize("check", sorted(SAMPLES))
@settings(max_examples=40, deadline=None, derandomize=True)
@given(
    status=st.integers(min_value=100, max_value=599),
    count=st.integers(min_value=0, max_value=100000),
    payload=st.text(max_size=60),
    object_id=st.uuids(),
)
def test_every_check_ignores_non_identity_run_noise(check, status, count, payload, object_id):
    owasp_id, title, evidence = SAMPLES[check]
    rotated = {
        **evidence, "status": status, "requests": count, "affected": count,
        "response_sample": payload, "payload": payload,
        "object_ids": [str(object_id)], "timestamp": count,
    }
    if evidence.get("route"):
        rotated["path"] = f"/objects/{object_id}/{payload}"
    # Reverse insertion order too: dictionary construction order is never identity.
    rotated = dict(reversed(list(rotated.items())))
    assert fingerprint(check, owasp_id, title, rotated) == GOLDEN_FINGERPRINTS[check]


@pytest.mark.parametrize("key", ["route", "method", "param", "location", "bypass_class"])
@settings(max_examples=40, deadline=None, derandomize=True)
@given(suffix=st.text(alphabet="abcdefghijklmnopqrstuvwxyz0123456789", min_size=1, max_size=30))
def test_identity_defining_changes_remain_distinguishable(key, suffix):
    evidence = {
        "route": "/items/{id}", "method": "GET", "param": "q",
        "location": "query", "bypass_class": "alg_none",
    }
    changed = {**evidence, key: evidence[key] + suffix}
    assert fingerprint("broken_auth", "API2:2023", "t", evidence) != fingerprint(
        "broken_auth", "API2:2023", "t", changed
    )


@settings(max_examples=40, deadline=None, derandomize=True)
@given(
    order=st.permutations(["content-security-policy", "x-frame-options", "referrer-policy"]),
    value=st.text(min_size=1, max_size=60),
    count=st.integers(min_value=1, max_value=10000),
)
def test_header_profile_identity_ignores_order_values_and_endpoint_counts(order, value, count):
    def digest(missing, observed, title):
        return fingerprint("security_headers", "API8:2023", title, {
            "missing": missing, "weak": {"strict-transport-security": observed},
        })

    assert digest(order, value, f"Missing headers on {count} endpoints") == digest(
        sorted(order), "max-age=60", "Missing headers on 1 endpoint"
    )
    assert digest(order, value, "t") != digest(order[:-1], value, "t")


@pytest.mark.parametrize("empty", [None, "", [], {}])
def test_empty_identity_values_use_the_title_fallback(empty):
    assert identity_parts("bola", None, "  title  ", {"route": empty}) == [
        "bola", "", "title=title"
    ]


def test_fingerprint_handles_malformed_unicode_without_losing_identity():
    assert fingerprint("bola", "API1:2023", "\ud800") == fingerprint("bola", "API1:2023", "?")
    assert fingerprint("bola", "API1:2023", "\ud800") != fingerprint("bola", "API1:2023", "other")
