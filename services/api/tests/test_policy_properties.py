"""Generated policy invariants with independent security/shape expectations."""
from __future__ import annotations

from dataclasses import asdict

from hypothesis import given, settings
from hypothesis import strategies as st

from app.domain.enums import Severity
from app.engine.base import TargetOperation
from app.engine.exposure_policy import (
    MAX_ARRAY_ITEMS,
    MAX_DEPTH,
    MAX_FIELDS,
    field_names,
    sensitive_issues,
    undeclared_issue,
)
from app.engine.header_policy import analyze_disclosure_headers, analyze_headers
from app.engine.spec_values import InjectionPoint, injection_points, injection_value, prepare

# Bounded, deterministic CI examples; failing examples are printed by Hypothesis.
bounded = settings(max_examples=60, deadline=None, derandomize=True)

names = st.text(alphabet="abcdefghijklmnopqrstuvwxyz", min_size=1, max_size=12)
scalars = st.one_of(st.none(), st.booleans(), st.integers(), st.text(max_size=40))
trees = st.recursive(
    scalars,
    lambda child: st.one_of(
        st.lists(child, max_size=5), st.dictionaries(names, child, max_size=6)
    ),
    max_leaves=35,
)


@bounded
@given(st.dictionaries(names, st.text(max_size=80), max_size=12), st.booleans())
def test_header_name_case_and_outer_whitespace_do_not_change_issues(headers, https):
    canonical = {k: v.strip() for k, v in headers.items()}
    varied = {k.upper(): f" \t{v}\t " for k, v in canonical.items()}
    # Include scored headers, so this cannot pass by only comparing missing headers.
    canonical.update({"x-frame-options": "DENY", "server": "nginx/1.2"})
    varied.update({"X-Frame-Options": " DENY ", "SERVER": " nginx/1.2 "})
    assert analyze_headers(canonical, https=https) == analyze_headers(varied, https=https)
    assert analyze_disclosure_headers(canonical) == analyze_disclosure_headers(varied)


@bounded
@given(st.integers(min_value=0, max_value=63_072_000))
def test_hsts_one_year_boundary(age):
    issues = analyze_headers(
        {"strict-transport-security": f"max-age={age}; includeSubDomains"}, https=True
    )
    assert any(i.header == "strict-transport-security" for i in issues) == (age < 31_536_000)


@bounded
@given(st.text(alphabet="abcdef0123456789", min_size=16, max_size=80), st.booleans())
def test_cookie_values_never_leave_header_policy(value, https):
    cookie = "sentinel_" + value
    issues = analyze_headers({"set-cookie": f"session={cookie}"}, https=https)
    cookie_issues = [i for i in issues if i.header == "set-cookie"]
    assert len(cookie_issues) == 1
    assert cookie_issues[0].observed == "session"
    assert cookie not in repr([asdict(i) for i in issues])


@bounded
@given(trees)
def test_arbitrary_json_field_walk_is_bounded_unique_and_deterministic(payload):
    fields = field_names(payload)
    assert fields == field_names(payload)
    assert len(fields) <= MAX_FIELDS
    assert len({f.location for f in fields}) == len(fields)
    assert all(isinstance(f.name, str) and f.name for f in fields)


@bounded
@given(st.integers(min_value=0, max_value=MAX_DEPTH + 8))
def test_nested_field_walk_stops_at_declared_depth(depth):
    payload = {"password": "sentinel"}
    for _ in range(depth):
        payload = {"wrapper": payload}
    assert any(f.name == "password" for f in field_names(payload)) == (depth <= MAX_DEPTH)


@bounded
@given(st.integers(min_value=0, max_value=MAX_ARRAY_ITEMS + 8))
def test_array_sample_does_not_inspect_later_elements(position):
    payload = [{} for _ in range(position)] + [{"password": "sentinel"}]
    assert bool(sensitive_issues(field_names(payload))) == (position < MAX_ARRAY_ITEMS)


@bounded
@given(st.integers(min_value=MAX_FIELDS - 2, max_value=MAX_FIELDS + 10))
def test_flat_object_field_limit(size):
    fields = field_names({f"key{i}": None for i in range(size)})
    assert len(fields) == min(size, MAX_FIELDS)


@bounded
@given(scalars, scalars)
def test_sensitive_value_rotation_leaves_findings_identical(first, second):
    def issues(value):
        return sensitive_issues(field_names({"password_hash": value, "card_last4": value}))

    assert issues(first) == issues(second)
    assert [i.key for i in issues(first)] == ["credential"]
    assert issues(first)[0].fields == ("password_hash",)


@bounded
@given(st.sets(names, min_size=1, max_size=15), trees)
def test_declared_top_level_fields_do_not_drift_with_nested_values(declared, nested):
    fields = field_names(dict.fromkeys(sorted(declared), nested))
    assert undeclared_issue(fields, declared) is None
    assert undeclared_issue(fields, None) is None


@bounded
@given(
    st.sampled_from(["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"]),
    st.booleans(),
    st.lists(st.sampled_from(["query", "path", "body", "header", "cookie"]), max_size=12),
)
def test_injection_sink_policy_never_widens_mutation_permission(method, mutate, locations):
    op = TargetOperation(
        id="op", method=method, path="/items",
        params=[{"name": f"p{i}", "in": loc} for i, loc in enumerate(locations)],
    )
    # Independent truth table: authorization does not enable DELETE/header/cookie fuzzing.
    allowed = {
        ("GET", False): {"query", "path"}, ("GET", True): {"query", "path"},
        ("POST", True): {"body"}, ("PUT", True): {"body"}, ("PATCH", True): {"body"},
    }.get((method, mutate), set())
    expected = [(loc, f"p{i}") for i, loc in enumerate(locations) if loc in allowed]
    assert [(p.location, p.name) for p in injection_points(op, mutate)] == expected


@bounded
@given(st.lists(names, min_size=1, max_size=5), st.text(max_size=50))
def test_enum_injection_preserves_chosen_prefix_and_exact_payload(enum, payload):
    assert injection_value({"enum": enum}, payload) == enum[0] + payload
    assert injection_value({"type": "string"}, payload) == payload


@bounded
@given(st.text(max_size=50), st.booleans())
def test_prepare_keeps_payload_in_its_sink_and_only_required_siblings(payload, required):
    op = TargetOperation(
        id="op", method="POST", path="/items/{id}", params=[
            {"name": "id", "in": "path", "schema": {"enum": ["owned"]}},
            {"name": "limit", "in": "query", "required": required},
            {"name": "name", "in": "body"},
            {"name": "state", "in": "body", "required": True,
             "schema": {"enum": ["draft"]}},
            {"name": "optional", "in": "body", "required": False},
        ],
    )
    path, query, body = prepare(op, InjectionPoint("body", "name"), payload)
    assert path == "/items/owned"
    assert query == ({"limit": "1"} if required else None)
    assert body == {"name": payload, "state": "draft"}


@bounded
@given(st.sampled_from(["*", "http:", "https:", "'unsafe-inline'", "'unsafe-eval'"]))
def test_csp_script_directive_overrides_default_sources(unsafe):
    def weak(value):
        return [i for i in analyze_headers({"content-security-policy": value})
                if i.header == "content-security-policy"]

    assert not weak(f"default-src {unsafe}; script-src 'self'")
    assert weak(f"default-src 'self'; script-src {unsafe}")
    assert weak("img-src 'self'")  # no script/default constraint


@bounded
@given(st.sampled_from(["same-origin", "same-origin; report-to=group", "same-origin, ignored"]))
def test_hygiene_header_first_directive_is_respected(value):
    assert not [i for i in analyze_headers({"cross-origin-opener-policy": value})
                if i.header == "cross-origin-opener-policy"]


@bounded
@given(st.booleans(), st.sampled_from(["reflected", "wildcard", "null", "trusted", "absent"]))
def test_cors_evidence_and_severity_follow_origin_and_credentials(credentialed, origin):
    headers = {"access-control-allow-credentials": "TRUE" if credentialed else "false"}
    origins = {"reflected": "https://probe.test", "wildcard": "*", "null": "null",
               "trusted": "https://trusted.test"}
    if origin != "absent":
        headers["access-control-allow-origin"] = origins[origin]
    issues = [i for i in analyze_headers(headers, probe_origin="https://probe.test")
              if i.header == "access-control-allow-origin"]
    expected = {
        ("reflected", True): Severity.high, ("reflected", False): Severity.medium,
        ("wildcard", True): Severity.high, ("wildcard", False): Severity.low,
        ("null", True): Severity.medium, ("null", False): Severity.medium,
    }.get((origin, credentialed))
    assert [i.severity for i in issues] == ([] if expected is None else [expected])
    assert all(i.detail and i.observed == origins[origin] for i in issues)


@bounded
@given(st.integers(min_value=0, max_value=MAX_DEPTH + 4))
def test_nested_arrays_count_toward_depth_limit(depth):
    payload = {"password": "sentinel"}
    for _ in range(depth):
        payload = [payload]
    assert bool(sensitive_issues(field_names(payload))) == (depth <= MAX_DEPTH)


@bounded
@given(st.integers(), scalars)
def test_malformed_key_does_not_hide_later_sensitive_fields(key, value):
    payload = {key: value, "has_password": True, "password": "sentinel"}
    assert [i.fields for i in sensitive_issues(field_names(payload))] == [("password",)]
