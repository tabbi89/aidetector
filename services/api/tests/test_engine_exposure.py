"""Excessive data exposure (API3): what a response gives away.

Two halves, and the tests keep them apart on purpose. A sensitive field name is
*present* in the response, so it is verified and needs no confirmation step.
Undeclared fields are drift — a lead — because a stale spec looks exactly like
an over-exposing endpoint from outside.

The scoring is pure (`app/engine/exposure_policy.py`) so most of this needs no
target at all; the engine-level tests run against the in-process vulnerable app.
"""
from __future__ import annotations

from app.domain.enums import Confidence, Severity
from app.engine.base import TargetOperation
from app.engine.checks.data_exposure import DataExposureCheck
from app.engine.exposure_policy import (
    MAX_ARRAY_ITEMS,
    MAX_DEPTH,
    field_names,
    normalise,
    sensitive_issues,
    undeclared_issue,
)
from tests import factories

PROFILE_OP = TargetOperation(
    id="op-profile", method="GET", path="/users/{user_id}", params=[]
)
HEALTH_OP = TargetOperation(id="op-health", method="GET", path="/health", params=[])


# ---- the pure policy -----------------------------------------------------------

def test_field_names_walks_objects_arrays_and_records_paths():
    fields = field_names({"a": 1, "b": {"c": 2}, "items": [{"d": 3}]})
    by_name = {f.name: f.location for f in fields}
    assert by_name["a"] == "a"
    assert by_name["c"] == "b.c"
    assert by_name["d"] == "items[].d"


def test_field_names_is_bounded_by_depth_and_array_width():
    deep = current = {}
    for i in range(MAX_DEPTH + 5):
        current["level"] = {f"leaf{i}": 1}
        current = current["level"]
    names = {f.name for f in field_names(deep)}
    assert f"leaf{MAX_DEPTH + 4}" not in names, "walk should stop at MAX_DEPTH"

    wide = [{f"k{i}": 1} for i in range(MAX_ARRAY_ITEMS + 5)]
    names = {f.name for f in field_names(wide)}
    assert f"k{MAX_ARRAY_ITEMS}" not in names, "only the first items are walked"


def test_field_names_truncated_reports_when_a_bound_cut_the_walk():
    from app.engine.exposure_policy import field_names_truncated

    fields, truncated = field_names_truncated(
        {"id": 1, "owner": {"email": "a@b"}}
    )
    assert not truncated

    wide = [{f"k{i}": 1} for i in range(MAX_ARRAY_ITEMS + 5)]
    _, truncated = field_names_truncated(wide)
    assert truncated, "more array elements than are walked"
    # And a clean response still returns the same names as `field_names`.
    assert field_names_truncated({"a": 1})[0] == field_names({"a": 1})


def test_naming_style_does_not_change_the_verdict():
    assert normalise("password_hash") == normalise("passwordHash") == "passwordhash"
    for spelling in ("password_hash", "passwordHash", "Password-Hash"):
        issues = sensitive_issues(field_names({spelling: "x"}))
        assert [i.key for i in issues] == ["credential"]


def test_sensitive_families_are_recognised_and_ranked():
    issues = sensitive_issues(
        field_names(
            {
                "password_hash": "x",
                "session_token": "x",
                "ssn": "x",
                "internal_owner": "x",
                "id": 1,
            }
        )
    )
    keys = [i.key for i in issues]
    assert keys == ["credential", "token", "government_id", "internal"]
    assert issues[0].severity is Severity.high
    assert issues[-1].severity is Severity.medium


def test_benign_lookalikes_are_not_flagged():
    """`has_password` is a boolean about a password, not a password."""
    payload = {
        "has_password": True,
        "password_changed_at": "2026-01-01",
        "card_last4": "4242",
        "card_brand": "visa",
        "token_type": "bearer",
    }
    assert sensitive_issues(field_names(payload)) == []


def test_values_never_reach_the_issue():
    """The one property that matters: names out, data never."""
    secret = "hunter2-do-not-leak"
    issues = sensitive_issues(field_names({"password": secret, "ssn": secret}))
    assert issues
    for issue in issues:
        assert secret not in " ".join(issue.fields)
        assert secret not in issue.why + issue.label


def test_undeclared_needs_a_declared_schema_to_compare_against():
    fields = field_names({"id": 1, "secret_extra": 2})
    assert undeclared_issue(fields, None) is None, "no contract is not drift"
    assert undeclared_issue(fields, set()) is None
    issue = undeclared_issue(fields, {"id"})
    assert issue is not None and issue.fields == ("secret_extra",)


def test_undeclared_ignores_fields_under_an_opaque_declared_parent():
    """A parent declared with no children leaves its contents alone: the schema
    never said what belongs under ``owner``, so ``owner.undocumented`` is not
    drift."""
    fields = field_names({"id": 1, "owner": {"undocumented": 2}})
    issue = undeclared_issue(fields, {"id", "owner"})
    assert issue is None


def test_undeclared_reports_fields_under_a_described_parent():
    """When the schema spells out a parent's children, an undocumented child is
    drift — nested, not just top level."""
    fields = field_names({"owner": {"id": 1, "secret_extra": 2}})
    issue = undeclared_issue(fields, {"owner", "owner.id"})
    assert issue is not None
    assert issue.fields == ("owner.secret_extra",)


def test_undeclared_treats_case_and_separator_variants_as_declared():
    """passwordHash vs a declared password_hash is one field, not a drift."""
    fields = field_names({"passwordHash": "x"})
    assert undeclared_issue(fields, {"password_hash"}) is None


# ---- the check against the vulnerable app --------------------------------------

def test_leaky_endpoint_is_reported_as_verified():
    findings = factories.run_one(DataExposureCheck(), [PROFILE_OP, HEALTH_OP])
    assert findings, "the profile endpoint leaks credentials and PII"
    creds = [f for f in findings if f.evidence["issue"] == "credential"]
    assert creds
    f = creds[0]
    assert f.owasp_id == "API3:2023"
    assert f.confidence is Confidence.verified
    assert f.severity is Severity.high
    assert "password_hash" in f.evidence["fields"]


def test_the_finding_carries_names_but_no_values():
    findings = factories.run_one(DataExposureCheck(), [PROFILE_OP])
    assert findings
    blob = " ".join(
        [f.title + f.description + str(f.evidence) for f in findings]
    )
    for value in ("$2b$12$abcdefghijklmnopqrstuv", "123-45-6789", "st_live_9f3a",
                  "ak_live_1234", "alice@example.com"):
        assert value not in blob, f"a response value leaked into a finding: {value}"


def test_nested_sensitive_fields_are_found():
    findings = factories.run_one(DataExposureCheck(), [PROFILE_OP])
    names = {n for f in findings for n in f.evidence["fields"]}
    assert "api_key" in names, "the walk should reach nested objects"


def test_a_clean_endpoint_produces_nothing():
    findings = factories.run_one(DataExposureCheck(), [HEALTH_OP])
    assert findings == []


def test_it_costs_no_requests_beyond_the_shared_sweep():
    """The whole point: it reads the header sweep, it does not re-probe."""
    from app.engine.checks.misconfig import SecurityHeadersCheck

    ctx = factories.scan_context([PROFILE_OP, HEALTH_OP])
    factories.run_check(SecurityHeadersCheck(), ctx)
    after_sweep = ctx.probe.count
    assert after_sweep > 0

    factories.run_check(DataExposureCheck(), ctx)
    assert ctx.probe.count == after_sweep


def test_spec_drift_is_a_lead_not_a_confirmation():
    spec = {
        "openapi": "3.0.0",
        "paths": {
            "/users/{user_id}": {
                "get": {
                    "responses": {
                        "200": {
                            "content": {
                                "application/json": {
                                    "schema": {
                                        "type": "object",
                                        "properties": {"id": {"type": "integer"}},
                                    }
                                }
                            }
                        }
                    }
                }
            }
        },
    }
    findings = factories.run_one(DataExposureCheck(), [PROFILE_OP], spec=spec)
    drift = [f for f in findings if f.evidence["issue"] == "undeclared"]
    assert drift, "fields absent from the declared schema should be reported"
    assert drift[0].confidence is Confidence.heuristic
    assert drift[0].severity is Severity.low
    assert "email" in drift[0].evidence["fields"]


def test_nested_spec_drift_is_reported():
    """A parent the schema describes makes an undocumented child drift — nested
    fields are judged too, not only the top level."""
    spec = {
        "openapi": "3.0.0",
        "paths": {
            "/users/{user_id}": {
                "get": {
                    "responses": {
                        "200": {
                            "content": {
                                "application/json": {
                                    "schema": {
                                        "type": "object",
                                        "properties": {
                                            "id": {"type": "integer"},
                                            "nested": {
                                                "type": "object",
                                                "properties": {"id": {"type": "integer"}},
                                            },
                                        },
                                    }
                                }
                            }
                        }
                    }
                }
            }
        },
    }
    findings = factories.run_one(DataExposureCheck(), [PROFILE_OP], spec=spec)
    drift = [f for f in findings if f.evidence["issue"] == "undeclared"]
    assert drift, "nested drift should be reported"
    assert "nested.api_key" in drift[0].evidence["fields"]


def test_no_spec_means_no_drift_finding():
    findings = factories.run_one(DataExposureCheck(), [PROFILE_OP])
    assert not [f for f in findings if f.evidence["issue"] == "undeclared"]


def test_non_json_responses_are_skipped():
    """The check reads JSON field names; HTML is not its business."""
    op = TargetOperation(id="op-debug", method="GET", path="/debug", params=[])
    assert factories.run_one(DataExposureCheck(), [op]) == []


# ---- the spec side -------------------------------------------------------------

def test_declared_response_fields_unwraps_arrays_and_refs():
    from app.specs.parser import declared_response_fields

    spec = {
        "openapi": "3.0.0",
        "components": {
            "schemas": {
                "Account": {
                    "type": "object",
                    "properties": {"id": {"type": "integer"}, "owner": {"type": "string"}},
                }
            }
        },
        "paths": {
            "/accounts": {
                "get": {
                    "responses": {
                        "200": {
                            "content": {
                                "application/json": {
                                    "schema": {
                                        "type": "array",
                                        "items": {"$ref": "#/components/schemas/Account"},
                                    }
                                }
                            }
                        }
                    }
                }
            }
        },
    }
    assert declared_response_fields(spec, "GET", "/accounts") == {"id", "owner"}


def test_declared_response_fields_returns_none_when_undocumented():
    from app.specs.parser import declared_response_fields

    spec = {"openapi": "3.0.0", "paths": {"/a": {"get": {"responses": {"200": {}}}}}}
    assert declared_response_fields(spec, "GET", "/a") is None
    assert declared_response_fields(spec, "POST", "/a") is None
    assert declared_response_fields(spec, "GET", "/missing") is None
    assert declared_response_fields({}, "GET", "/a") is None


def test_declared_response_field_paths_recurses_nested_and_array_shapes():
    from app.specs.parser import declared_response_field_paths

    spec = {
        "openapi": "3.0.0",
        "paths": {
            "/things": {
                "get": {
                    "responses": {
                        "200": {
                            "content": {
                                "application/json": {
                                    "schema": {
                                        "type": "object",
                                        "properties": {
                                            "id": {"type": "integer"},
                                            "owner": {
                                                "type": "object",
                                                "properties": {
                                                    "email": {"type": "string"},
                                                    "opaque": {"type": "object"},
                                                },
                                            },
                                            "items": {
                                                "type": "array",
                                                "items": {
                                                    "type": "object",
                                                    "properties": {"sku": {"type": "string"}},
                                                },
                                            },
                                        },
                                    }
                                }
                            }
                        }
                    }
                }
            }
        },
    }
    assert declared_response_field_paths(spec, "GET", "/things") == {
        "id",
        "owner",
        "owner.email",
        "owner.opaque",
        "items",
        "items[].sku",
    }


def test_evidence_names_the_route_and_what_was_probed():
    """Remediation should point at the handler, not at one rendered URL."""
    findings = factories.run_one(DataExposureCheck(), [PROFILE_OP])
    assert findings
    ev = findings[0].evidence
    assert ev["path"] == "/users/{user_id}"
    assert ev["probed_path"] == "/users/1"


def test_grouping_collapses_endpoints_that_share_an_issue():
    """A uniformly over-exposing API stays one finding per issue family."""
    second = TargetOperation(id="op-user2", method="GET", path="/users/{id}", params=[])
    findings = factories.run_one(DataExposureCheck(), [PROFILE_OP, second])
    creds = [f for f in findings if f.evidence["issue"] == "credential"]
    assert len(creds) == 1
    assert creds[0].evidence["endpoint_count"] == 2
    # Grouped findings are not attributed to a single operation.
    assert creds[0].operation_id is None


# ---- The request trace as a second corpus --------------------------------------
#
# The header sweep is structurally narrow: GET/HEAD only, capped at
# MAX_HEADER_ENDPOINTS, one identity, spec operations only. The trace is every
# call the scan made, so it covers what the sweep cannot — at no extra request,
# because another check already paid for the response.


def _echoing_app():
    from fastapi import FastAPI
    from fastapi.responses import JSONResponse

    app = FastAPI()

    @app.post("/tokens")
    def create_token(body: dict):
        # A create that hands credential material back. GET/HEAD-only sweeping
        # can never see this response.
        return JSONResponse(
            {"id": 1, "access_token": "at_live_x", "refresh_token": "rt_x"}, 201
        )

    @app.get("/ok")
    def ok():
        return {"id": 1}

    return app


def _trace_ctx():
    from fastapi.testclient import TestClient

    from tests import factories

    ops = [
        factories.operation("GET", "/ok", id="op-ok", params=[]),
        factories.operation(
            "POST", "/tokens", id="op-tokens",
            params=[{"name": "label", "in": "body", "schema": {"type": "string"}}],
        ),
    ]
    return factories.scan_context(
        ops, client=TestClient(_echoing_app()), allow_mutation=True
    )


def test_exposure_is_found_in_a_write_response_the_sweep_cannot_reach():
    """A create echoing a token back is invisible to a GET/HEAD sweep."""
    from tests import factories

    ctx = _trace_ctx()
    # Some *other* check makes the write; data_exposure only reads the trace.
    ctx.probe.check_context = "write_authz"
    ctx.probe.send("POST", "/tokens", json={"label": "x"}, headers=ctx.primary_headers())

    findings = factories.run_check(DataExposureCheck(), ctx)

    tokens = [f for f in findings if "token" in f.title.lower()]
    assert tokens, [f.title for f in findings]
    assert set(tokens[0].evidence["fields"]) == {"access_token", "refresh_token"}
    assert tokens[0].confidence is Confidence.verified
    assert tokens[0].evidence["method"] == "POST"


def test_reading_the_trace_costs_no_requests():
    """The whole point: the responses were already paid for by another check."""
    from tests import factories

    ctx = _trace_ctx()
    ctx.probe.check_context = "write_authz"
    ctx.probe.send("POST", "/tokens", json={"label": "x"}, headers=ctx.primary_headers())
    # Warm the sweep so its cost is not attributed to the check under test.
    from app.engine.checks.misconfig import sweep_headers

    sweep_headers(ctx)

    before = ctx.probe.count
    factories.run_check(DataExposureCheck(), ctx)
    assert ctx.probe.count == before


def test_the_finding_names_the_identity_that_saw_the_exposure():
    """An exposure only an admin sees is a different problem from a public one."""
    from tests import factories

    ctx = _trace_ctx()
    ctx.probe.check_context = "write_authz"
    ctx.probe.send("POST", "/tokens", json={"label": "x"}, headers=ctx.primary_headers())

    findings = factories.run_check(DataExposureCheck(), ctx)
    tokens = [f for f in findings if "token" in f.title.lower()]
    assert tokens[0].evidence["identities"] == ["alice"]


def test_detection_survives_the_body_budget_being_spent():
    """Retention is capped; detection is not. The archive's limits must not blind us.

    A response past the run's body budget keeps no text — but the field names
    were read while it was being redacted, so the exposure is still reported.
    """
    from app.core.redact import Redactor
    from app.engine.base import HttpProbe

    probe = HttpProbe(_Recorder(), max_requests=5, redact=Redactor())
    probe._body_spent = 10**9  # budget exhausted

    assert probe.send("GET", "/x") is not None
    response = probe.mutations[0]["response"]
    assert response["body"] == ""
    assert response["body_omitted"] is True
    assert response["sensitive_fields"] == ["password_hash"]


class _Recorder:
    def request(self, method, path, **kwargs):
        import httpx

        return httpx.Response(
            200,
            content=b'{"id":1,"password_hash":"x"}',
            headers={"content-type": "application/json"},
            request=httpx.Request(method, "http://t" + path),
        )
