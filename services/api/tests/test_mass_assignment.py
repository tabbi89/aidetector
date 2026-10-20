"""Mass assignment (API6): a field the client can set that the server should own.

The oracle is the write oracle's, asking a different question — not "did the
wrong identity's write persist" but "did the wrong field's". These tests pin the
three properties that make it safe to run against a real system: it is opt-in,
it writes a canary rather than a real privileged value, and it puts the original
back.
"""
from __future__ import annotations

from app.domain.enums import Confidence, Severity
from app.engine.base import TargetOperation
from app.engine.checks.mass_assignment import (
    MassAssignmentCheck,
    candidate_fields,
    classify,
    declared_body_fields,
    normalise,
)
from tests import factories

# PUT /widgets/{id} declares only `name`; the object also carries `owner` and
# `role`, and the handler binds whatever the body contains.
WRITE = TargetOperation(
    id="op-widget-put",
    method="PUT",
    path="/widgets/{widget_id}",
    params=[
        {"name": "widget_id", "in": "path", "required": True},
        {"name": "name", "in": "body", "required": False, "schema": {"type": "string"}},
    ],
)
READ = TargetOperation(
    id="op-widget-get",
    method="GET",
    path="/widgets/{widget_id}",
    params=[{"name": "widget_id", "in": "path", "required": True}],
)
PAIR = [WRITE, READ]


# ---- the field policy ----------------------------------------------------------

def test_naming_style_does_not_change_the_verdict():
    assert normalise("owner_id") == normalise("ownerId") == "ownerid"
    for spelling in ("owner_id", "ownerId", "Owner-ID"):
        assert classify(spelling) == ("ownership", Severity.high)


def test_families_are_ranked_by_what_they_hand_an_attacker():
    assert classify("role") == ("privilege", Severity.critical)
    assert classify("is_admin") == ("privilege", Severity.critical)
    assert classify("tenant_id") == ("ownership", Severity.high)
    assert classify("balance") == ("state", Severity.high)


def test_ordinary_fields_are_not_server_owned():
    for name in ("name", "title", "description", "colour", "quantity"):
        assert classify(name) is None


def test_a_declared_field_is_not_a_candidate():
    """An API that documents `role` as input has decided to accept it."""
    op = TargetOperation(
        id="x", method="PUT", path="/w/{id}",
        params=[{"name": "role", "in": "body", "required": False}],
    )
    assert declared_body_fields(op) == {"role"}
    assert candidate_fields(op, {"role": "user"}) == []


def test_only_string_fields_are_candidates():
    """There is no non-escalating value to write into a boolean flag."""
    current = {"role": "user", "is_admin": False, "balance": 100}
    names = [name for name, _, _ in candidate_fields(WRITE, current)]
    assert names == ["role"]


def test_candidates_come_back_most_severe_first():
    current = {"owner": "admin", "role": "user", "name": "x"}
    families = [family for _, family, _ in candidate_fields(WRITE, current)]
    assert families[0] == "privilege"


# ---- the check against the vulnerable app --------------------------------------

def test_it_is_opt_in():
    """Like every state-changing probe: nothing happens without mutate:true."""
    ctx = factories.scan_context(PAIR, allow_mutation=False)
    assert factories.run_check(MassAssignmentCheck(), ctx) == []
    assert ctx.probe.count == 0, "an opt-out check must not touch the target"


def test_a_bound_server_owned_field_is_a_verified_finding():
    findings = factories.run_one(MassAssignmentCheck(), PAIR, allow_mutation=True)
    assert findings, "put_widget binds the whole body, including `role`"
    f = findings[0]
    assert f.check == "mass_assignment"
    assert f.owasp_id == "API6:2023"
    assert f.confidence is Confidence.verified
    assert f.severity is Severity.critical      # `role` is a privilege field
    assert f.evidence["field"] == "role"
    assert f.evidence["route"] == "/widgets/{widget_id}"
    assert "name" in f.evidence["declared_body_fields"]


def test_it_writes_a_canary_and_never_a_real_privileged_value():
    """The safety property, asserted on what actually went over the wire.

    Sending `role=admin` would escalate privileges on a live system. Every value
    this check writes into a server-owned field is either a canary or the
    original value being put back.
    """
    from fastapi.testclient import TestClient

    from tests.vulnapp import _WIDGETS, vulnapp

    original = dict(_WIDGETS[1])

    class Recorder:
        """Wraps the client and keeps every JSON body it was asked to send."""

        def __init__(self):
            self._inner = TestClient(vulnapp)
            self.bodies: list[dict] = []

        def request(self, method, url, **kwargs):
            body = kwargs.get("json")
            if isinstance(body, dict):
                self.bodies.append(body)
            return self._inner.request(method, url, **kwargs)

    recorder = Recorder()
    ctx = factories.scan_context(PAIR, client=recorder, allow_mutation=True)
    assert factories.run_check(MassAssignmentCheck(), ctx)

    written = [b for b in recorder.bodies if "role" in b or "owner" in b]
    assert written, "the check should have written a server-owned field"
    for body in written:
        for field in ("role", "owner"):
            if field in body:
                value = body[field]
                assert value.startswith("aidx") or value == original[field], (
                    f"wrote {value!r} into {field!r} — only a canary or the "
                    "original value may ever be written"
                )


def test_the_original_value_is_restored():
    from tests.vulnapp import _WIDGETS

    before = dict(_WIDGETS[1])
    findings = factories.run_one(MassAssignmentCheck(), PAIR, allow_mutation=True)
    assert findings
    assert _WIDGETS[1]["role"] == before["role"]
    assert _WIDGETS[1]["owner"] == before["owner"]
    assert "aidx" not in str(_WIDGETS[1]), "no canary should survive the check"


def test_it_needs_a_read_back_pair():
    """A write with no GET of the same resource cannot be confirmed."""
    findings = factories.run_one(
        MassAssignmentCheck(), [WRITE], allow_mutation=True
    )
    assert findings == []


def test_it_works_with_a_single_credential():
    """Unlike the authz oracles: this is about fields, not identities."""
    creds = factories.two_identities()[:1]
    findings = factories.run_one(
        MassAssignmentCheck(), PAIR, allow_mutation=True, credentials=creds
    )
    assert findings


def test_an_endpoint_that_declares_the_field_produces_nothing():
    write = TargetOperation(
        id="op-declared",
        method="PUT",
        path="/widgets/{widget_id}",
        params=[
            {"name": "widget_id", "in": "path", "required": True},
            {"name": "role", "in": "body", "required": False,
             "schema": {"type": "string"}},
            {"name": "owner", "in": "body", "required": False,
             "schema": {"type": "string"}},
        ],
    )
    findings = factories.run_one(
        MassAssignmentCheck(), [write, READ], allow_mutation=True
    )
    assert findings == []


def test_the_finding_carries_a_fix_and_an_identity():
    from app.engine.fingerprint import fingerprint
    from app.engine.remediation import remediate

    findings = factories.run_one(MassAssignmentCheck(), PAIR, allow_mutation=True)
    f = findings[0]
    text, refs = remediate(f.check, f.evidence)
    assert "/widgets/{widget_id}" in text and "role" in text
    assert refs
    # Identity is the route and the field, neither of which drifts between runs.
    assert fingerprint(f.check, f.owasp_id, f.title, f.evidence) == fingerprint(
        f.check, f.owasp_id, f.title, dict(f.evidence)
    )


# ---- create-time mass assignment ----------------------------------------------

# POST /widgets declares only `name`; create_widget binds the whole body, so an
# undeclared `role` sent at creation is stored and read back.
WIDGET_POST = TargetOperation(
    id="op-widget-post",
    method="POST",
    path="/widgets",
    params=[{"name": "name", "in": "body", "required": False, "schema": {"type": "string"}}],
)
WIDGET_DELETE = TargetOperation(
    id="op-widget-del",
    method="DELETE",
    path="/widgets/{widget_id}",
    params=[{"name": "widget_id", "in": "path", "required": True}],
)
CREATE_PAIR = [WIDGET_POST, READ, WIDGET_DELETE]


def test_create_time_mass_assignment_is_a_verified_finding():
    findings = factories.run_one(MassAssignmentCheck(), CREATE_PAIR, allow_mutation=True)
    assert findings, "create_widget binds an undeclared `role` at creation"
    f = findings[0]
    assert f.check == "mass_assignment"
    assert f.owasp_id == "API6:2023"
    assert f.confidence is Confidence.verified
    assert f.severity is Severity.critical      # `role` is a privilege field
    assert f.evidence["field"] == "role"
    assert f.evidence["route"] == "/widgets"
    assert f.evidence["cleanup"] == "deleted"


def test_create_time_cleans_up_the_object_it_created():
    from tests.vulnapp import _WIDGETS

    before = set(_WIDGETS)
    findings = factories.run_one(MassAssignmentCheck(), CREATE_PAIR, allow_mutation=True)
    assert findings
    # Every object the create probe made was deleted (a DELETE on the item exists).
    assert set(_WIDGETS) == before
    assert "aidx" not in str(_WIDGETS), "no canary should survive the check"


def test_create_time_writes_only_canaries():
    """The safety property on the create path: only canary values go over the wire."""
    from fastapi.testclient import TestClient

    from tests.vulnapp import vulnapp

    class Recorder:
        def __init__(self):
            self._inner = TestClient(vulnapp)
            self.bodies: list[dict] = []

        def request(self, method, url, **kwargs):
            body = kwargs.get("json")
            if isinstance(body, dict):
                self.bodies.append(body)
            return self._inner.request(method, url, **kwargs)

    recorder = Recorder()
    ctx = factories.scan_context(CREATE_PAIR, client=recorder, allow_mutation=True)
    assert factories.run_check(MassAssignmentCheck(), ctx)
    written = [b for b in recorder.bodies if "role" in b]
    assert written
    for body in written:
        assert str(body["role"]).startswith("aidx"), "only a canary may be written"


def test_create_time_skips_a_declared_field():
    """A create op that documents `role` as input has decided to accept it."""
    post_declaring_role = TargetOperation(
        id="op-widget-post-role",
        method="POST",
        path="/widgets",
        params=[
            {"name": "name", "in": "body", "required": False, "schema": {"type": "string"}},
            {"name": "role", "in": "body", "required": False, "schema": {"type": "string"}},
        ],
    )
    findings = factories.run_one(
        MassAssignmentCheck(), [post_declaring_role, READ, WIDGET_DELETE], allow_mutation=True
    )
    # `role` is declared, so it is skipped as documented input — the check moves
    # on to other shortlist names (the widget store binds those too) but never
    # flags the field the API explicitly accepts.
    assert findings, "the store binds other server-owned names from the shortlist"
    assert all(f.evidence["field"] != "role" for f in findings)


# ---- multi-hop: create-time mass assignment reaches a nested resource ----------

PROJ_POST_MA = TargetOperation(
    id="p-post", method="POST", path="/projects",
    params=[{"name": "name", "in": "body", "required": False, "schema": {"type": "string"}}],
)
PROJ_DELETE_MA = TargetOperation(
    id="p-del", method="DELETE", path="/projects/{project_id}",
    params=[{"name": "project_id", "in": "path", "required": True}],
)
ITEM_POST_MA = TargetOperation(
    id="i-post", method="POST", path="/projects/{project_id}/items",
    params=[
        {"name": "project_id", "in": "path", "required": True},
        {"name": "body", "in": "body", "required": False, "schema": {"type": "string"}},
    ],
)
ITEM_GET_MA = TargetOperation(
    id="i-get", method="GET", path="/projects/{project_id}/items/{item_id}",
    params=[
        {"name": "project_id", "in": "path", "required": True},
        {"name": "item_id", "in": "path", "required": True},
    ],
)
ITEM_DELETE_MA = TargetOperation(
    id="i-del", method="DELETE", path="/projects/{project_id}/items/{item_id}",
    params=[
        {"name": "project_id", "in": "path", "required": True},
        {"name": "item_id", "in": "path", "required": True},
    ],
)
NESTED_MA = [PROJ_POST_MA, PROJ_DELETE_MA, ITEM_POST_MA, ITEM_GET_MA, ITEM_DELETE_MA]


def test_create_time_mass_assignment_reaches_a_nested_resource():
    from tests.vulnapp import _PROJECT_ITEMS, _PROJECTS

    findings = factories.run_one(MassAssignmentCheck(), NESTED_MA, allow_mutation=True)
    assert findings, "the nested item create binds an undeclared server-owned field"
    routes = {f.evidence["route"] for f in findings}
    assert routes == {"/projects/{project_id}/items"}
    assert any(f.evidence["field"] == "role" and f.severity is Severity.critical for f in findings)
    # The seeded parent and every created child were cleaned up.
    assert not _PROJECTS and not _PROJECT_ITEMS


def test_nested_create_mass_assignment_skips_without_a_parent_producer():
    findings = factories.run_one(
        MassAssignmentCheck(), [ITEM_POST_MA, ITEM_GET_MA, ITEM_DELETE_MA], allow_mutation=True
    )
    assert findings == []
