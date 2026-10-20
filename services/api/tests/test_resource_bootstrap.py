from __future__ import annotations

from types import SimpleNamespace

from app.domain.enums import AuthType
from app.engine import resource_bootstrap
from app.engine.base import HttpProbe, ResolvedCredential, ScanContext, TargetOperation
from app.engine.resource_bootstrap import provision
from app.engine.runner import _cleanup_provisioned_resources


class RecordingClient:
    def __init__(self) -> None:
        self.requests: list[dict] = []

    def request(self, method: str, url: str, **kwargs):
        self.requests.append({"method": method, "url": url, **kwargs})
        if method == "POST" and url == "/v1/merchants":
            return SimpleNamespace(
                status_code=201,
                headers={},
                text='{"id":"merchant-42"}',
                content=b'{"id":"merchant-42"}',
            )
        if method == "GET" and url == "/v1/merchants/merchant-42":
            return SimpleNamespace(
                status_code=200,
                headers={},
                text='{"id":"merchant-42"}',
                content=b'{"id":"merchant-42"}',
            )
        return SimpleNamespace(status_code=200, headers={}, text="[]", content=b"[]")


def test_provision_creates_a_valid_top_level_resource_for_dependent_reads():
    operations = [
        TargetOperation(
            id="create-merchant", method="POST", path="/v1/merchants",
            params=[{"name": "email", "in": "body", "schema": {"type": "string"}}],
        ),
        TargetOperation(
            id="get-merchant", method="GET", path="/v1/merchants/{merchant_id}",
            params=[{"name": "merchant_id", "in": "path", "required": True}],
        ),
        TargetOperation(
            id="get-statements", method="GET", path="/v1/statements/{merchantId}",
            params=[{"name": "merchantId", "in": "path", "required": True}],
        ),
    ]
    client = RecordingClient()
    credential = ResolvedCredential("admin", "admin", AuthType.header, "Authorization", "token")
    probe = HttpProbe(client, operations=operations, credentials=[credential], max_requests=10)
    ctx = ScanContext(
        base_url="http://target", operations=operations, credentials=[credential], probe=probe,
        allow_mutation=True,
    )

    notes = provision(ctx)

    assert ctx.resource_ids == {"merchant": "merchant-42"}
    assert any("created and verified merchant resource" in note for note in notes)
    assert any("no DELETE endpoint" in note for note in notes)
    assert ctx.cleanup_failures == []
    assert ctx.created_resources == [
        {
            "resource": "merchant",
            "create_method": "POST",
            "create_path": "/v1/merchants",
            "read_method": "GET",
            "read_path": "/v1/merchants/{merchant_id}",
            "status": "verified",
            "via_ai": False,
            "cleanup": "none",
            "source": "deterministic",
            "attempts": [{"number": 1, "source": "deterministic", "status": 201}],
        }
    ]
    assert [request["url"] for request in client.requests[:2]] == [
        "/v1/merchants",
        "/v1/merchants/merchant-42",
    ]
    assert client.requests[0]["json"]["email"].endswith("@example.invalid")


def test_provision_resolves_a_bare_id_item_route_to_its_collection():
    """``/merchants/{id}`` names a merchant by the segment before it."""
    operations = [
        TargetOperation(
            id="create-merchant", method="POST", path="/v1/merchants",
            params=[{"name": "email", "in": "body", "schema": {"type": "string"}}],
        ),
        TargetOperation(
            id="get-merchant", method="GET", path="/v1/merchants/{id}",
            params=[{"name": "id", "in": "path", "required": True}],
        ),
    ]
    client = RecordingClient()
    credential = ResolvedCredential("admin", "admin", AuthType.header, "Authorization", "token")
    probe = HttpProbe(client, operations=operations, credentials=[credential], max_requests=10)
    ctx = ScanContext(
        base_url="http://target", operations=operations, credentials=[credential], probe=probe,
        allow_mutation=True,
    )

    notes = provision(ctx)

    assert ctx.resource_ids == {"merchant": "merchant-42"}
    assert any("created and verified merchant resource" in note for note in notes)
    assert [request["url"] for request in client.requests[:2]] == [
        "/v1/merchants",
        "/v1/merchants/merchant-42",
    ]


def test_a_predefined_bare_id_is_used_without_writing():
    operations = [
        TargetOperation(
            id="create-merchant", method="POST", path="/v1/merchants",
            params=[{"name": "email", "in": "body", "schema": {"type": "string"}}],
        ),
        TargetOperation(
            id="get-merchant", method="GET", path="/v1/merchants/{id}",
            params=[{"name": "id", "in": "path", "required": True}],
        ),
    ]
    client = RecordingClient()
    credential = ResolvedCredential("admin", "admin", AuthType.header, "Authorization", "token")
    probe = HttpProbe(client, operations=operations, credentials=[credential], max_requests=10)
    ctx = ScanContext(
        base_url="http://target", operations=operations, credentials=[credential], probe=probe,
        allow_mutation=True, predefined_resource_ids={"id": "existing-7"},
    )

    provision(ctx)

    assert ctx.resource_ids == {"id": "existing-7"}
    assert client.requests == []


def test_provision_creates_for_dependent_endpoint_without_item_read_back():
    operations = [
        TargetOperation(
            id="create-merchant", method="POST", path="/v1/merchants",
            params=[{"name": "email", "in": "body", "schema": {"type": "string"}}],
        ),
        TargetOperation(
            id="get-approval", method="GET", path="/v1/merchants/{merchant_id}/approval_status",
            params=[{"name": "merchant_id", "in": "path", "required": True}],
        ),
    ]
    client = RecordingClient()
    credential = ResolvedCredential("admin", "admin", AuthType.header, "Authorization", "token")
    probe = HttpProbe(client, operations=operations, credentials=[credential], max_requests=10)
    ctx = ScanContext(
        base_url="http://target", operations=operations, credentials=[credential],
        probe=probe, allow_mutation=True,
    )

    notes = provision(ctx)

    assert ctx.resource_ids == {"merchant": "merchant-42"}
    assert any("no matching item read-back endpoint was selected" in n for n in notes)
    assert ctx.created_resources == [
        {
            "resource": "merchant",
            "create_method": "POST",
            "create_path": "/v1/merchants",
            "read_method": "",
            "read_path": "",
            "status": "created",
            "via_ai": False,
            "cleanup": "none",
            "source": "deterministic",
            "attempts": [{"number": 1, "source": "deterministic", "status": 201}],
        }
    ]
    assert [request["url"] for request in client.requests] == ["/v1/merchants"]


def test_provision_creates_for_dependent_patch_without_item_get():
    operations = [
        TargetOperation(
            id="create-merchant", method="POST", path="/v1/merchants",
            params=[{"name": "email", "in": "body", "schema": {"type": "string"}}],
        ),
        TargetOperation(
            id="list-merchants", method="GET", path="/v1/merchants", params=[],
        ),
        TargetOperation(
            id="patch-merchant", method="PATCH", path="/v1/merchants/{merchant_id}",
            params=[
                {"name": "merchant_id", "in": "path", "required": True},
                {"name": "name", "in": "body", "schema": {"type": "string"}},
            ],
        ),
    ]
    client = RecordingClient()
    credential = ResolvedCredential("admin", "admin", AuthType.header, "Authorization", "token")
    probe = HttpProbe(client, operations=operations, credentials=[credential], max_requests=10)
    ctx = ScanContext(
        base_url="http://target", operations=operations, credentials=[credential],
        probe=probe, allow_mutation=True,
    )

    notes = provision(ctx)

    assert ctx.resource_ids == {"merchant": "merchant-42"}
    assert any("created merchant resource for dependent operations" in note for note in notes)
    assert [request["url"] for request in client.requests] == ["/v1/merchants"]


def test_provision_uses_a_predefined_id_without_writing():
    operations = [
        TargetOperation(
            id="patch-merchant", method="PATCH", path="/v1/merchants/{merchant_id}",
            params=[{"name": "merchant_id", "in": "path", "required": True}],
        )
    ]
    client = RecordingClient()
    probe = HttpProbe(client, operations=operations, max_requests=10)
    ctx = ScanContext(
        base_url="http://target", operations=operations, credentials=[], probe=probe,
        predefined_resource_ids={"merchant_id": "existing-merchant-7"},
    )

    notes = provision(ctx)

    assert ctx.resource_ids == {"merchant": "existing-merchant-7"}
    assert client.requests == []
    assert ctx.created_resources == [
        {
            "resource": "merchant",
            "create_method": "",
            "create_path": "",
            "read_method": "",
            "read_path": "",
            "status": "provided",
            "via_ai": False,
            "cleanup": "not_needed",
            "source": "predefined",
            "attempts": [],
        }
    ]
    assert any("predefined 'merchant'" in note for note in notes)


def test_provision_builds_nested_required_body_from_the_full_schema():
    spec = {
        "paths": {
            "/v1/merchants": {
                "post": {
                    "requestBody": {
                        "content": {
                            "application/json": {
                                "schema": {"$ref": "#/components/schemas/CreateMerchantRequestDto"}
                            }
                        }
                    }
                }
            }
        },
        "components": {
            "schemas": {
                "CreateMerchantRequestDto": {
                    "type": "object",
                    "required": [],
                    "properties": {
                        "email": {"type": "string"},
                        "merchant": {"$ref": "#/components/schemas/Merchant"},
                        "device": {"$ref": "#/components/schemas/Device"},
                    },
                },
                "Merchant": {
                    "type": "object",
                    "required": ["bank_account", "tin", "owner_one"],
                    "properties": {
                        "bank_account": {"$ref": "#/components/schemas/BankAccount"},
                        "tin": {"type": "string"},
                        "owner_one": {"$ref": "#/components/schemas/Owner"},
                    },
                },
                "BankAccount": {
                    "type": "object",
                    "required": ["routing_number", "account_number"],
                    "properties": {
                        "routing_number": {"type": "string"},
                        "account_number": {"type": "string"},
                    },
                },
                "Owner": {
                    "type": "object",
                    "required": ["first_name", "ssn"],
                    "properties": {
                        "first_name": {"type": "string"},
                        "ssn": {"type": "string"},
                    },
                },
                "Device": {
                    "type": "object",
                    "required": ["imei"],
                    "properties": {"imei": {"type": "string"}},
                },
            }
        },
    }
    operations = [
        TargetOperation(
            id="create-merchant", method="POST", path="/v1/merchants",
            params=[
                {"name": "email", "in": "body", "schema": {"type": "string"}},
                {"name": "merchant", "in": "body"},
                {"name": "device", "in": "body"},
            ],
        ),
        TargetOperation(
            id="get-merchant", method="GET", path="/v1/merchants/{merchant_id}",
            params=[{"name": "merchant_id", "in": "path", "required": True}],
        ),
    ]
    client = RecordingClient()
    credential = ResolvedCredential("admin", "admin", AuthType.header, "Authorization", "token")
    probe = HttpProbe(client, operations=operations, credentials=[credential], max_requests=10)
    ctx = ScanContext(
        base_url="http://target", operations=operations, credentials=[credential],
        probe=probe, allow_mutation=True, spec=spec,
    )

    provision(ctx)

    body = client.requests[0]["json"]
    assert body["email"].endswith("@example.invalid")
    assert body["merchant"]["tin"] == "123456789"
    assert body["merchant"]["bank_account"]["routing_number"] == "021000021"
    assert body["merchant"]["owner_one"]["ssn"] == "123-45-6789"
    assert body["device"]["imei"] == "123456789012345"
    assert ctx.resource_ids == {"merchant": "merchant-42"}


def test_created_resource_cleanup_status_is_archived():
    operations = [
        TargetOperation(
            id="create-merchant", method="POST", path="/v1/merchants",
            params=[{"name": "email", "in": "body", "schema": {"type": "string"}}],
        ),
        TargetOperation(
            id="get-merchant", method="GET", path="/v1/merchants/{merchant_id}",
            params=[{"name": "merchant_id", "in": "path", "required": True}],
        ),
        TargetOperation(
            id="delete-merchant", method="DELETE", path="/v1/merchants/{merchant_id}",
            params=[{"name": "merchant_id", "in": "path", "required": True}],
        ),
    ]
    client = RecordingClient()
    credential = ResolvedCredential("admin", "admin", AuthType.header, "Authorization", "token")
    probe = HttpProbe(client, operations=operations, credentials=[credential], max_requests=10)
    ctx = ScanContext(
        base_url="http://target", operations=operations, credentials=[credential],
        probe=probe, allow_mutation=True,
    )
    journal = SimpleNamespace(run_row=SimpleNamespace(resources=[]))

    provision(ctx)
    assert ctx.created_resources[0]["cleanup"] == "queued"
    _cleanup_provisioned_resources(ctx, journal)

    assert ctx.created_resources[0]["cleanup"] == "deleted"
    assert journal.run_row.resources[0]["cleanup"] == "deleted"
    assert any(row["method"] == "DELETE" for row in probe.mutations)


# ---- Pathological specs -------------------------------------------------------
#
# Every case here is a shape real OpenAPI documents contain and an earlier
# builder crashed or mis-typed on. Resource setup is wrapped in a blanket
# ``except`` by the runner, so a crash does not fail a scan — it silently
# disables the pass for *every* resource and reports "resource setup
# unavailable". These assert it stays enabled instead.


def _build(schema, spec=None):
    from app.engine.resource_bootstrap import _value_from_schema

    return _value_from_schema(schema, spec if spec is not None else {}, "abc123")


def test_free_form_object_yields_an_object_not_a_crash():
    """``type: object`` with no properties declares no fields to fill."""
    assert _build({"type": "object"}) == {}
    assert _build({"type": "object", "additionalProperties": True}) == {}


def test_self_referential_schema_terminates():
    """A tree node whose child is a tree node is ordinary, not pathological."""
    spec = {
        "components": {
            "schemas": {
                "Node": {
                    "type": "object",
                    "required": ["child", "label"],
                    "properties": {
                        "child": {"$ref": "#/components/schemas/Node"},
                        "label": {"type": "string"},
                    },
                }
            }
        }
    }
    built = _build({"$ref": "#/components/schemas/Node"}, spec)
    assert built["label"]
    # The cycle stops rather than recursing: the child is present but empty.
    assert built["child"] == {}


def test_mutually_recursive_schemas_terminate():
    spec = {
        "components": {
            "schemas": {
                "A": {"type": "object", "required": ["b"],
                      "properties": {"b": {"$ref": "#/components/schemas/B"}}},
                "B": {"type": "object", "required": ["a"],
                      "properties": {"a": {"$ref": "#/components/schemas/A"}}},
            }
        }
    }
    assert _build({"$ref": "#/components/schemas/A"}, spec) == {"b": {"a": {}}}


def test_allof_composition_builds_an_object_not_a_string():
    """``allOf`` is how OpenAPI 3.0 spells inheritance — the common case."""
    spec = {
        "components": {
            "schemas": {
                "Base": {"type": "object", "required": ["id"],
                         "properties": {"id": {"type": "string"}}},
                "Extra": {"type": "object", "required": ["ssn"],
                          "properties": {"ssn": {"type": "string"}}},
            }
        }
    }
    built = _build(
        {"allOf": [{"$ref": "#/components/schemas/Base"},
                   {"$ref": "#/components/schemas/Extra"}]},
        spec,
    )
    assert isinstance(built, dict)
    assert built["ssn"] == "123-45-6789"
    assert built["id"]


def test_oneof_takes_the_first_branch():
    built = _build({"oneOf": [
        {"type": "object", "required": ["a"], "properties": {"a": {"type": "string"}}},
        {"type": "object", "required": ["b"], "properties": {"b": {"type": "string"}}},
    ]})
    assert set(built) == {"a"}


def test_unresolvable_ref_degrades_to_a_value():
    assert isinstance(_build({"$ref": "#/components/schemas/Missing"}, {}), str)
    # A remote ref is never fetched from here.
    assert isinstance(_build({"$ref": "https://example.com/s.json#/Thing"}, {}), str)


def test_depth_is_bounded():
    """A spec nested past the limit stops rather than building forever."""
    schema: dict = {"type": "string"}
    for _ in range(40):
        schema = {"type": "object", "required": ["n"], "properties": {"n": schema}}
    built = _build(schema)
    depth = 0
    node = built
    while isinstance(node, dict) and "n" in node:
        depth += 1
        node = node["n"]
    assert depth <= 10


def test_one_broken_resource_does_not_disable_setup_for_the_others():
    """Per-resource isolation: the pass reports the failure and carries on."""
    from unittest.mock import patch

    operations = [
        TargetOperation(id="c-a", method="POST", path="/alphas", params=[
            {"name": "label", "in": "body", "schema": {"type": "string"}}]),
        TargetOperation(id="g-a", method="GET", path="/alphas/{alpha_id}",
                        params=[{"name": "alpha_id", "in": "path", "required": True}]),
        TargetOperation(id="c-b", method="POST", path="/betas", params=[
            {"name": "label", "in": "body", "schema": {"type": "string"}}]),
        TargetOperation(id="g-b", method="GET", path="/betas/{beta_id}",
                        params=[{"name": "beta_id", "in": "path", "required": True}]),
    ]

    class Creating(RecordingClient):
        def request(self, method, url, **kwargs):
            super().request(method, url, **kwargs)
            if method == "POST":
                return SimpleNamespace(status_code=201, headers={},
                                       text='{"id":"x-1"}', content=b'{"id":"x-1"}')
            return SimpleNamespace(status_code=200, headers={},
                                   text='{"id":"x-1"}', content=b'{"id":"x-1"}')

    client = Creating()
    credential = ResolvedCredential("admin", "admin", AuthType.header, "Authorization", "token")
    ctx = ScanContext(
        base_url="http://target", operations=operations, credentials=[credential],
        probe=HttpProbe(client, operations=operations, credentials=[credential],
                        max_requests=20),
        allow_mutation=True,
    )

    real = resource_bootstrap._body

    def explode_on_alpha(producer, spec=None, target_base_url=None):
        if producer.path == "/alphas":
            raise RecursionError("cyclic schema")
        return real(producer, spec, target_base_url)

    with patch.object(resource_bootstrap, "_body", explode_on_alpha):
        notes = provision(ctx)

    assert any("alpha" in n and "failed" in n for n in notes), notes
    # The other resource was still provisioned.
    assert "beta" in ctx.resource_ids


def test_refs_are_followed_by_json_pointer_not_by_last_segment():
    """Two schemas named alike in different sections must not be confused.

    Taking the last path segment of a ``$ref`` makes ``#/components/schemas/Item``
    and ``#/components/responses/Item`` the same thing.
    """
    from app.engine.request_bodies import _resolve_ref

    spec = {
        "components": {
            "schemas": {"Item": {"type": "object", "properties": {"a": {}}}},
            "responses": {"Item": {"type": "object", "properties": {"b": {}}}},
        }
    }
    assert _resolve_ref("#/components/schemas/Item", spec) == {
        "type": "object", "properties": {"a": {}}
    }
    assert _resolve_ref("#/components/responses/Item", spec) == {
        "type": "object", "properties": {"b": {}}
    }


def test_ref_pointer_escapes_are_decoded():
    """``~1`` is ``/`` and ``~0`` is ``~`` — a path with a slash in its key."""
    from app.engine.request_bodies import _resolve_ref

    spec = {"paths": {"/a/b": {"x": {"type": "string"}}}}
    assert _resolve_ref("#/paths/~1a~1b/x", spec) == {"type": "string"}


def test_a_remote_ref_is_never_fetched_from_the_body_builder():
    """Fetching a spec-supplied URL is spec-driven SSRF; that path is elsewhere."""
    from app.engine.request_bodies import _resolve_ref

    assert _resolve_ref("https://example.com/s.json#/Thing", {}) is None
    assert _resolve_ref("Thing", {}) is None


def test_a_ref_into_a_non_object_is_not_a_schema():
    from app.engine.request_bodies import _resolve_ref

    spec = {"components": {"schemas": {"Item": 7}}}
    assert _resolve_ref("#/components/schemas/Item", spec) is None
    assert _resolve_ref("#/nope/missing", {}) is None


def test_predefined_ids_named_after_bare_id_collections_reach_their_routes():
    """The web editor names a bare ``{id}`` after its collection (``monitor_id``)."""
    from app.engine.resource_map import path_values

    operations = [
        TargetOperation(
            id=f"get-{name}", method="GET", path=f"/{name}s/{{id}}",
            params=[{"name": "id", "in": "path", "required": True}],
        )
        for name in ("monitor", "incident")
    ]
    client = RecordingClient()
    credential = ResolvedCredential("admin", "admin", AuthType.header, "Authorization", "token")
    probe = HttpProbe(client, operations=operations, credentials=[credential], max_requests=10)
    ctx = ScanContext(
        base_url="http://target", operations=operations, credentials=[credential], probe=probe,
        predefined_resource_ids={"monitor_id": "m-1", "incident_id": "i-2"},
    )

    provision(ctx)

    assert [path_values(op, ctx.resource_ids) for op in operations] == [
        {"id": "m-1"},
        {"id": "i-2"},
    ]
    assert client.requests == []


def test_a_predefined_id_is_stored_under_the_key_routes_read_it_by():
    """Setup and rendering share one key function, so a name ending in "ss"
    (``address_id``, a bare ``{id}`` under ``/address``) is not stored as
    "address" and then read back as "addre"."""
    from app.engine.resource_map import path_values

    operations = [
        TargetOperation(
            id="get-named", method="GET", path="/addresses/{address_id}",
            params=[{"name": "address_id", "in": "path", "required": True}],
        ),
        TargetOperation(
            id="get-bare", method="GET", path="/access/{id}",
            params=[{"name": "id", "in": "path", "required": True}],
        ),
    ]
    client = RecordingClient()
    credential = ResolvedCredential("admin", "admin", AuthType.header, "Authorization", "token")
    probe = HttpProbe(client, operations=operations, credentials=[credential], max_requests=10)
    ctx = ScanContext(
        base_url="http://target", operations=operations, credentials=[credential], probe=probe,
        predefined_resource_ids={"address_id": "a-1", "acce_id": "x-2"},
    )

    provision(ctx)

    assert [path_values(op, ctx.resource_ids) for op in operations] == [
        {"address_id": "a-1"},
        {"id": "x-2"},
    ]
    assert client.requests == []


def test_provision_creates_as_the_most_privileged_identity_not_the_first_listed():
    # A read-only key listed first answered every create with 403 ("This API key
    # can only read"), so no fixture was ever made and the dependent checks had
    # nothing to work against.
    operations = [
        TargetOperation(
            id="create-merchant", method="POST", path="/v1/merchants",
            params=[{"name": "email", "in": "body", "schema": {"type": "string"}}],
        ),
        TargetOperation(
            id="get-merchant", method="GET", path="/v1/merchants/{merchant_id}",
            params=[{"name": "merchant_id", "in": "path", "required": True}],
        ),
    ]
    client = RecordingClient()
    reader = ResolvedCredential("reader", "viewer", AuthType.header, "Authorization", "read-key")
    writer = ResolvedCredential("writer", "editor", AuthType.header, "Authorization", "write-key")
    probe = HttpProbe(
        client, operations=operations, credentials=[reader, writer], max_requests=10
    )
    ctx = ScanContext(
        base_url="http://target", operations=operations, credentials=[reader, writer],
        probe=probe, allow_mutation=True,
    )

    provision(ctx)

    [create] = [r for r in client.requests if r["method"] == "POST"]
    assert create["headers"]["Authorization"] == "write-key"
    assert ctx.resource_ids == {"merchant": "merchant-42"}


def test_create_body_keeps_required_fields_beside_allof_and_unwraps_scalars():
    # A create DTO that reuses the update one (allOf) and adds `required` beside
    # it, with an enum field wrapped in allOf only to carry a description. The
    # builder once dropped both required fields and sent an invented `kind`, so
    # the create was refused ("Choose an HTTP, TCP, … monitor").
    spec = {
        "openapi": "3.1.0",
        "paths": {"/monitors": {"post": {"requestBody": {"content": {"application/json": {
            "schema": {"$ref": "#/components/schemas/MonitorCreate"}}}}}}},
        "components": {"schemas": {
            "MonitorKind": {"type": "string", "enum": ["http", "tcp"]},
            "MonitorInput": {
                "type": "object",
                "additionalProperties": False,
                "properties": {
                    "name": {"type": "string", "minLength": 1},
                    "url": {"type": "string"},
                    "kind": {"allOf": [{"$ref": "#/components/schemas/MonitorKind"}],
                             "description": "`http` when left out."},
                    "slow_threshold_ms": {"type": "integer", "anyOf": [
                        {"const": 0}, {"minimum": 100, "maximum": 10000}]},
                },
            },
            "MonitorCreate": {"allOf": [{"$ref": "#/components/schemas/MonitorInput"}],
                              "required": ["name", "url"]},
        }},
    }
    schema = spec["paths"]["/monitors"]["post"]["requestBody"]["content"][
        "application/json"]["schema"]

    body = resource_bootstrap._value_from_schema(schema, spec, "seed1234")

    # Optional scalars are left to the target's defaults: an invented
    # `slow_threshold_ms` of 1 was refused ("between 100 and 10000 ms").
    assert set(body) == {"name", "url"}
    # A required one takes a branch's value, and keeps the outer type.
    spec["components"]["schemas"]["MonitorCreate"]["required"] = [
        "name", "url", "kind", "slow_threshold_ms"]
    body = resource_bootstrap._value_from_schema(schema, spec, "seed1234")
    assert body["kind"] == "http"
    assert body["slow_threshold_ms"] == 0
