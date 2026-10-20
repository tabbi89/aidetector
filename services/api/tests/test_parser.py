"""Unit tests for the OpenAPI/Swagger parser — no DB required."""
from __future__ import annotations

import json

import pytest

from app.specs.parser import (
    SpecError,
    join_route,
    load_spec,
    parse_operations,
    recompose_route,
    route_prefixes,
    routing_warnings,
    spec_operation,
)

OPENAPI3 = {
    "openapi": "3.0.0",
    "info": {"title": "t", "version": "1"},
    "security": [{"bearerAuth": []}],
    "paths": {
        "/users/{id}": {
            "parameters": [{"name": "id", "in": "path", "required": True}],
            "get": {"responses": {"200": {"description": "ok"}}},
            "delete": {"security": [{"adminAuth": []}]},
        },
        "/search": {
            "get": {"parameters": [{"name": "q", "in": "query"}]},
        },
    },
}

SWAGGER2 = {
    "swagger": "2.0",
    "info": {"title": "t", "version": "1"},
    "paths": {"/ping": {"get": {"responses": {"200": {"description": "ok"}}}}},
}


def test_parse_openapi3_flattens_methods_and_params():
    ops = parse_operations(OPENAPI3)
    assert len(ops) == 3
    by_key = {(o.method, o.path) for o in ops}
    assert ("GET", "/users/{id}") in by_key
    assert ("DELETE", "/users/{id}") in by_key
    assert ("GET", "/search") in by_key

    get_user = next(o for o in ops if o.method == "GET" and o.path == "/users/{id}")
    assert {p["name"] for p in get_user.params} == {"id"}
    assert get_user.auth_scope == "bearerAuth"  # inherits global security

    delete_user = next(o for o in ops if o.method == "DELETE")
    assert delete_user.auth_scope == "adminAuth"  # operation overrides global


def test_parse_swagger2():
    ops = parse_operations(SWAGGER2)
    assert [(o.method, o.path) for o in ops] == [("GET", "/ping")]


def test_server_and_base_path_prefix_operations_once():
    openapi = {
        "openapi": "3.0.0",
        "servers": [{"url": "https://api.example.test/v2"}],
        "paths": {"/users": {"get": {}}},
    }
    assert parse_operations(openapi)[0].path == "/v2/users"
    assert parse_operations(
        openapi, target_base_url="https://api.example.test/v2"
    )[0].path == "/users"

    swagger = {
        "swagger": "2.0",
        "basePath": "/api/v1",
        "paths": {"/users": {"get": {}}},
    }
    assert parse_operations(swagger)[0].path == "/api/v1/users"


def test_target_prefix_is_removed_from_a_longer_spec_server_path():
    spec = {
        "openapi": "3.0.0",
        "servers": [{"url": "https://api.example.test/api/v2"}],
        "paths": {"/users": {"get": {}}},
    }
    operations = parse_operations(
        spec, target_base_url="https://api.example.test/api"
    )
    assert operations[0].path == "/v2/users"


def test_unrelated_target_and_server_paths_emit_a_composition_warning():
    spec = {
        "openapi": "3.0.0",
        "servers": [{"url": "https://api.example.test/v2"}],
        "paths": {"/users": {"get": {}}},
    }
    assert routing_warnings(spec, "https://api.example.test/gateway") == [
        "target base path '/gateway' and spec server path '/v2' do not overlap; "
        "requests will be composed under '/gateway/v2'"
    ]


def test_operation_server_overrides_root_server():
    spec = {
        "openapi": "3.0.0",
        "servers": [{"url": "https://api.example.test/v1"}],
        "paths": {
            "/reports": {
                "get": {"servers": [{"url": "https://api.example.test/v3"}]}
            }
        },
    }
    assert parse_operations(spec)[0].path == "/v3/reports"


@pytest.mark.parametrize(
    "path",
    ["http://169.254.169.254/latest/meta-data", "//169.254.169.254/latest"],
)
def test_operation_paths_must_be_origin_relative(path):
    with pytest.raises(SpecError, match="origin-relative"):
        parse_operations({"openapi": "3.0.0", "paths": {path: {"get": {}}}})


def test_oauth_scopes_survive_parsing_for_privilege_checks():
    spec = {
        "openapi": "3.0.0",
        "paths": {
            "/reports": {
                "post": {"security": [{"oauth2": ["admin:write"]}]}
            }
        },
    }
    assert parse_operations(spec)[0].auth_scope == "oauth2, admin:write"


def test_load_spec_accepts_json_and_yaml():
    assert load_spec(json.dumps(OPENAPI3))["openapi"] == "3.0.0"
    yaml_text = "openapi: 3.0.0\npaths:\n  /p:\n    get: {}\n"
    assert load_spec(yaml_text)["openapi"] == "3.0.0"


def test_missing_version_raises():
    with pytest.raises(SpecError, match="version"):
        parse_operations({"paths": {"/x": {"get": {}}}})


def test_no_paths_raises():
    with pytest.raises(SpecError, match="paths"):
        parse_operations({"openapi": "3.0.0", "paths": {}})


def test_garbage_raises():
    with pytest.raises(SpecError):
        load_spec("]{not valid[")


def test_openapi3_request_body_fields_become_body_params():
    spec = {
        "openapi": "3.0.0",
        "paths": {
            "/users": {
                "post": {
                    "requestBody": {
                        "content": {
                            "application/json": {
                                "schema": {
                                    "type": "object",
                                    "required": ["email"],
                                    "properties": {
                                        "email": {"type": "string"},
                                        "name": {"type": "string"},
                                    },
                                }
                            }
                        }
                    }
                }
            }
        },
    }
    ops = parse_operations(spec)
    body = [p for p in ops[0].params if p["in"] == "body"]
    names = {p["name"] for p in body}
    assert names == {"email", "name"}
    assert next(p for p in body if p["name"] == "email")["required"] is True


def test_param_schema_facts_are_retained():
    spec = {
        "openapi": "3.0.0",
        "paths": {
            "/merchants": {
                "get": {
                    "parameters": [
                        {
                            "name": "status",
                            "in": "query",
                            "schema": {"type": "string", "enum": ["active", "closed"]},
                        },
                        {"name": "limit", "in": "query", "schema": {"type": "integer"}},
                    ]
                }
            }
        },
    }
    ops = parse_operations(spec)
    by_name = {p["name"]: p for p in ops[0].params}
    assert by_name["status"]["schema"] == {"type": "string", "enum": ["active", "closed"]}
    assert by_name["limit"]["schema"] == {"type": "integer"}


def test_swagger2_param_inline_type_is_retained():
    spec = {
        "swagger": "2.0",
        "paths": {
            "/ping": {
                "get": {"parameters": [{"name": "n", "in": "query", "type": "integer"}]}
            }
        },
    }
    ops = parse_operations(spec)
    assert ops[0].params[0]["schema"] == {"type": "integer"}


def test_body_field_schema_facts_are_retained():
    spec = {
        "openapi": "3.0.0",
        "paths": {
            "/users": {
                "post": {
                    "requestBody": {
                        "content": {
                            "application/json": {
                                "schema": {
                                    "type": "object",
                                    "properties": {
                                        "role": {"type": "string", "enum": ["admin", "user"]},
                                    },
                                }
                            }
                        }
                    }
                }
            }
        },
    }
    ops = parse_operations(spec)
    role = next(p for p in ops[0].params if p["name"] == "role")
    assert role["schema"] == {"type": "string", "enum": ["admin", "user"]}


def test_validation_schema_facts_are_retained_for_adaptive_body_checks():
    spec = {
        "openapi": "3.0.0",
        "paths": {
            "/widgets": {
                "post": {
                    "requestBody": {
                        "content": {
                            "application/json": {
                                "schema": {
                                    "type": "object",
                                    "properties": {
                                        "name": {
                                            "type": "string",
                                            "minLength": 2,
                                            "maxLength": 24,
                                        }
                                    },
                                }
                            }
                        }
                    }
                }
            }
        },
    }

    ops = parse_operations(spec)
    assert next(p for p in ops[0].params if p["name"] == "name")["schema"] == {
        "type": "string",
        "minLength": 2,
        "maxLength": 24,
    }


def test_requestbody_ref_is_resolved_into_body_fields():
    spec = {
        "openapi": "3.0.0",
        "paths": {
            "/notes/{id}": {
                "put": {
                    "parameters": [{"name": "id", "in": "path", "required": True}],
                    "requestBody": {
                        "content": {
                            "application/json": {
                                "schema": {"$ref": "#/components/schemas/Note"}
                            }
                        }
                    },
                }
            }
        },
        "components": {
            "schemas": {
                "Note": {
                    "type": "object",
                    "required": ["title"],
                    "properties": {
                        "title": {"type": "string"},
                        "body": {"type": "string"},
                    },
                }
            }
        },
    }
    ops = parse_operations(spec)
    body = {p["name"] for p in ops[0].params if p["in"] == "body"}
    assert body == {"title", "body"}
    title = next(p for p in ops[0].params if p["name"] == "title")
    assert title["required"] is True


def test_swagger2_body_param_schema_is_expanded():
    spec = {
        "swagger": "2.0",
        "paths": {
            "/items": {
                "post": {
                    "parameters": [
                        {
                            "name": "body",
                            "in": "body",
                            "schema": {
                                "type": "object",
                                "properties": {"title": {"type": "string"}},
                            },
                        }
                    ]
                }
            }
        },
    }
    ops = parse_operations(spec)
    body = [p for p in ops[0].params if p["in"] == "body"]
    # the raw `in: body` wrapper is dropped; its fields are surfaced instead
    assert {p["name"] for p in body} == {"title"}


def test_allof_composed_body_fields_are_merged():
    """A requestBody whose schema composes base + extension via allOf surfaces
    fields from BOTH members, not just the first branch."""
    from app.specs.parser import load_spec, parse_operations

    spec = {
        "openapi": "3.0.0",
        "info": {"title": "t", "version": "1"},
        "paths": {
            "/notes": {
                "post": {
                    "requestBody": {
                        "content": {
                            "application/json": {
                                "schema": {"$ref": "#/components/schemas/Note"}
                            }
                        }
                    },
                    "responses": {"200": {"description": "ok"}},
                }
            }
        },
        "components": {
            "schemas": {
                "Base": {
                    "type": "object",
                    "properties": {"id": {"type": "integer"}},
                    "required": ["id"],
                },
                "Note": {
                    "allOf": [
                        {"$ref": "#/components/schemas/Base"},
                        {
                            "type": "object",
                            "properties": {
                                "title": {"type": "string"},
                                "body": {"type": "string"},
                            },
                            "required": ["title"],
                        },
                    ]
                },
            }
        },
    }
    import json
    ops = parse_operations(load_spec(json.dumps(spec)))
    body = {p["name"] for p in ops[0].params if p["in"] == "body"}
    assert body == {"id", "title", "body"}  # merged across allOf members
    required = {p["name"] for p in ops[0].params if p["in"] == "body" and p["required"]}
    assert required == {"id", "title"}


def test_route_prefixes_resolve_like_parse_operations():
    spec = {
        "openapi": "3.0.0",
        "servers": [{"url": "https://api.example.test/v1"}],
        "paths": {
            "/users": {"get": {}, "post": {"servers": [{"url": "/v2"}]}},
            "/admin": {"servers": [{"url": "/internal"}], "get": {}},
        },
    }
    assert route_prefixes(spec) == {
        ("GET", "/users"): "/v1",
        ("POST", "/users"): "/v2",
        ("GET", "/admin"): "/internal",
    }
    parsed = {(op.method, op.path) for op in parse_operations(spec)}
    assert parsed == {
        (method, join_route(prefix, key, None))
        for (method, key), prefix in route_prefixes(spec).items()
    }
    assert route_prefixes({"swagger": "2.0", "basePath": "/api", "paths": {
        "/users": {"get": {}},
    }}) == {("GET", "/users"): "/api"}
    assert route_prefixes({"paths": {"/users": {"get": {}}}}) == {}


def test_spec_operation_finds_the_raw_operation_behind_a_prefixed_route():
    users_get = {"operationId": "listUsers"}
    spec = {
        "openapi": "3.0.0",
        "servers": [{"url": "https://api.example.test/api/v1"}],
        "paths": {"/users": {"get": users_get}},
    }
    assert spec_operation(spec, "GET", "/api/v1/users") is users_get
    # A target base URL that already carries the prefix stores the bare key.
    assert spec_operation(spec, "get", "/users") is users_get
    assert spec_operation(spec, "POST", "/api/v1/users") is None
    assert spec_operation(spec, "GET", "/v1/users") is None
    assert spec_operation(None, "GET", "/users") is None


def test_spec_operation_recomposes_the_route_with_the_target_base_url():
    items_get = {"operationId": "items"}
    spec = {
        "openapi": "3.0.0",
        "servers": [{"url": "/api/v2"}],
        "paths": {"/items": {"get": items_get}},
    }
    # Target ``/api`` cuts part of the server path: the parser stores /v2/items.
    target = "https://api.example.test/api"
    assert parse_operations(spec, target_base_url=target)[0].path == "/v2/items"
    assert spec_operation(spec, "GET", "/v2/items", target) is items_get
    assert spec_operation(spec, "GET", "/v2/items") is None


def test_spec_operation_with_a_target_resolves_a_route_that_is_also_a_key():
    users = {"operationId": "users"}
    nested = {"operationId": "nested"}
    spec = {
        "openapi": "3.0.0",
        "servers": [{"url": "/v1"}],
        "paths": {"/users": {"get": users}, "/v1/users": {"get": nested}},
    }
    routes = {
        op.path for op in parse_operations(spec, target_base_url="https://h.test")
    }
    assert routes == {"/v1/users", "/v1/v1/users"}
    assert spec_operation(spec, "GET", "/v1/users", "https://h.test") is users
    assert spec_operation(spec, "GET", "/v1/v1/users", "https://h.test") is nested


def test_recompose_route_moves_a_route_to_a_new_target():
    spec = {
        "openapi": "3.0.0",
        "servers": [{"url": "https://api.example.test/api/v1"}],
        "paths": {"/users": {"get": {}, "post": {}}},
    }
    bare, prefixed = "http://h.test", "http://h.test/api/v1"

    def moved(path, old, new, method="GET"):
        return recompose_route(spec, method, path, old_target=old, new_target=new)

    # Each direction gives what parse_operations stores under the new target.
    assert moved("/api/v1/users", bare, prefixed) == "/users"
    assert moved("/users", prefixed, bare) == "/api/v1/users"
    assert moved("/api/v1/users", bare, prefixed, "POST") == "/users"
    # A target that cuts part of the server path keeps only the rest.
    assert moved("/api/v1/users", bare, "http://h.test/api") == "/v1/users"
    # A route composed under an earlier target than ``old`` is still found.
    assert moved("/api/v1/users", prefixed, prefixed) == "/users"
    # An operation the spec does not declare has no new route.
    assert moved("/api/v1/users", bare, prefixed, "DELETE") is None
    assert moved("/elsewhere", bare, prefixed) is None
    assert recompose_route(None, "GET", "/users", old_target=bare, new_target=prefixed) is None
