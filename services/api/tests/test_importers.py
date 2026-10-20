"""HAR and Postman import: scan an API that never had an OpenAPI spec.

The importer converts a capture into the same OpenAPI dict the parser consumes,
so the assertions here are about that conversion — path templating, request and
query shape, response-schema inference — and about `load_source` routing each
format correctly. Values are shape only; no captured value should survive.
"""
from __future__ import annotations

import json

import pytest

from app.specs.importers import (
    har_to_openapi,
    load_source,
    looks_like_har,
    looks_like_postman,
    postman_to_openapi,
)
from app.specs.parser import SpecError, parse_operations


def _har(*entries) -> dict:
    return {"log": {"version": "1.2", "entries": list(entries)}}


def _entry(method, url, *, query=None, post=None, resp_text=None, status=200) -> dict:
    e = {
        "request": {
            "method": method,
            "url": url,
            "queryString": [{"name": n, "value": "x"} for n in (query or [])],
        },
        "response": {"status": status, "content": {}},
    }
    if post is not None:
        e["request"]["postData"] = post
    if resp_text is not None:
        e["response"]["content"] = {"mimeType": "application/json", "text": resp_text}
    return e


# ---- sniffing ------------------------------------------------------------------

def test_format_sniffers():
    assert looks_like_har(_har())
    assert not looks_like_har({"item": [], "info": {}})
    assert looks_like_postman({"item": [], "info": {"name": "c"}})
    assert not looks_like_postman({"openapi": "3.0.0"})


# ---- HAR conversion ------------------------------------------------------------

def test_concrete_ids_are_templated_and_collapse():
    doc = har_to_openapi(_har(
        _entry("GET", "https://api.test/users/1837"),
        _entry("GET", "https://api.test/users/42"),
        _entry("GET", "https://api.test/users/9c8a1b2e3d4f5061"),  # long hex
    ))
    # Three concrete captures of one endpoint → one templated path.
    assert list(doc["paths"]) == ["/users/{id}"]
    assert "get" in doc["paths"]["/users/{id}"]


def test_two_ids_get_distinct_params():
    doc = har_to_openapi(_har(_entry("GET", "https://api.test/users/12/orders/98765")))
    assert "/users/{id}/orders/{id2}" in doc["paths"]


def test_version_and_short_segments_are_not_templated():
    doc = har_to_openapi(_har(_entry("GET", "https://api.test/v2/health")))
    assert "/v2/health" in doc["paths"]


def test_a_versioned_segment_with_four_digits_is_not_templated():
    # v2024 mixes letters and 4 digits but is a version, not an object id.
    doc = har_to_openapi(_har(_entry("GET", "https://api.test/v2024/health")))
    assert "/v2024/health" in doc["paths"]


def test_a_non_2xx_response_body_is_not_a_declared_schema():
    # An error body is not the 200 shape; it must not become a response schema.
    doc = har_to_openapi(_har(_entry(
        "GET", "https://api.test/users", resp_text='{"error": "nope"}', status=401,
    )))
    op = doc["paths"]["/users"]["get"]
    assert "responses" not in op


def test_query_and_body_become_shape_not_value():
    doc = har_to_openapi(_har(
        _entry(
            "POST", "https://api.test/orders",
            query=["dryRun"],
            post={"mimeType": "application/json",
                  "text": json.dumps({"item": "sku-1", "qty": 3, "gift": True})},
        )
    ))
    op = doc["paths"]["/orders"]["post"]
    assert [p["name"] for p in op["parameters"]] == ["dryRun"]
    props = op["requestBody"]["content"]["application/json"]["schema"]["properties"]
    assert props == {"item": {"type": "string"}, "qty": {"type": "integer"},
                     "gift": {"type": "boolean"}}
    # No captured value ("sku-1", 3) appears anywhere in the document.
    assert "sku-1" not in json.dumps(doc)


def test_response_body_becomes_a_declared_schema():
    """The bonus: an imported endpoint declares what it returned, so
    data_exposure can diff drift against it."""
    doc = har_to_openapi(_har(
        _entry("GET", "https://api.test/me",
               resp_text=json.dumps({"id": 1, "email": "a@b.c"})),
    ))
    from app.specs.parser import declared_response_fields

    assert declared_response_fields(doc, "GET", "/me") == {"id", "email"}


def test_array_response_is_unwrapped_to_its_item():
    doc = har_to_openapi(_har(
        _entry("GET", "https://api.test/things",
               resp_text=json.dumps([{"id": 1, "name": "x"}])),
    ))
    from app.specs.parser import declared_response_fields

    assert declared_response_fields(doc, "GET", "/things") == {"id", "name"}


def test_urlencoded_body_fields_are_captured():
    doc = har_to_openapi(_har(
        _entry("POST", "https://api.test/login",
               post={"mimeType": "application/x-www-form-urlencoded",
                     "params": [{"name": "user"}, {"name": "pass"}]}),
    ))
    props = doc["paths"]["/login"]["post"]["requestBody"]["content"][
        "application/json"]["schema"]["properties"]
    assert set(props) == {"user", "pass"}


def test_empty_har_is_a_spec_error():
    with pytest.raises(SpecError):
        har_to_openapi(_har())


# ---- Postman conversion --------------------------------------------------------

def _postman(*items) -> dict:
    return {"info": {"name": "c", "schema": "v2.1.0"}, "item": list(items)}


def test_postman_object_url_and_path_vars():
    coll = _postman({
        "name": "get user",
        "request": {
            "method": "GET",
            "url": {"raw": "https://api.test/users/:id",
                    "path": ["users", ":id"], "query": [{"key": "expand"}]},
        },
    })
    doc = postman_to_openapi(coll)
    assert "/users/{id}" in doc["paths"]
    assert [p["name"] for p in doc["paths"]["/users/{id}"]["get"]["parameters"]] == ["expand"]


def test_postman_folders_are_walked():
    coll = _postman({
        "name": "folder",
        "item": [{
            "name": "create",
            "request": {"method": "POST", "url": {"path": ["things"]},
                        "body": {"mode": "raw", "raw": json.dumps({"name": "x"})}},
        }],
    })
    doc = postman_to_openapi(coll)
    props = doc["paths"]["/things"]["post"]["requestBody"]["content"][
        "application/json"]["schema"]["properties"]
    assert set(props) == {"name"}


def test_postman_string_url():
    coll = _postman({
        "name": "p", "request": {"method": "GET", "url": "https://api.test/ping"},
    })
    assert "/ping" in postman_to_openapi(coll)["paths"]


# ---- load_source routing + end-to-end through the parser -----------------------

def test_load_source_routes_har_and_stores_openapi():
    text = json.dumps(_har(_entry("GET", "https://api.test/users/5")))
    doc, canonical = load_source(text)
    assert doc["openapi"] == "3.0.0"
    # The persisted text is the synthesised OpenAPI, not the original HAR.
    assert json.loads(canonical)["paths"] == doc["paths"]
    # And it parses into operations like any spec.
    ops = parse_operations(doc)
    assert any(o.path == "/users/{id}" for o in ops)


def test_load_source_passes_openapi_through_unchanged():
    spec = json.dumps({
        "openapi": "3.0.0", "info": {"title": "t", "version": "1"},
        "paths": {"/a": {"get": {"responses": {"200": {"description": "ok"}}}}},
    })
    doc, canonical = load_source(spec)
    assert canonical == spec  # verbatim
    assert "/a" in doc["paths"]


def test_load_source_rejects_junk():
    with pytest.raises(SpecError):
        load_source("not json or yaml: [unclosed")
