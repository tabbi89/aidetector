"""Bounded, allowlisted remote ``$ref`` resolution.

A fake fetcher stands in for the network, so these pin the security envelope
(off by default, allowlist-gated, budgeted, redirect/failure-safe) without any
real egress.
"""
from __future__ import annotations

from app.specs.remote_refs import inline_remote_refs

# A remote components document an allowlisted host serves.
_SCHEMAS = "https://schemas.example.com/models.yaml"
_REMOTE_DOC = {
    "components": {
        "schemas": {
            "Widget": {
                "type": "object",
                "properties": {
                    "id": {"type": "integer"},
                    "maker": {"$ref": "#/components/schemas/Maker"},
                },
            },
            "Maker": {"type": "object", "properties": {"name": {"type": "string"}}},
        }
    }
}


def _fetcher(mapping):
    calls: list[str] = []

    def fetch(url: str):
        calls.append(url)
        return mapping.get(url)

    fetch.calls = calls  # type: ignore[attr-defined]
    return fetch


def _spec_with_ref(ref: str) -> dict:
    return {"components": {"schemas": {"W": {"$ref": ref}}}}


def test_disabled_when_allowlist_empty():
    fetch = _fetcher({_SCHEMAS: "{}"})
    root = _spec_with_ref(f"{_SCHEMAS}#/components/schemas/Widget")
    out = inline_remote_refs(root, allowlist=[], fetch=fetch)
    assert out is root
    assert fetch.calls == [], "nothing is fetched when remote refs are disabled"


def test_allowlisted_remote_ref_is_inlined():
    import yaml

    fetch = _fetcher({_SCHEMAS: yaml.safe_dump(_REMOTE_DOC)})
    root = _spec_with_ref(f"{_SCHEMAS}#/components/schemas/Widget")
    out = inline_remote_refs(root, allowlist=["schemas.example.com"], fetch=fetch)
    widget = out["components"]["schemas"]["W"]
    assert widget["type"] == "object"
    # The remote doc's OWN internal ref (Maker) resolved against that doc.
    assert widget["properties"]["maker"]["properties"]["name"] == {"type": "string"}
    assert fetch.calls == [_SCHEMAS]


def test_a_non_allowlisted_host_is_never_fetched():
    fetch = _fetcher({"https://evil.example.net/x.yaml": "{}"})
    root = _spec_with_ref("https://evil.example.net/x.yaml#/a")
    out = inline_remote_refs(root, allowlist=["schemas.example.com"], fetch=fetch)
    # The ref is left untouched and no request was made to the blocked host.
    assert out["components"]["schemas"]["W"] == {"$ref": "https://evil.example.net/x.yaml#/a"}
    assert fetch.calls == []


def test_a_cloud_metadata_host_is_refused_even_if_allowlisted():
    fetch = _fetcher({"http://metadata/x.json": "{}"})
    root = _spec_with_ref("http://metadata/x.json#/a")
    out = inline_remote_refs(root, allowlist=["metadata"], fetch=fetch)
    assert out["components"]["schemas"]["W"] == {"$ref": "http://metadata/x.json#/a"}
    assert fetch.calls == []


def test_a_failed_fetch_leaves_the_ref_untouched():
    fetch = _fetcher({})  # every fetch returns None
    root = _spec_with_ref(f"{_SCHEMAS}#/components/schemas/Widget")
    out = inline_remote_refs(root, allowlist=["schemas.example.com"], fetch=fetch)
    assert out["components"]["schemas"]["W"] == {"$ref": f"{_SCHEMAS}#/components/schemas/Widget"}


def test_a_missing_pointer_leaves_the_ref_untouched():
    import yaml

    fetch = _fetcher({_SCHEMAS: yaml.safe_dump(_REMOTE_DOC)})
    ref = f"{_SCHEMAS}#/components/schemas/DoesNotExist"
    out = inline_remote_refs(_spec_with_ref(ref), allowlist=["schemas.example.com"], fetch=fetch)
    assert out["components"]["schemas"]["W"] == {"$ref": ref}


def test_the_document_is_fetched_once_and_cached():
    import yaml

    fetch = _fetcher({_SCHEMAS: yaml.safe_dump(_REMOTE_DOC)})
    root = {
        "a": {"$ref": f"{_SCHEMAS}#/components/schemas/Widget"},
        "b": {"$ref": f"{_SCHEMAS}#/components/schemas/Maker"},
    }
    inline_remote_refs(root, allowlist=["schemas.example.com"], fetch=fetch)
    assert fetch.calls == [_SCHEMAS], "two refs to one document is one fetch"


def test_the_fetch_budget_is_bounded():
    docs = {f"https://schemas.example.com/{i}.yaml": "{}" for i in range(5)}
    fetch = _fetcher(docs)
    root = {
        str(i): {"$ref": f"https://schemas.example.com/{i}.yaml#/"} for i in range(5)
    }
    inline_remote_refs(root, allowlist=["schemas.example.com"], fetch=fetch, max_fetches=2)
    assert len(fetch.calls) == 2, "no more documents are fetched than the budget allows"


def test_a_self_referential_remote_doc_does_not_loop():
    import yaml

    cyclic = {
        "components": {
            "schemas": {
                "Node": {
                    "type": "object",
                    "properties": {"next": {"$ref": "#/components/schemas/Node"}},
                }
            }
        }
    }
    fetch = _fetcher({_SCHEMAS: yaml.safe_dump(cyclic)})
    ref = f"{_SCHEMAS}#/components/schemas/Node"
    out = inline_remote_refs(_spec_with_ref(ref), allowlist=["schemas.example.com"], fetch=fetch)
    node = out["components"]["schemas"]["W"]
    assert node["type"] == "object"
    # Finite (the test returning at all proves no infinite expansion), and the
    # cycle is cut: a residual $ref reappears one level down rather than looping.
    assert node["properties"]["next"]["properties"]["next"] == {
        "$ref": "#/components/schemas/Node"
    }


# ---- wiring: load_spec pulls remote refs through the allowlist ----------------

def test_load_spec_inlines_a_remote_ref_when_allowlisted(monkeypatch):
    import yaml

    from app.specs import parser, remote_refs

    monkeypatch.setattr(remote_refs, "_httpx_fetch", lambda url: yaml.safe_dump(_REMOTE_DOC))
    spec = {
        "openapi": "3.0.0",
        "info": {"title": "t", "version": "1"},
        "paths": {
            "/widgets/{id}": {
                "get": {
                    "parameters": [{"name": "id", "in": "path", "required": True}],
                    "responses": {
                        "200": {
                            "content": {
                                "application/json": {
                                    "schema": {"$ref": f"{_SCHEMAS}#/components/schemas/Widget"}
                                }
                            }
                        }
                    },
                }
            }
        },
    }
    import json as _json

    data = parser.load_spec(_json.dumps(spec), remote_ref_allowlist=["schemas.example.com"])
    schema = data["paths"]["/widgets/{id}"]["get"]["responses"]["200"]["content"][
        "application/json"
    ]["schema"]
    assert "$ref" not in schema, "the remote schema was inlined"
    assert set(schema["properties"]) == {"id", "maker"}


def test_load_spec_leaves_a_remote_ref_when_not_allowlisted(monkeypatch):
    import json as _json

    from app.specs import parser, remote_refs

    called: list[str] = []
    monkeypatch.setattr(remote_refs, "_httpx_fetch", lambda url: called.append(url) or "{}")
    spec = {
        "openapi": "3.0.0",
        "info": {"title": "t", "version": "1"},
        "components": {"schemas": {"W": {"$ref": f"{_SCHEMAS}#/components/schemas/Widget"}}},
        "paths": {},
    }
    # Empty allowlist → remote resolution stays off, nothing is fetched.
    data = parser.load_spec(_json.dumps(spec), remote_ref_allowlist=[])
    assert called == []
    assert data["components"]["schemas"]["W"] == {
        "$ref": f"{_SCHEMAS}#/components/schemas/Widget"
    }
