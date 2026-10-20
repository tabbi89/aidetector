"""Read-only id seeding: real ids from collection reads, never a write, never a leak."""
from __future__ import annotations

import json
from types import SimpleNamespace

import pytest
from starlette.testclient import TestClient

from app.domain.enums import AuthType
from app.engine.base import (
    HttpProbe,
    ResolvedCredential,
    ScanContext,
    TargetOperation,
    render_path,
)
from app.engine.checks.authz import BolaCheck
from app.engine.id_seed import seed_read_only_ids
from app.engine.resource_map import path_param_key, path_values
from tests import factories
from tests.safeapp import safeapp as safe_app
from tests.vulnapp import vulnapp


def _op(method: str, path: str) -> TargetOperation:
    names = [seg[1:-1] for seg in path.split("/") if seg.startswith("{")]
    return TargetOperation(
        id=f"{method} {path}",
        method=method,
        path=path,
        params=[{"name": n, "in": "path", "required": True} for n in names],
    )


class Client:
    def __init__(self, routes: dict[str, tuple[int, str]]) -> None:
        self.routes = routes
        self.sent: list[tuple[str, str]] = []

    def request(self, method: str, url: str, **kwargs):
        self.sent.append((method, url))
        status, text = self.routes.get(url, (404, '{"detail":"not found"}'))
        return SimpleNamespace(status_code=status, headers={}, text=text, content=text.encode())


def _ctx(ops: list[TargetOperation], routes: dict, **ctx_kwargs) -> tuple[ScanContext, Client]:
    client = Client(routes)
    cred = ResolvedCredential("alice", "user", AuthType.header, "Authorization", "tok")
    probe = HttpProbe(client, operations=ops, credentials=[cred], max_requests=100)
    ctx = ScanContext(
        base_url="http://target", operations=ops, credentials=[cred], probe=probe, **ctx_kwargs
    )
    return ctx, client


def test_collection_read_seeds_the_item_id():
    ops = [_op("GET", "/accounts"), _op("GET", "/accounts/{account_id}")]
    ctx, client = _ctx(ops, {"/accounts": (200, json.dumps({"items": [{"id": 42}]}))})

    notes = seed_read_only_ids(ctx)

    assert ctx.resource_ids == {"account": "42"}
    assert ctx.seeded_resource_keys == {"account"}
    assert client.sent == [("GET", "/accounts")]
    assert not any("42" in note for note in notes)


def test_a_parent_id_unlocks_a_nested_collection_in_a_later_round():
    ops = [
        _op("GET", "/projects/{project_id}/items/{item_id}"),
        _op("GET", "/projects/{project_id}/items"),
        _op("GET", "/projects"),
    ]
    routes = {
        "/projects": (200, json.dumps([{"id": "p-7"}])),
        "/projects/p-7/items": (200, json.dumps({"data": [{"itemId": "i-9"}]})),
    }
    ctx, client = _ctx(ops, routes)

    seed_read_only_ids(ctx)

    assert ctx.resource_ids == {"project": "p-7", "item": "i-9"}
    assert {method for method, _ in client.sent} == {"GET"}


def test_an_existing_id_is_kept_and_not_read_for():
    ops = [_op("GET", "/accounts"), _op("GET", "/accounts/{account_id}")]
    ctx, client = _ctx(
        ops, {"/accounts": (200, '[{"id": 1}]')}, resource_ids={"account": "fixture"}
    )

    seed_read_only_ids(ctx)

    assert ctx.resource_ids == {"account": "fixture"}
    assert ctx.seeded_resource_keys == set()
    assert client.sent == []


def test_reads_are_capped():
    ops = []
    for name in ("alpha", "beta", "gamma", "delta"):
        ops += [_op("GET", f"/{name}s"), _op("GET", f"/{name}s/{{{name}_id}}")]
    ctx, client = _ctx(ops, {})

    seed_read_only_ids(ctx, max_reads=2)

    assert len(client.sent) == 2


@pytest.mark.parametrize("value", ["../x", "a/b", "has space", True, "x" * 65, "..", "a?b"])
def test_unsafe_ids_are_refused(value):
    ops = [_op("GET", "/accounts"), _op("GET", "/accounts/{account_id}")]
    ctx, _ = _ctx(ops, {"/accounts": (200, json.dumps([{"id": value}]))})

    seed_read_only_ids(ctx)

    assert ctx.resource_ids == {}


def test_a_foreign_key_is_not_mistaken_for_the_record_id():
    ops = [_op("GET", "/accounts"), _op("GET", "/accounts/{account_id}")]
    ctx, _ = _ctx(ops, {"/accounts": (200, '[{"org_id": 5, "name": "x"}]')})

    seed_read_only_ids(ctx)

    assert ctx.resource_ids == {}


@pytest.mark.parametrize("response", [(403, '[{"id": 1}]'), (200, "<html>nope</html>")])
def test_rejected_and_non_json_reads_seed_nothing(response):
    ops = [_op("GET", "/accounts"), _op("GET", "/accounts/{account_id}")]
    ctx, _ = _ctx(ops, {"/accounts": response})

    notes = seed_read_only_ids(ctx)

    assert ctx.resource_ids == {}
    assert notes[-1].startswith("read-only id seeding: 0 of 1")


def test_no_path_parameters_means_no_requests():
    ops = [_op("GET", "/health")]
    ctx, client = _ctx(ops, {})

    assert seed_read_only_ids(ctx) == []
    assert client.sent == []


# ---- bare ``{id}`` path parameters -------------------------------------------


@pytest.mark.parametrize(
    ("path", "name", "key"),
    [
        ("/monitors/{id}", "id", "monitor"),
        ("/api/v1/incidents/{id}/acknowledge", "id", "incident"),
        ("/monitors/{uuid}", "uuid", "monitor"),
        ("/status-pages/{guid}", "guid", "statuspage"),
        ("/monitors/{ID}", "ID", "monitor"),
        # A named parameter names itself, wherever it sits.
        ("/monitors/{monitor_id}", "monitor_id", "monitor"),
        ("/teams/{teamId}/monitors/{monitor_id}", "teamId", "team"),
        ("/monitors/{monitor_id}/checks/{id}", "id", "check"),
        # Nothing static before it: no better name than the parameter's own.
        ("/{id}", "id", "id"),
        ("/orgs/{org}/{id}", "id", "id"),
    ],
)
def test_a_bare_id_takes_its_resource_from_the_segment_before_it(path, name, key):
    assert path_param_key(path, name) == key


def test_two_bare_id_resources_get_distinct_ids():
    ops = [
        _op("GET", "/monitors"),
        _op("GET", "/monitors/{id}"),
        _op("GET", "/incidents"),
        _op("GET", "/incidents/{id}/acknowledge"),
    ]
    routes = {
        "/monitors": (200, json.dumps({"items": [{"id": "mon-1"}]})),
        "/incidents": (200, json.dumps([{"id": "inc-9"}])),
    }
    ctx, _ = _ctx(ops, routes)

    notes = seed_read_only_ids(ctx)

    assert ctx.resource_ids == {"monitor": "mon-1", "incident": "inc-9"}
    assert notes[-1].startswith("read-only id seeding: 2 of 2")
    assert path_values(ops[1], ctx.resource_ids) == {"id": "mon-1"}
    assert path_values(ops[3], ctx.resource_ids) == {"id": "inc-9"}


def test_a_bare_parent_id_unlocks_its_nested_collection():
    ops = [
        _op("GET", "/monitors"),
        _op("GET", "/monitors/{id}/checks"),
        _op("GET", "/monitors/{monitor_id}/checks/{check_id}"),
    ]
    routes = {
        "/monitors": (200, json.dumps([{"id": "mon-1"}])),
        "/monitors/mon-1/checks": (200, json.dumps([{"id": "chk-4"}])),
    }
    ctx, _ = _ctx(ops, routes)

    seed_read_only_ids(ctx)

    assert ctx.resource_ids == {"monitor": "mon-1", "check": "chk-4"}
    assert path_values(ops[1], ctx.resource_ids) == {"id": "mon-1"}


def test_an_id_keyed_on_the_bare_name_still_applies():
    """A user-supplied ``{"id": ...}`` predates per-resource bare-id keys."""
    op = _op("GET", "/monitors/{id}")

    assert path_values(op, {"id": "given"}) == {"id": "given"}
    assert path_values(op, {"id": "given", "monitor": "seeded"}) == {"id": "seeded"}


def test_a_parent_supplied_on_the_bare_name_unlocks_a_nested_collection():
    """Parents resolve through the same bare-name fallback as rendering does."""
    ops = [
        _op("GET", "/projects/{id}/items"),
        _op("GET", "/projects/{project_id}/items/{item_id}"),
    ]
    routes = {"/projects/p-3/items": (200, json.dumps([{"id": "i-5"}]))}
    ctx, client = _ctx(ops, routes, resource_ids={"id": "p-3"})

    seed_read_only_ids(ctx)

    assert client.sent == [("GET", "/projects/p-3/items")]
    assert ctx.resource_ids["item"] == "i-5"


def _bare_id_ops() -> list[TargetOperation]:
    return [
        factories.operation("GET", "/monitors", id="b-monitors", params=[]),
        factories.operation("GET", "/monitors/{id}", id="b-monitor"),
        factories.operation("GET", "/incidents", id="b-incidents", params=[]),
        factories.operation("GET", "/incidents/{id}", id="b-incident"),
    ]


def test_seeding_reaches_both_bare_id_objects_on_the_target():
    ctx = factories.scan_context(_bare_id_ops())

    seed_read_only_ids(ctx)

    assert ctx.resource_ids == {"monitor": "mon-7f3a", "incident": "inc-22c1"}
    for op in ctx.operations[1::2]:
        path = render_path(op.path, path_values(op, ctx.resource_ids))
        response = ctx.probe.send("GET", path, headers=ctx.primary_headers())
        assert response is not None and response.status == 200, path


def _bola_routes(client) -> set[str]:
    ctx = factories.scan_context(_bare_id_ops(), client=client)
    seed_read_only_ids(ctx)
    findings = factories.run_check(BolaCheck(), ctx)
    return {f.evidence["route"] for f in findings}


def test_bola_fires_on_every_bare_id_route_of_the_vulnerable_app():
    assert _bola_routes(TestClient(vulnapp)) == {"/monitors/{id}", "/incidents/{id}"}


def test_bola_stays_quiet_on_owner_scoped_bare_id_routes():
    assert _bola_routes(TestClient(safe_app)) == set()


def test_an_id_supplied_on_the_bare_name_is_not_seeded_over():
    ops = [_op("GET", "/monitors"), _op("GET", "/monitors/{id}")]
    ctx, client = _ctx(
        ops, {"/monitors": (200, '[{"id": "mon-other"}]')}, resource_ids={"id": "mon-mine"}
    )

    assert seed_read_only_ids(ctx) == []
    assert client.sent == []
    assert path_values(ops[1], ctx.resource_ids) == {"id": "mon-mine"}
