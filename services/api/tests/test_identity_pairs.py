"""What a set of identities can test, answered by the engine's own pairing."""
from __future__ import annotations

from app.engine.identity_pairs import IdentityShape, describe_pairs


def test_two_tenants_and_two_roles_cover_both_boundaries():
    out = describe_pairs([
        IdentityShape("a-admin", "admin", 3, "a"),
        IdentityShape("a-user", "user", 1, "a"),
        IdentityShape("b-user", "user", 1, "b"),
    ])
    assert out["object_level"] == {"owner": "a-admin", "attacker": "b-user"}
    assert out["function_level"] == {"privileged": "a-admin", "lower": "a-user"}
    assert out["object_level_gap"] is None and out["function_level_gap"] is None


def test_same_role_across_tenants_is_bola_but_not_bfla():
    out = describe_pairs([IdentityShape("a", "user", 1, "a"), IdentityShape("b", "user", 1, "b")])
    assert out["object_level"] == {"owner": "a", "attacker": "b"}
    assert out["function_level"] is None
    assert "no tenant has two identities" in out["function_level_gap"]


def test_one_tenant_two_roles_is_bfla_but_not_bola():
    out = describe_pairs(
        [IdentityShape("adm", "admin", None, "a"), IdentityShape("u", "user", None, "a")]
    )
    assert out["function_level"] == {"privileged": "adm", "lower": "u"}
    assert out["object_level"] is None
    assert "another tenant" in out["object_level_gap"]


def test_untenanted_identities_sit_out_once_one_declares_a_tenant():
    out = describe_pairs([
        IdentityShape("a", "user", 1, "a"), IdentityShape("b", "user", 1, "b"),
        IdentityShape("loose", "admin", 3),
    ])
    assert out["left_out"] == ["loose"]


def test_one_identity_has_nothing_to_compare():
    out = describe_pairs([IdentityShape("solo", "user")])
    assert out["object_level"] is None and out["function_level"] is None
    assert "two identities" in out["object_level_gap"]


def test_same_rank_without_tenants_names_the_missing_boundary():
    out = describe_pairs([IdentityShape("x", "user", 1), IdentityShape("y", "user", 1)])
    assert out["object_level"] is not None
    assert "share one privilege rank" in out["function_level_gap"]


def test_the_route_takes_shapes_and_no_secret(client):
    r = client.post("/specs/identity-pairs", json={"identities": [
        {"name": "a", "role": "user", "tenant": "a"}, {"name": "b", "role": "user", "tenant": "b"},
    ]})
    assert r.status_code == 200, r.text
    assert r.json()["object_level"] == {"owner": "a", "attacker": "b"}
    # Extra fields are ignored, never stored: there is nowhere for a secret to go.
    assert client.post("/specs/identity-pairs", json={"identities": [
        {"name": "a", "role": "user", "privilege": 9},
    ]}).status_code == 422
