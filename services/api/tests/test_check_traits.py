"""Which checks the runner refuses to run concurrently, and who decides.

Whether a check may write to the target is a property *of the check*, so it is
declared on the check — ``mutates`` for one that writes under any options,
``serial_when_mutating`` for one that only writes once ``mutate: true`` is set —
and read through ``base.runs_serially``.

It used to live in ``runner.py`` as two sets of strings, four modules from the
checks they governed. A new mutating check that nobody remembered to list there
was dispatched into the ``ThreadPoolExecutor`` alongside the write oracles,
against the same resources on a real target, silently and non-deterministically.

The partition asserted here is byte-for-byte the one the string sets produced;
``test_char_stage_order.py`` pins the same fact from the outside, through the
order a run's events arrive in. Registry order is pinned too, because it is
documented as run order *and* display order, so a reordering is user-visible.
"""
from __future__ import annotations

import pytest

from app.engine.base import mutates, premium, runs_serially, serial_when_mutating
from app.engine.checks import ALL_CHECKS

#: Checks that write to the target under any run options.
EXPECTED_MUTATING = {
    "write_authz", "seeded_bola", "mass_assignment", "race_condition", "business_flow"
}

#: Read-only by default, but may create or update once ``mutate: true`` is set.
EXPECTED_SERIAL_WHEN_MUTATING = {"bola", "schema_fuzz"}

#: Checks reserved for the premium tier — off unless ``premium: true``.
EXPECTED_PREMIUM = {
    "host_header",
    "design_review",
    "advanced_rate_limit",
    "xxe_confirmation",
    "jwt_confusion",
    "deserialization",
    "unsafe_consumption",
    "graphql_introspection",
    "graphql_behavior",
    "request_smuggling",
    "grpc_reflection",
}

#: ``ALL_CHECKS`` order is run order and display order, so it is a contract.
EXPECTED_REGISTRY_ORDER = [
    "bola",
    "bfla",
    "broken_auth",
    "security_headers",
    "info_disclosure",
    "data_exposure",
    "potential_secrets",
    "enumeration",
    "resource_consumption",
    "write_authz",
    "seeded_bola",
    "mass_assignment",
    "race_condition",
    "business_flow",
    "reflected_injection",
    "signature_injection",
    "ssrf",
    "oob_injection",
    "schema_fuzz",
    "tls_config",
    "host_header",
    "design_review",
    "advanced_rate_limit",
    "xxe_confirmation",
    "jwt_confusion",
    "deserialization",
    "unsafe_consumption",
    "graphql_introspection",
    "graphql_behavior",
    "request_smuggling",
    "grpc_reflection",
]


def _partition(*, allow_mutation: bool) -> tuple[list[str], list[str]]:
    """The runner's own rule (``_run_engine_checks``), applied to the registry."""
    return (
        [c.key for c in ALL_CHECKS if not runs_serially(c, allow_mutation=allow_mutation)],
        [c.key for c in ALL_CHECKS if runs_serially(c, allow_mutation=allow_mutation)],
    )


def test_registry_order_is_unchanged() -> None:
    assert [c.key for c in ALL_CHECKS] == EXPECTED_REGISTRY_ORDER


def test_the_mutating_checks_declare_it() -> None:
    assert {c.key for c in ALL_CHECKS if mutates(c)} == EXPECTED_MUTATING


def test_the_conditionally_writing_checks_declare_it() -> None:
    assert {
        c.key for c in ALL_CHECKS if serial_when_mutating(c)
    } == EXPECTED_SERIAL_WHEN_MUTATING


def test_the_premium_checks_declare_it() -> None:
    """A check that is premium must opt in — and nothing else is accidentally gated."""
    assert {c.key for c in ALL_CHECKS if premium(c)} == EXPECTED_PREMIUM


def test_partition_without_mutation() -> None:
    parallel, serial = _partition(allow_mutation=False)
    assert serial == [
        "write_authz", "seeded_bola", "mass_assignment", "race_condition",
        "business_flow",
    ]
    assert parallel == [
        "bola", "bfla", "broken_auth", "security_headers", "info_disclosure",
        "data_exposure", "potential_secrets", "enumeration", "resource_consumption",
        "reflected_injection",
        "signature_injection", "ssrf", "oob_injection", "schema_fuzz", "tls_config",
        "host_header",
        "design_review",
        "advanced_rate_limit",
        "xxe_confirmation",
        "jwt_confusion",
        "deserialization",
        "unsafe_consumption",
        "graphql_introspection",
        "graphql_behavior",
        "request_smuggling",
        "grpc_reflection",
    ]


def test_partition_with_mutation_moves_bola_and_schema_fuzz() -> None:
    parallel, serial = _partition(allow_mutation=True)
    assert "bola" in serial and "schema_fuzz" in serial
    assert "bola" not in parallel and "schema_fuzz" not in parallel
    assert serial == [
        "bola", "write_authz", "seeded_bola", "mass_assignment",
        "race_condition", "business_flow", "schema_fuzz",
    ]


def test_the_runner_keeps_no_check_list_of_its_own() -> None:
    """The regression guard: a name-matched list drifts from what it names.

    ``runner.py`` used to hold ``_ALWAYS_SERIAL`` / ``_SERIAL_WHEN_MUTATING``. A
    stale entry there protected nothing and a missing one was a silent race,
    because neither fails a test until a check actually corrupts another's data.
    """
    import app.engine.runner as runner

    for gone in ("_ALWAYS_SERIAL", "_SERIAL_WHEN_MUTATING"):
        assert not hasattr(runner, gone), (
            f"runner.py declares {gone} again — concurrency safety belongs on the "
            "check, not in a list of strings four modules away."
        )


@pytest.mark.parametrize("check", ALL_CHECKS, ids=lambda c: c.key)
def test_defaults_are_the_safe_answer(check: object) -> None:
    """A check that declares nothing must land in the parallel group.

    That is the safe default only because declaring nothing means "does not
    write". Any check that gains a write must gain the trait in the same commit
    — which is what the two membership tests above are for.
    """
    if not mutates(check) and not serial_when_mutating(check):
        assert not runs_serially(check, allow_mutation=True)
        assert not runs_serially(check, allow_mutation=False)
