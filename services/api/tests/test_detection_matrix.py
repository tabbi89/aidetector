"""Every registered check must be *proved* to detect something, somewhere.

``test_coverage_mirror`` proves a check has a coverage entry, ``test_remediation``
proves it has remediation text, and ``test_engine_smoke`` proves the registry
does not explode. None of them proves a given check has ever produced a finding.
A check could be registered, documented, catalogued, and silently broken — and
the only symptom would be a scan that reports nothing, which is also what a clean
target looks like.

So this is the recall half of the pair whose precision half is
``test_precision.py``. It fails in both directions, like the mirror tests: a
check with no entry here, and an entry naming a check that left the registry.

Two kinds of proof are accepted:

- ``STANDARD`` — the check fires in the shared registry run against
  ``tests/vulnapp.py``. This is asserted directly, so it cannot go stale.
- a **module name** — the check needs a target the shared run does not offer (an
  OAST collector, a TLS socket, a GraphQL server, a spec to fuzz), and its proof
  lives in that dedicated test module. The file's existence is asserted; the
  module named is where to look when the check regresses.
"""
from __future__ import annotations

import pathlib

from app.engine.checks import ALL_CHECKS
from tests import factories

#: Marker for "proved by the shared run against the vulnerable app".
STANDARD = "<standard run>"

#: check key -> where its positive proof lives. Add a row when you add a check.
PROOF: dict[str, str] = {
    # --- Fire against the shared vulnerable app -------------------------------
    "bola": STANDARD,
    "bfla": STANDARD,
    "broken_auth": STANDARD,
    "design_review": STANDARD,
    "graphql_introspection": STANDARD,
    "grpc_reflection": STANDARD,
    "reflected_injection": STANDARD,
    "security_headers": STANDARD,
    "signature_injection": STANDARD,
    "tls_config": STANDARD,
    # --- Need a target or an opt-in the shared run does not provide -----------
    # Writes to the target: needs mutate:true plus a spec-paired create/update.
    "write_authz": "tests/test_write_oracle.py",
    "mass_assignment": "tests/test_mass_assignment.py",
    "seeded_bola": "tests/test_seeded_bola.py",
    # Needs a transport that can fire a real concurrent burst.
    "race_condition": "tests/test_race_condition.py",
    # Needs an out-of-band collector; no-ops without one by design.
    "oob_injection": "tests/test_engine_oob.py",
    # Needs a real parser/opcode target — see tests/realistic_targets.py.
    "xxe_confirmation": "tests/test_xxe_confirmation.py",
    "deserialization": "tests/test_deserialization.py",
    # Needs a spec to generate cases from (fuzz:true).
    "schema_fuzz": "tests/test_schema_fuzz.py",
    # Read the header sweep, which needs endpoints shaped to trip them.
    "data_exposure": "tests/test_engine_exposure.py",
    "info_disclosure": "tests/test_engine_headers.py",
    "potential_secrets": "tests/test_potential_secrets.py",
    # Premium checks: gated off in a default run.
    "host_header": "tests/test_host_header.py",
    "request_smuggling": "tests/test_request_smuggling.py",
    "advanced_rate_limit": "tests/test_advanced_rate_limit.py",
    "jwt_confusion": "tests/test_jwt_confusion.py",
    # Behavioural probes against their own targets.
    "graphql_behavior": "tests/test_graphql_behavior.py",
    "enumeration": "tests/test_engine_smoke.py",
    "ssrf": "tests/test_engine_injection.py",
    # Needs a collection endpoint that honours an unbounded page size.
    "resource_consumption": "tests/test_resource_consumption.py",
    # Writes: needs mutate:true and a sensitive-flow endpoint that mints objects.
    "business_flow": "tests/test_business_flow.py",
    # Premium + OOB: needs a collector to confirm the downstream fetch.
    "unsafe_consumption": "tests/test_unsafe_consumption.py",
}

_ROOT = pathlib.Path(__file__).resolve().parent.parent


def _registered() -> set[str]:
    return {check.key for check in ALL_CHECKS}


def test_every_registered_check_declares_where_it_is_proved():
    """A new check without a row here has no evidence it detects anything."""
    missing = _registered() - set(PROOF)
    assert not missing, (
        "registered checks with no detection proof declared: "
        f"{sorted(missing)} — add a row to PROOF naming the test that proves it fires"
    )


def test_no_row_names_a_check_that_left_the_registry():
    """The other direction: a stale row points reviewers at nothing."""
    stale = set(PROOF) - _registered()
    assert not stale, f"PROOF rows for unregistered checks: {sorted(stale)}"


def test_every_named_proof_module_exists():
    """A row naming a deleted file is a dead pointer, not a proof."""
    for key, where in PROOF.items():
        if where == STANDARD:
            continue
        assert (_ROOT / where).is_file(), f"{key} points at missing {where}"


def test_every_named_proof_module_references_its_check():
    """A module that exists but no longer exercises the check is a dead pointer.

    ``test_every_named_proof_module_exists`` only proves the file is still there;
    this proves the file still imports/instantiates the check it is the proof
    for. Without it, a check whose dedicated test was deleted (or moved to
    another module) keeps its row green as long as *some* file of that name
    remains — which is exactly the silent no-op the matrix exists to catch.
    """
    class_by_key = {check.key: type(check).__name__ for check in ALL_CHECKS}
    for key, where in PROOF.items():
        if where == STANDARD:
            continue
        source = (_ROOT / where).read_text(encoding="utf-8")
        class_name = class_by_key[key]
        assert class_name in source, (
            f"{key}'s proof module {where} never references {class_name}; "
            "a module that no longer instantiates the check is not a proof"
        )


def test_the_standard_run_really_fires_every_check_that_claims_it():
    """The half of this matrix that is asserted rather than asserted-about.

    Run once, compare sets both ways: a check claiming ``STANDARD`` that has
    gone quiet fails, and a check that started firing without claiming it is
    reported too — that is a row that should be upgraded from a module pointer.
    """
    findings = factories.run_registry(
        factories.engine_operations(),
        credentials=factories.two_identities(),
        allow_mutation=True,
        premium=True,
    )
    fired = {f.check for f in findings}
    claimed = {key for key, where in PROOF.items() if where == STANDARD}

    silent = claimed - fired
    assert not silent, f"claim STANDARD but produced no finding: {sorted(silent)}"

    unclaimed = fired - claimed
    assert not unclaimed, (
        f"fire in the standard run but are not marked STANDARD: {sorted(unclaimed)} "
        "— promote their PROOF row"
    )


# ---- Applicability ------------------------------------------------------------
#
# The matrix above answers "can this check detect anything, ever". This answers
# the question a *user* has: "did it run against my API, and if not, why not".
# A check with nothing to work against returns an empty list, which is exactly
# what a clean result looks like — so the reason has to be stated, not inferred.


#: Checks that legitimately produce nothing on a starved scan without declaring
#: a reason, and why that is acceptable. Everything else must declare.
_NEED_NO_REASON: dict[str, str] = {
    # These read the shared header sweep rather than probing themselves, so they
    # always have something to say about whatever the sweep reached.
    "security_headers": "reads the header sweep, which always runs",
    "info_disclosure": "reads the header sweep, which always runs",
    "data_exposure": "reads the header sweep and the request trace",
    "potential_secrets": "reads the header sweep, which always runs",
    # Inspect the transport or the spec document, not the operation set.
    "tls_config": "opens its own TLS socket; needs no operation",
    "design_review": "reads the spec document itself",
    # Probe fixed, well-known endpoints rather than spec operations.
    "graphql_introspection": "probes well-known GraphQL paths",
    "graphql_behavior": "probes well-known GraphQL paths",
    "grpc_reflection": "probes the gRPC reflection service",
    "deserialization": "probes for its own sinks across the operation set",
    "xxe_confirmation": "probes for its own sinks across the operation set",
    # Apply to any operation with a parameter or an auth requirement.
    "broken_auth": "synthesizes a bearer forgery even when no credential is configured",
    "enumeration": "applies to any operation that can be repeated",
    "reflected_injection": "applies to any parameter",
    "signature_injection": "applies to any parameter",
    "advanced_rate_limit": "applies to any operation",
    "host_header": "applies to any operation",
    "request_smuggling": "applies to any operation",
    "jwt_confusion": "applies to any bearer credential",
    "mass_assignment": "declares only the mutate gate; reaches any writable body",
}


def test_every_check_either_runs_or_says_why_not():
    """No silent no-ops: the two must be distinguishable in the report."""
    from app.engine.base import inapplicable
    from tests import factories

    # A deliberately starved scan: no writes, no second identity, no spec, no
    # OAST, no fuzzing — the shape of a first run against an unknown API.
    ctx = factories.scan_context(factories.engine_operations(), credentials=[])

    undeclared = [
        check.key
        for check in ALL_CHECKS
        if inapplicable(check, ctx) is None and check.key not in _NEED_NO_REASON
    ]
    assert not undeclared, (
        f"checks that neither run nor explain themselves: {sorted(undeclared)}. "
        "Add an `inapplicable(ctx)` staticmethod naming what is missing, or a "
        "_NEED_NO_REASON entry saying why the check always has work to do."
    )


def test_no_check_is_excused_without_a_reason():
    """The excuse list is only as good as its justifications."""
    registered = _registered()
    for key, why in _NEED_NO_REASON.items():
        assert key in registered, f"_NEED_NO_REASON names unregistered check {key!r}"
        assert len(why.strip()) > 15, f"{key}'s excuse is too thin to review: {why!r}"


def test_a_declared_reason_names_the_thing_to_change():
    """A reason a user cannot act on is not worth showing them."""
    from app.engine.base import inapplicable
    from tests import factories

    ctx = factories.scan_context(factories.engine_operations(), credentials=[])
    for check in ALL_CHECKS:
        reason = inapplicable(check, ctx)
        if reason is None:
            continue
        assert len(reason) > 25, f"{check.key}'s reason is too terse: {reason!r}"
        assert not reason.endswith("."), f"{check.key}'s reason reads as a sentence fragment"
