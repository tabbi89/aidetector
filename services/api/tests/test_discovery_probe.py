"""Scanning what discovery found (API9): the second, separately-budgeted pass.

The adjuncts (ffuf/katana/arjun) find shadow endpoints the spec omits; this
turns them back into operations and runs the core checks against them. The pure
`synthetic_operations` builder needs no target; the end-to-end pass runs against
the in-process app, using real vulnapp paths as stand-ins for "discovered".
"""
from __future__ import annotations

from app.domain.enums import Severity
from app.engine.base import HttpProbe, ScanContext, TargetOperation
from app.engine.checks import ALL_CHECKS
from app.engine.discovery_probe import (
    DISCOVERY_CHECK_KEYS,
    relevant_checks,
    synthetic_operations,
)
from app.models.finding import Finding
from tests import factories
from tests.vulnapp import vulnapp


def _finding(check: str, **evidence) -> Finding:
    return Finding(
        check=check, owasp_id=None, severity=Severity.low, title="t",
        description="d", evidence=evidence,
    )


# ---- the pure builder ----------------------------------------------------------

def test_discovered_paths_become_get_operations():
    ops = synthetic_operations([
        _finding("kali_discovery", path="/admin/debug"),
        _finding("kali_crawl", path="/internal/metrics"),
    ])
    by_path = {o.path: o for o in ops}
    assert set(by_path) == {"/admin/debug", "/internal/metrics"}
    assert all(o.method == "GET" for o in ops)
    assert all(o.id.startswith("discovered:") for o in ops)


def test_a_full_url_is_reduced_to_its_path():
    """A discovered URL must never point the probe at another host (SSRF)."""
    ops = synthetic_operations([
        _finding("kali_discovery", path="https://evil.example.com/shadow"),
    ])
    assert [o.path for o in ops] == ["/shadow"]


def test_a_bare_path_with_a_query_is_reduced_to_the_path():
    """A bare path carrying a query/fragment keeps only the path."""
    ops = synthetic_operations([
        _finding("kali_discovery", path="/admin/debug?verbose=1#top"),
    ])
    assert [o.path for o in ops] == ["/admin/debug"]


def test_arjun_params_are_attached_as_query_params():
    ops = synthetic_operations([
        _finding("kali_params", url="/search", params=["debug", "admin"]),
    ])
    assert len(ops) == 1
    names = {p["name"] for p in ops[0].params}
    assert names == {"debug", "admin"}
    assert all(p["in"] == "query" for p in ops[0].params)


def test_a_path_from_both_ffuf_and_arjun_is_one_operation():
    ops = synthetic_operations([
        _finding("kali_discovery", path="/x"),
        _finding("kali_params", url="/x", params=["q"]),
    ])
    assert len(ops) == 1
    assert [p["name"] for p in ops[0].params] == ["q"]


def test_documented_routes_are_not_reprobed_by_discovery():
    findings = [_finding("kali_crawl", path="/accounts/1")]
    documented = [factories.operation("GET", "/accounts/{account_id}")]
    assert synthetic_operations(findings, documented) == []


def test_new_param_on_a_documented_route_is_still_probed():
    findings = [_finding("kali_params", url="/search", params=["q", "debug"])]
    documented = [
        factories.operation(
            "GET",
            "/search",
            params=[{"name": "q", "in": "query", "required": False}],
        )
    ]
    ops = synthetic_operations(findings, documented)
    assert len(ops) == 1
    assert [param["name"] for param in ops[0].params] == ["debug"]


def test_non_discovery_findings_are_ignored():
    assert synthetic_operations([
        _finding("bola", path="/accounts/1"),
        _finding("security_headers", affected_endpoints=["GET /a"]),
    ]) == []


def test_empty_and_malformed_paths_are_dropped():
    ops = synthetic_operations([
        _finding("kali_discovery", path=""),
        _finding("kali_discovery"),  # no path key
        _finding("kali_params", url="/x", params="not-a-list"),
    ])
    assert ops == []


# ---- the check-set filter ------------------------------------------------------

def test_the_write_checks_are_never_in_the_discovery_set():
    """Shadow paths have no spec pairing to restore — nothing may mutate."""
    for key in ("write_authz", "mass_assignment", "schema_fuzz", "tls_config"):
        assert key not in DISCOVERY_CHECK_KEYS


def test_fuzzers_are_dropped_when_no_endpoint_has_a_parameter():
    bare = [TargetOperation(id="discovered:GET:/x", method="GET", path="/x", params=[])]
    keys = {c.key for c in relevant_checks(list(ALL_CHECKS), bare)}
    assert "reflected_injection" not in keys  # nothing to inject into
    assert "security_headers" in keys          # still worth probing


def test_fuzzers_are_kept_when_a_parameter_exists():
    withp = [TargetOperation(
        id="discovered:GET:/x", method="GET", path="/x",
        params=[{"name": "q", "in": "query", "required": False}],
    )]
    keys = {c.key for c in relevant_checks(list(ALL_CHECKS), withp)}
    assert "reflected_injection" in keys


def test_relevant_checks_only_draws_from_the_live_registry():
    """A key in the set but not registered simply does not appear."""
    ops = [TargetOperation(id="d", method="GET", path="/x", params=[])]
    selected = relevant_checks(list(ALL_CHECKS), ops)
    registered = {c.key for c in ALL_CHECKS}
    assert all(c.key in registered for c in selected)


# ---- end to end against the in-process target ----------------------------------

def _discovery_pass(ops, budget=150):
    """Run the discovery check set against `ops`, as the runner does."""
    from app.engine.run_record import append_finding
    from app.models.scan import Scan, ScanStatus

    scan = Scan(target_base_url="http://t", status=ScanStatus.draft)
    from fastapi.testclient import TestClient

    probe = HttpProbe(
        TestClient(vulnapp), max_requests=budget, operations=ops,
        credentials=factories.two_identities(),
    )
    ctx = ScanContext(
        base_url=factories.BASE_URL, operations=ops,
        credentials=factories.two_identities(), probe=probe, allow_mutation=False,
    )
    for check in relevant_checks(list(ALL_CHECKS), ops):
        probe.check_context = check.key
        for ef in check.run(ctx):
            ef.operation_id = None
            append_finding(scan, ef)
    return scan, probe


def test_a_discovered_leaky_endpoint_is_actually_tested():
    """`/users/{id}` (over-exposing) reached only via discovery is now scanned."""
    ops = synthetic_operations([_finding("kali_discovery", path="/users/1")])
    scan, _ = _discovery_pass(ops)
    exposure = [f for f in scan.findings if f.check == "data_exposure"]
    assert exposure, "the discovered endpoint's data exposure should be caught"
    assert any(f.evidence.get("issue") == "credential" for f in exposure)


def test_discovered_findings_are_not_tied_to_a_spec_operation():
    ops = synthetic_operations([_finding("kali_discovery", path="/debuginfo")])
    scan, _ = _discovery_pass(ops)
    assert scan.findings
    assert all(f.operation_id is None for f in scan.findings)


def test_the_pass_respects_its_own_budget():
    ops = synthetic_operations([_finding("kali_discovery", path="/debuginfo")])
    _, probe = _discovery_pass(ops, budget=3)
    assert probe.count <= 3, "the discovery pass must honour its request cap"
