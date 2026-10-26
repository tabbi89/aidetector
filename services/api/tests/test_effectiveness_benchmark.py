"""The scoring half of the real-target effectiveness benchmark.

The live driver needs a running stack + target (see benchmarks/README.md); the
scoring is pure and pinned here so recall/precision math can't drift.
"""
from __future__ import annotations

import json

from benchmarks.effectiveness import (
    ExpectedVuln,
    Finding,
    load_manifest,
    score,
)


def _expected():
    return [
        ExpectedVuln("API1:2023", "/users/v1/{username}", "GET", note="BOLA read"),
        ExpectedVuln("API1:2023", "/books/v1/{book}", "GET"),
        ExpectedVuln("API3:2023", "/users/v1/_debug", "GET", check="data_exposure"),
        ExpectedVuln("API6:2023", "/users/v1/register", "POST", check="mass_assignment"),
    ]


def test_recall_counts_each_documented_weakness_the_scan_found():
    findings = [
        # Matches the BOLA read (route template matches a rendered id).
        Finding("bola", "API1:2023", "/users/v1/alice", "GET"),
        # Matches the data-exposure debug endpoint.
        Finding("data_exposure", "API3:2023", "/users/v1/_debug", "GET"),
    ]
    result = score("vampi", findings, _expected())

    assert result.covered == 2
    assert result.expected_total == 4
    assert result.recall == 0.5
    missed = {(m.owasp_id, m.route) for m in result.missed}
    assert ("API1:2023", "/books/v1/{book}") in missed
    assert ("API6:2023", "/users/v1/register") in missed


def test_per_category_recall_is_broken_out():
    findings = [Finding("bola", "API1:2023", "/users/v1/bob", "GET")]
    result = score("vampi", findings, _expected())

    assert result.categories["API1:2023"].expected == 2
    assert result.categories["API1:2023"].found == 1
    assert result.categories["API1:2023"].recall == 0.5
    assert result.categories["API3:2023"].found == 0


def test_a_finding_the_manifest_did_not_predict_is_unexpected_not_a_match():
    findings = [
        Finding("bola", "API1:2023", "/users/v1/carol", "GET"),  # matches
        Finding("security_headers", "API8:2023", "/users/v1/me", "GET"),  # not in manifest
    ]
    result = score("vampi", findings, _expected())

    assert result.matched_findings == 1
    assert result.findings_total == 2
    assert result.manifest_precision == 0.5
    assert [f.check for f in result.unexpected] == ["security_headers"]


def test_method_and_check_tighten_the_match():
    expected = [ExpectedVuln("API6:2023", "/users/v1/register", "POST", check="mass_assignment")]
    wrong_method = [Finding("mass_assignment", "API6:2023", "/users/v1/register", "GET")]
    wrong_check = [Finding("business_flow", "API6:2023", "/users/v1/register", "POST")]
    right = [Finding("mass_assignment", "API6:2023", "/users/v1/register", "POST")]

    assert score("t", wrong_method, expected).covered == 0
    assert score("t", wrong_check, expected).covered == 0
    assert score("t", right, expected).covered == 1


def test_shipped_manifests_load_and_use_emitted_owasp_ids():
    from pathlib import Path

    emitted = {"API1:2023", "API2:2023", "API3:2023", "API4:2023", "API5:2023",
               "API6:2023", "API7:2023", "API8:2023", "API9:2023", "API10:2023", "CWE-74"}
    root = Path(__file__).resolve().parents[1] / "benchmarks" / "targets"
    for name in ("vampi.json", "crapi.json"):
        target, expected = load_manifest(root / name)
        assert target and expected, f"{name} should name a target and list weaknesses"
        for e in expected:
            assert e.owasp_id in emitted, f"{name}: {e.owasp_id} is not an id the engine emits"
            assert e.route.startswith("/"), f"{name}: route must be a path"


def test_to_dict_is_json_serializable_and_carries_the_scope_caveat():
    result = score("t", [Finding("bola", "API1:2023", "/users/v1/x", "GET")], _expected())
    blob = json.dumps(result.to_dict())
    assert "ground-truth manifest" in blob
    assert "not confirmed false positives" in blob
