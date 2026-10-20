"""Identity across runs: fingerprints, triage that survives, and the diff.

A scan you run twice should be able to tell you what changed. That needs one
thing the engine did not have — a finding that is recognisable as *the same
finding* next week — and everything here rests on it: a dismissed false positive
staying dismissed, and "three new highs" instead of "sixty findings".
"""
from __future__ import annotations

from app.engine.fingerprint import fingerprint, identity_parts
from app.scans.diff import diff_snapshots


def _row(fp: str, **kw):
    row = {
        "fingerprint": fp,
        "check": "bola",
        "severity": "high",
        "confidence": "verified",
        "title": "t",
        "owasp_id": "API1:2023",
        "verdict": "unreviewed",
    }
    row.update(kw)
    return row


# ---- the fingerprint -----------------------------------------------------------

def test_same_finding_hashes_the_same():
    ev = {"method": "GET", "path": "/accounts/{id}", "param": "id"}
    assert fingerprint("bola", "API1:2023", "Possible BOLA", ev) == fingerprint(
        "bola", "API1:2023", "Possible BOLA", dict(ev)
    )


def test_details_that_drift_between_runs_do_not_change_identity():
    """Status codes, samples, counts and rotating payloads must not matter."""
    base = {"method": "GET", "path": "/accounts/{id}"}
    drifted = {
        **base,
        "status": 200,
        "anon_status": 401,
        "response_sample": "…",
        "payload": "aidx9f3a' OR 1=1--",
        "object_ids": [7, 9, 11],
    }
    assert fingerprint("bola", "API1:2023", "t", base) == fingerprint(
        "bola", "API1:2023", "t", drifted
    )


def test_a_different_endpoint_or_parameter_is_a_different_finding():
    def fp(route: str, param: str) -> str:
        return fingerprint(
            "reflected_injection", "CWE-74", "t",
            {"route": route, "param": param, "location": "query", "family": "sqli"},
        )

    assert len({fp("/search", "q"), fp("/search", "name"), fp("/lookup", "q")}) == 3


def test_a_reflection_lead_is_one_finding_whatever_payload_carried_it():
    """Payloads rotate per run; the weakness — "q is reflected" — does not.

    Including the family would report the same lead as fixed-and-new on every
    scan, which is the failure mode a diff exists to avoid.
    """
    def fp(family: str) -> str:
        return fingerprint(
            "reflected_injection", "CWE-74", f"Reflected {family.upper()} via 'q'",
            {"route": "/search", "param": "q", "location": "query", "family": family,
             "payload": f"aidx9f3a-{family}"},
        )

    assert fp("sqli") == fp("xss") == fp("cmdi")


def test_the_families_that_are_the_finding_stay_in_the_identity():
    """A confirmed blind SSRF is not a confirmed RCE, and an LDAP error
    signature is not a SQL one — there the family names the weakness."""
    def oob(family: str) -> str:
        return fingerprint("oob_injection", "CWE-74", "t",
                           {"param": "url", "location": "query", "family": family})

    def sig(family: str) -> str:
        return fingerprint("signature_injection", "CWE-74", "t",
                           {"route": "/lookup", "param": "name", "family": family})

    assert oob("blind_ssrf") != oob("rce")
    assert sig("ldap") != sig("sqli")


def test_the_attacked_url_is_ignored_once_a_route_is_known():
    """A path parameter's attack URL contains the payload itself."""
    a = fingerprint("signature_injection", "CWE-74", "t",
                    {"route": "/accounts/{id}", "path": "/accounts/aidx1)(|(cn=*",
                     "param": "id", "location": "path", "family": "ldap"})
    b = fingerprint("signature_injection", "CWE-74", "t",
                    {"route": "/accounts/{id}", "path": "/accounts/aidx2\\",
                     "param": "id", "location": "path", "family": "ldap"})
    assert a == b


def test_the_check_is_part_of_the_identity():
    ev = {"method": "GET", "path": "/a"}
    assert fingerprint("bola", "API1:2023", "t", ev) != fingerprint("bfla", "API1:2023", "t", ev)


def test_header_findings_are_identified_by_which_headers():
    """Not by the endpoint list or the counts, which move as scope does.

    The sweep emits one finding per issue profile, so the headers are the whole
    identity. Including the endpoint list reported the same missing CSP as
    fixed-and-new the moment an endpoint re-entered scope — which a real
    re-scoped run did before this was narrowed.
    """
    a = fingerprint(
        "security_headers", "API8:2023", "Missing security headers (4) on all endpoints",
        {"missing": {"CSP": "absent", "HSTS": "absent"},
         "affected_endpoints": ["GET /a", "GET /b"], "probed_endpoints": 9},
    )
    b = fingerprint(
        "security_headers", "API8:2023", "Missing security headers (4) on 12 endpoints",
        {"missing": {"HSTS": "absent", "CSP": "absent"},        # order differs
         "affected_endpoints": ["GET /a", "GET /b", "GET /c"],  # scope grew
         "probed_endpoints": 41},                               # count differs
    )
    assert a == b

    different_header = fingerprint(
        "security_headers", "API8:2023", "t",
        {"missing": {"CSP": "absent"}, "affected_endpoints": ["GET /a", "GET /b"]},
    )
    assert different_header != a


def test_a_weak_header_changing_its_bad_value_is_still_one_finding():
    """Dict *keys* are identity; the observed value that made it weak is not."""
    a = fingerprint("security_headers", "API8:2023", "t",
                    {"weak": {"CSP": {"observed": "default-src *"}}})
    b = fingerprint("security_headers", "API8:2023", "t",
                    {"weak": {"CSP": {"observed": "script-src 'unsafe-inline'"}}})
    assert a == b


def test_evidence_with_no_identity_keys_falls_back_to_the_title():
    ev = {"host": "api.example.com", "cipher": "TLS_RSA_WITH_3DES_EDE_CBC_SHA"}
    parts = identity_parts("tls_config", "API8:2023", "Weak cipher negotiated", ev)
    assert any(p.startswith("title=") for p in parts)
    assert fingerprint("tls_config", "API8:2023", "Weak cipher", ev) != fingerprint(
        "tls_config", "API8:2023", "Expired certificate", ev
    )


def test_fingerprint_is_a_short_stable_hex_string():
    fp = fingerprint("bola", "API1:2023", "t", {"path": "/a"})
    assert len(fp) == 32 and all(c in "0123456789abcdef" for c in fp)


def test_missing_evidence_is_tolerated():
    assert fingerprint("bola", None, "t", None)
    assert fingerprint("bola", None, "t", {})


# ---- the engine stamps it ------------------------------------------------------

def test_append_finding_stamps_a_fingerprint():
    from app.domain.enums import Severity
    from app.engine.base import EngineFinding
    from app.engine.run_record import append_finding
    from app.models.scan import Scan, ScanStatus

    scan = Scan(target_base_url="http://t", status=ScanStatus.draft)
    append_finding(
        scan,
        EngineFinding(
            check="bola", owasp_id="API1:2023", severity=Severity.high, title="t",
            description="d", evidence={"method": "GET", "path": "/a"},
        ),
    )
    assert scan.findings[0].fingerprint


def test_append_finding_deduplicates_the_same_identity():
    from app.domain.enums import Severity
    from app.engine.base import EngineFinding
    from app.engine.run_record import append_finding
    from app.models.scan import Scan, ScanStatus

    scan = Scan(target_base_url="http://t", status=ScanStatus.draft)
    finding = EngineFinding(
        check="bola",
        owasp_id="API1:2023",
        severity=Severity.high,
        title="t",
        description="d",
        evidence={"method": "GET", "route": "/accounts/{id}"},
    )
    append_finding(scan, finding)
    append_finding(scan, finding)
    assert len(scan.findings) == 1


def test_two_engine_runs_produce_the_same_fingerprints():
    """The property the whole feature rests on, end to end."""
    from app.engine.run_record import append_finding
    from app.models.scan import Scan, ScanStatus
    from tests import factories

    def run_once(seed: int) -> set[str]:
        scan = Scan(target_base_url="http://t", status=ScanStatus.draft)
        for ef in factories.run_registry(
            factories.engine_operations(),
            credentials=factories.two_identities(),
            seed=seed,
        ):
            append_finding(scan, ef)
        return {f.fingerprint for f in scan.findings}

    # Different seeds rotate the payloads, which must not move identity.
    assert run_once(1) == run_once(2)


# ---- triage survives a re-run --------------------------------------------------

def test_triage_is_remembered_against_the_fingerprint():
    from app.domain.enums import Severity, Verdict
    from app.engine.run_record import apply_triage, record_triage
    from app.models.finding import Finding
    from app.models.scan import Scan, ScanStatus

    scan = Scan(target_base_url="http://t", status=ScanStatus.draft)
    old = Finding(check="ssrf", severity=Severity.low, title="t", description="",
                  evidence={}, fingerprint="abc123", verdict=Verdict.unreviewed)
    scan.findings.append(old)
    record_triage(scan, old, Verdict.dismissed)
    assert scan.triage == {"abc123": "dismissed"}

    # Next run: the row is new, the identity is not.
    scan.findings.clear()
    fresh = Finding(check="ssrf", severity=Severity.low, title="t", description="",
                    evidence={}, fingerprint="abc123", verdict=Verdict.unreviewed)
    scan.findings.append(fresh)
    assert apply_triage(scan) == 1
    assert fresh.verdict is Verdict.dismissed


def test_clearing_a_verdict_forgets_the_triage():
    from app.domain.enums import Severity, Verdict
    from app.engine.run_record import record_triage
    from app.models.finding import Finding
    from app.models.scan import Scan, ScanStatus

    scan = Scan(target_base_url="http://t", status=ScanStatus.draft)
    f = Finding(check="ssrf", severity=Severity.low, title="t", description="",
                evidence={}, fingerprint="abc123")
    scan.findings.append(f)
    record_triage(scan, f, Verdict.confirmed)
    record_triage(scan, f, Verdict.unreviewed)
    assert scan.triage == {}


def test_triage_for_a_finding_this_run_did_not_produce_is_kept():
    """It may come back when the endpoint is in scope again."""
    from app.engine.run_record import apply_triage
    from app.models.scan import Scan, ScanStatus

    scan = Scan(target_base_url="http://t", status=ScanStatus.draft)
    scan.triage = {"gone": "dismissed"}
    assert apply_triage(scan) == 0
    assert scan.triage == {"gone": "dismissed"}


def test_a_finding_with_no_fingerprint_is_not_remembered():
    from app.domain.enums import Severity, Verdict
    from app.engine.run_record import record_triage
    from app.models.finding import Finding
    from app.models.scan import Scan, ScanStatus

    scan = Scan(target_base_url="http://t", status=ScanStatus.draft)
    f = Finding(check="ssrf", severity=Severity.low, title="t", description="",
                evidence={}, fingerprint="")
    record_triage(scan, f, Verdict.dismissed)
    assert scan.triage in ({}, None)


# ---- the diff ------------------------------------------------------------------

def test_diff_splits_new_fixed_and_still_there():
    older = [_row("a"), _row("b")]
    newer = [_row("b"), _row("c")]
    result = diff_snapshots(older, newer)
    assert [r["fingerprint"] for r in result.added] == ["c"]
    assert [r["fingerprint"] for r in result.resolved] == ["a"]
    assert [r["fingerprint"] for r in result.unchanged] == ["b"]
    assert result.unmatchable == 0


def test_diff_of_identical_runs_reports_no_change():
    rows = [_row("a"), _row("b")]
    result = diff_snapshots(rows, list(rows))
    assert not result.added and not result.resolved
    assert len(result.unchanged) == 2


def test_unfingerprinted_rows_are_counted_not_called_new():
    """An older run predating the feature must not read as 12 regressions."""
    older = [_row(""), _row("")]
    newer = [_row("a")]
    result = diff_snapshots(older, newer)
    assert result.unmatchable == 2
    assert [r["fingerprint"] for r in result.added] == ["a"]
    assert result.resolved == []


def test_diff_orders_by_severity_then_confidence():
    newer = [
        _row("low", severity="low", confidence="verified"),
        _row("hi-lead", severity="high", confidence="heuristic"),
        _row("hi-proof", severity="high", confidence="verified"),
    ]
    result = diff_snapshots([], newer)
    assert [r["fingerprint"] for r in result.added] == ["hi-proof", "hi-lead", "low"]


def test_an_empty_older_run_makes_everything_new():
    result = diff_snapshots([], [_row("a")])
    assert len(result.added) == 1 and not result.resolved


def test_findings_from_a_pass_the_newer_run_left_off_are_not_called_fixed():
    """A manual mutate:true run vs a scheduled read-only one: nothing was fixed."""
    older = [_row("w", check="write_authz"), _row("h", check="security_headers")]
    result = diff_snapshots(
        older, [], not_retested=lambda row: row["check"] == "write_authz"
    )
    assert [r["fingerprint"] for r in result.not_retested] == ["w"]
    assert [r["fingerprint"] for r in result.resolved] == ["h"]


def test_required_passes_come_from_the_registry_and_adjunct_names():
    from app.engine.checks import premium_check_keys
    from app.scans.run_options import required_passes

    assert required_passes("write_authz") == {"mutate"}
    assert required_passes("zap") == {"zap"}
    assert required_passes("kali_nuclei") == {"kali"}
    assert required_passes("sqlmap_confirm") == {"confirm"}
    assert required_passes("testssl") == {"testssl"}
    assert required_passes("schema_fuzz") == {"fuzz"}
    assert required_passes("security_headers") == frozenset()
    # Gated inside run(), not by a trait.
    assert required_passes("xxe_confirmation") == {"premium", "mutate"}
    assert required_passes("deserialization") == {"premium", "mutate"}
    assert required_passes("adaptive_validation") == {"premium", "adaptive"}
    # Body-sink injection needs mutate; the same check on GET does not.
    assert required_passes("reflected_injection", "POST") == {"mutate"}
    assert required_passes("reflected_injection", "GET") == frozenset()
    assert required_passes("reflected_injection") == frozenset()
    for key in premium_check_keys():
        assert "premium" in required_passes(key)


def test_only_finding_passes_turned_off_count_as_dropped():
    from app.scans.run_options import dropped_passes

    # plan/adjudicate reorder and judge; they never decide what can be found.
    assert dropped_passes({"mutate": True, "plan": True}, {}) == {"mutate"}
    assert dropped_passes({}, {"mutate": True}) == frozenset()
    assert dropped_passes(None, None) == frozenset()


# ---- through the API -----------------------------------------------------------

def test_diff_endpoint_compares_the_two_latest_runs(
    client, db_session, make_scan, engine_client
):
    from app.engine.runner import run_scan

    scan = make_scan()
    run_scan(db_session, scan, client=engine_client)
    run_scan(db_session, scan, client=engine_client)

    body = client.get(f"/scans/{scan.id}/diff").json()
    assert body["from_run"] == 1 and body["to_run"] == 2
    # Nothing about the target changed between the two runs.
    assert body["added"] == [] and body["resolved"] == []
    assert body["unchanged"], "two identical runs should match on every finding"
    assert body["unmatchable"] == 0


def test_diff_does_not_call_findings_from_a_dropped_pass_fixed(
    client, db_session, make_scan, engine_client
):
    """Run 1 tested writes, run 2 did not: its write findings were never re-checked."""
    from app.engine.runner import run_scan
    from app.scans.run_options import RunOptions, required_passes

    scan = make_scan()
    run_scan(db_session, scan, client=engine_client, options=RunOptions(mutate=True))
    run_scan(db_session, scan, client=engine_client)

    runs = client.get(f"/scans/{scan.id}/runs").json()  # newest first
    assert runs[1]["options"]["mutate"] is True and runs[0]["options"]["mutate"] is False

    body = client.get(f"/scans/{scan.id}/diff").json()
    assert body["options_changed"] is True
    # Not re-tested: a write check, or a check the read-only run had to skip —
    # BFLA's only privileged target here is a POST, so it skips without writes.
    skipped = set(runs[0]["gaps"].get("skipped_checks") or [])
    assert "bfla" in skipped
    assert all(
        "mutate" in required_passes(r["check"]) or r["check"] in skipped
        for r in body["not_retested"]
    )
    assert not any(
        "mutate" in required_passes(r["check"]) or r["check"] in skipped
        for r in body["resolved"]
    )


def test_diff_flags_a_change_of_executor(client, db_session, make_scan, engine_client):
    """Two runs on different executors (server vs local runner) is a partial compare."""
    from app.engine.runner import run_scan

    scan = make_scan()
    run_scan(db_session, scan, client=engine_client)
    run_scan(db_session, scan, client=engine_client)
    # Both ran on the server worker: no executor change.
    assert client.get(f"/scans/{scan.id}/diff").json()["executor_changed"] is False

    # Re-run 2 as if it came from the local runner.
    scan.runs[1].executor = {"kind": "local_runner", "max_requests": 500}
    db_session.commit()
    assert client.get(f"/scans/{scan.id}/diff").json()["executor_changed"] is True


def test_diff_needs_two_runs(client, db_session, make_scan, engine_client):
    from app.engine.runner import run_scan

    scan = make_scan()
    assert client.get(f"/scans/{scan.id}/diff").status_code == 409
    run_scan(db_session, scan, client=engine_client)
    r = client.get(f"/scans/{scan.id}/diff")
    assert r.status_code == 409
    assert "two runs" in r.json()["detail"]


def test_diff_rejects_a_run_number_that_does_not_exist(
    client, db_session, make_scan, engine_client
):
    from app.engine.runner import run_scan

    scan = make_scan()
    run_scan(db_session, scan, client=engine_client)
    run_scan(db_session, scan, client=engine_client)
    assert client.get(f"/scans/{scan.id}/diff?from_run=9").status_code == 404


def test_diff_rejects_a_reversed_run_pair(client, db_session, make_scan, engine_client):
    """A diff is directional; reversing the pair would invert the buckets."""
    from app.engine.runner import run_scan

    scan = make_scan()
    run_scan(db_session, scan, client=engine_client)
    run_scan(db_session, scan, client=engine_client)
    assert client.get(f"/scans/{scan.id}/diff?from_run=2&to_run=1").status_code == 422


def test_diff_accepts_an_explicit_valid_pair(client, db_session, make_scan, engine_client):
    """An explicit from_run/to_run pair selects and echoes the intended snapshots."""
    from app.engine.runner import run_scan

    scan = make_scan()
    run_scan(db_session, scan, client=engine_client)
    run_scan(db_session, scan, client=engine_client)
    r = client.get(f"/scans/{scan.id}/diff?from_run=1&to_run=2")
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["from_run"] == 1 and body["to_run"] == 2


def test_a_dismissed_finding_stays_dismissed_across_a_re_run(
    client, db_session, make_scan, engine_client
):
    """The workflow this exists for: triage once, not once per run."""
    from app.engine.runner import run_scan

    scan = make_scan()
    run_scan(db_session, scan, client=engine_client)
    sid = str(scan.id)

    first = client.get(f"/scans/{sid}/findings").json()
    target = first[0]
    client.patch(
        f"/scans/{sid}/findings/{target['id']}", json={"verdict": "dismissed"}
    )

    run_scan(db_session, scan, client=engine_client)

    after = client.get(f"/scans/{sid}/findings").json()
    same = [f for f in after if f["fingerprint"] == target["fingerprint"]]
    assert same, "the finding should be produced again by an unchanged target"
    assert same[0]["verdict"] == "dismissed"
    assert same[0]["id"] != target["id"], "it is a new row, matched by identity"
