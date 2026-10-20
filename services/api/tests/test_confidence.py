"""The evidence tier: that checks grade themselves, and that grading is carried.

The heuristic/verified distinction is the product's central claim — a reflection
lead is not a proven cross-identity write, and everything downstream (report
order, SARIF levels, a CI gate) depends on the two never being confused. These
tests pin the grading at the checks that produce it and follow it through the
consumers.
"""
from __future__ import annotations

from types import SimpleNamespace

from app.domain.enums import CONFIDENCE_RANK, Confidence, Severity, Verdict
from app.models.finding import Finding, sort_findings
from tests import factories
from tests.vulnapp import vulnapp

OPERATIONS = factories.engine_operations()
CREDS = factories.two_identities()


# ---- the engine grades its own findings ---------------------------------------

def test_bola_with_two_identities_is_verified():
    """A cross-identity read the check proved is not a lead."""
    from app.engine.checks.authz import BolaCheck

    findings = factories.run_one(BolaCheck(), OPERATIONS, credentials=CREDS)
    assert findings
    assert findings[0].confidence is Confidence.verified


def test_bola_single_identity_sibling_probe_is_only_a_lead():
    """The same check, degraded: one identity cannot prove cross-tenant access."""
    from app.engine.base import TargetOperation
    from app.engine.checks.authz import BolaCheck

    ops = OPERATIONS + [
        TargetOperation(id="op-acct-list", method="GET", path="/accounts", params=[])
    ]
    findings = factories.run_one(BolaCheck(), ops, credentials=CREDS[:1])
    assert findings
    assert findings[0].confidence is Confidence.heuristic


def test_reflected_injection_is_a_lead_not_a_confirmation():
    """A reflected marker proves input reached the response, nothing more."""
    from app.engine.checks.injection import ReflectedInjectionCheck

    findings = factories.run_one(ReflectedInjectionCheck(), OPERATIONS)
    assert findings
    assert all(f.confidence is Confidence.heuristic for f in findings)


def test_engine_findings_default_to_the_cautious_tier():
    """An ungraded finding must read as a lead — never as proof by omission."""
    from app.engine.base import EngineFinding

    ef = EngineFinding(
        check="x",
        owasp_id=None,
        severity=Severity.high,
        title="t",
        description="d",
        evidence={},
    )
    assert ef.confidence is Confidence.heuristic


def test_a_scan_produces_both_tiers():
    """The smoke path: a full registry run grades findings on both sides."""
    findings = factories.run_registry(OPERATIONS, credentials=CREDS)
    tiers = {f.confidence for f in findings}
    assert Confidence.verified in tiers
    assert Confidence.heuristic in tiers


# ---- the tier survives the trip into the database ------------------------------

def test_append_finding_carries_the_tier():
    from app.engine.base import EngineFinding
    from app.engine.run_record import append_finding
    from app.models.scan import Scan, ScanStatus

    scan = Scan(target_base_url="http://t", status=ScanStatus.draft)
    append_finding(
        scan,
        EngineFinding(
            check="write_authz",
            owasp_id="API1:2023",
            severity=Severity.critical,
            title="write persisted",
            description="d",
            evidence={},
            confidence=Confidence.verified,
        ),
    )
    assert scan.findings[0].confidence is Confidence.verified


def test_run_snapshot_records_the_tier():
    """Archived runs keep it, so the run history can show what was proven."""
    from fastapi.testclient import TestClient

    from app.engine.base import HttpProbe
    from app.engine.run_record import finish_run
    from app.models.scan import Scan, ScanRun, ScanStatus

    scan = Scan(target_base_url="http://t", status=ScanStatus.draft)
    scan.findings.append(
        Finding(
            check="tls_config",
            owasp_id="API8:2023",
            severity=Severity.medium,
            title="weak cipher",
            description="d",
            evidence={},
            confidence=Confidence.verified,
        )
    )
    run = ScanRun(run_number=1)
    finish_run(run, "completed", scan, HttpProbe(TestClient(vulnapp)))
    assert run.findings_snapshot[0]["confidence"] == "verified"


# ---- report ordering ----------------------------------------------------------

def test_sort_findings_puts_proof_above_leads_within_a_severity():
    def f(check: str, confidence: Confidence) -> Finding:
        return Finding(
            check=check,
            owasp_id=None,
            severity=Severity.high,
            title=check,
            description="",
            evidence={},
            confidence=confidence,
        )

    # `aaa` sorts first by check name, so only the tier can reorder these.
    ordered = sort_findings([f("aaa", Confidence.heuristic), f("zzz", Confidence.verified)])
    assert [x.check for x in ordered] == ["zzz", "aaa"]


def test_severity_still_outranks_confidence():
    """A verified low must not outrank an unconfirmed critical."""
    crit = Finding(
        check="a", owasp_id=None, severity=Severity.critical, title="a",
        description="", evidence={}, confidence=Confidence.heuristic,
    )
    low = Finding(
        check="b", owasp_id=None, severity=Severity.low, title="b",
        description="", evidence={}, confidence=Confidence.verified,
    )
    assert [f.check for f in sort_findings([low, crit])] == ["a", "b"]


def test_sort_tolerates_an_unrefreshed_column_default():
    """Column defaults are absent on in-memory rows until a refresh."""
    f = Finding(
        check="a", owasp_id=None, severity=Severity.high, title="a",
        description="", evidence={},
    )
    assert sort_findings([f]) == [f]
    assert CONFIDENCE_RANK[Confidence.verified] > CONFIDENCE_RANK[Confidence.heuristic]


# ---- SARIF --------------------------------------------------------------------

def _sarif_finding(severity: Severity, confidence: Confidence):
    return SimpleNamespace(
        check="bola",
        owasp_id="API1:2023",
        severity=severity,
        confidence=confidence,
        title="Possible BOLA on GET /accounts/{id}",
        description="cross-identity read",
        evidence={"path": "/accounts/1"},
        remediation="",
        references=[],
        verdict=Verdict.confirmed,
    )


def _level(severity: Severity, confidence: Confidence) -> str:
    from app.scans.sarif import to_sarif

    scan = SimpleNamespace(
        target_base_url="https://api.example.com",
        findings=[_sarif_finding(severity, confidence)],
    )
    return to_sarif(scan)["runs"][0]["results"][0]["level"]


def test_only_verified_evidence_reaches_sarif_error():
    """A dashboard that errors on leads is a dashboard people learn to ignore."""
    assert _level(Severity.high, Confidence.verified) == "error"
    assert _level(Severity.high, Confidence.heuristic) == "warning"
    assert _level(Severity.medium, Confidence.heuristic) == "note"
    # `note` is the floor — a low lead does not demote below it.
    assert _level(Severity.low, Confidence.heuristic) == "note"


def test_sarif_publishes_the_tier_as_a_property():
    from app.scans.sarif import to_sarif

    scan = SimpleNamespace(
        target_base_url="https://api.example.com",
        findings=[_sarif_finding(Severity.high, Confidence.verified)],
    )
    props = to_sarif(scan)["runs"][0]["results"][0]["properties"]
    assert props["confidence"] == "verified"


def _rule(*findings):
    from app.scans.sarif import to_sarif

    scan = SimpleNamespace(
        target_base_url="https://api.example.com", findings=list(findings)
    )
    return to_sarif(scan)["runs"][0]["tool"]["driver"]["rules"][0]


def test_sarif_rule_carries_a_security_severity_and_tags():
    """Code scanning only ranks an alert when the *rule* scores it."""
    props = _rule(_sarif_finding(Severity.high, Confidence.verified))["properties"]
    assert props["security-severity"] == "8.0"
    assert "security" in props["tags"]
    # "bola" is CWE-639 in the catalogue; the tag GitHub groups by is lowercase.
    assert "external/cwe/cwe-639" in props["tags"]


def test_sarif_scores_a_heuristic_lead_one_step_down():
    """Heuristics are ranked below proven evidence — the tier must survive."""
    props = _rule(_sarif_finding(Severity.high, Confidence.heuristic))["properties"]
    assert props["security-severity"] == "5.5"


def test_sarif_rule_scores_the_worst_of_its_findings():
    props = _rule(
        # heuristic critical -> high -> 8.0 beats verified medium -> 5.5
        _sarif_finding(Severity.critical, Confidence.heuristic),
        _sarif_finding(Severity.medium, Confidence.verified),
    )["properties"]
    assert props["security-severity"] == "8.0"


def test_sarif_omits_security_severity_for_an_informational_rule():
    props = _rule(_sarif_finding(Severity.info, Confidence.verified))["properties"]
    assert "security-severity" not in props
