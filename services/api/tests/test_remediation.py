"""Remediation: every check has a fix, shaped by the finding's own evidence.

The catalogue is a hand-maintained mirror of the check registry, so the first
test here is the guard that stops a new check shipping without advice. The rest
pin the two properties that make the advice usable: it names the endpoint the
finding is about, and a check that changes its evidence shape can never break a
scan by leaving a template unfilled.
"""
from __future__ import annotations

from types import SimpleNamespace

import pytest

from app.domain.enums import Confidence, Severity, Verdict
from app.engine.checks import ALL_CHECKS
from app.engine.remediation import CATALOGUE, cwe, knowledge, remediate
from tests import factories

# Check keys produced outside the registry, by the adjunct tools.
ADJUNCT_KEYS = [
    "source_runtime_cve",
    "zap",
    "testssl",
    "kali_nuclei",
    "kali_discovery",
    "kali_crawl",
    "kali_params",
    "kali_nikto",
    "kali_whatweb",
    "sqlmap_confirm",
    "dalfox_confirm",
    "commix_confirm",
    "tplmap_confirm",
    "adaptive_validation",
]


# ---- the catalogue mirrors the engine -----------------------------------------

def test_every_registered_check_has_remediation():
    """A finding with no fix is a problem report, not a work item."""
    missing = sorted({c.key for c in ALL_CHECKS} - set(CATALOGUE))
    assert not missing, (
        f"checks with no entry in app/engine/remediation.py: {missing}. "
        "The catalogue is a hand-maintained mirror of the check registry."
    )


@pytest.mark.parametrize("key", ADJUNCT_KEYS)
def test_adjunct_check_keys_have_remediation(key: str):
    assert key in CATALOGUE, f"adjunct check '{key}' has no catalogue entry"


def test_catalogue_documents_no_check_that_left_the_engine():
    known = {c.key for c in ALL_CHECKS} | set(ADJUNCT_KEYS)
    stale = sorted(set(CATALOGUE) - known)
    assert not stale, f"remediation.py describes checks nothing emits: {stale}"


@pytest.mark.parametrize("key", sorted(CATALOGUE))
def test_every_entry_is_populated(key: str):
    entry = CATALOGUE[key]
    assert entry.summary.strip()
    assert len(entry.remediation) > 80, "remediation should say what to change"
    assert entry.references, "a fix should point somewhere for the detail"
    assert all(u.startswith("https://") for u in entry.references)


# ---- templates are shaped by evidence ------------------------------------------

def test_remediation_names_the_endpoint_from_evidence():
    text, refs = remediate("bola", {"path": "/accounts/7", "method": "GET"})
    assert "/accounts/7" in text
    assert refs


def test_the_route_is_preferred_over_the_probed_url():
    """A fix is made in a handler, so name the route, not one rendered URL."""
    text, _ = remediate(
        "bola",
        {"method": "GET", "route": "/accounts/{id}", "path": "/accounts/7"},
    )
    assert "/accounts/{id}" in text
    assert "/accounts/7" not in text


def test_missing_evidence_degrades_to_prose_rather_than_raising():
    """A check that changes its evidence keys must not break a scan."""
    text, _ = remediate("bola", {})
    assert "the affected endpoint" in text
    assert "{path}" not in text and "None" not in text


def test_evidence_of_the_wrong_type_is_ignored():
    """Only scalars interpolate — a dict or list would render as noise."""
    text, _ = remediate("bola", {"path": {"nested": "thing"}, "method": ["GET"]})
    assert "the affected endpoint" in text
    assert "nested" not in text


def test_unknown_check_gets_no_advice():
    """Better bare than advice about the wrong weakness."""
    assert remediate("a_check_that_does_not_exist", {"path": "/x"}) == ("", [])


def test_knowledge_and_cwe_helpers():
    assert cwe("bola") == "CWE-639"
    assert cwe("nope") is None
    assert knowledge("ssrf") is not None
    assert knowledge("nope") is None


# ---- the wiring ----------------------------------------------------------------

def test_append_finding_fills_remediation_from_the_catalogue():
    from app.engine.base import EngineFinding
    from app.engine.run_record import append_finding
    from app.models.scan import Scan, ScanStatus

    scan = Scan(target_base_url="http://t", status=ScanStatus.draft)
    append_finding(
        scan,
        EngineFinding(
            check="bola",
            owasp_id="API1:2023",
            severity=Severity.high,
            title="Possible BOLA",
            description="d",
            evidence={"path": "/accounts/7", "method": "GET"},
            confidence=Confidence.verified,
        ),
    )
    f = scan.findings[0]
    assert "/accounts/7" in f.remediation
    assert f.references


def test_a_check_can_override_the_catalogue():
    """ZAP and nuclei ship alert-specific text that beats a generic line."""
    from app.engine.base import EngineFinding
    from app.engine.run_record import append_finding
    from app.models.scan import Scan, ScanStatus

    scan = Scan(target_base_url="http://t", status=ScanStatus.draft)
    append_finding(
        scan,
        EngineFinding(
            check="zap",
            owasp_id=None,
            severity=Severity.medium,
            title="ZAP: something",
            description="d",
            evidence={},
            remediation="Set the X-Frobnicate header on every response.",
        ),
    )
    assert scan.findings[0].remediation == (
        "Set the X-Frobnicate header on every response."
    )


def test_zap_alerts_carry_their_own_solution():
    from app.engine.zap import map_alerts

    findings = map_alerts(
        [{"risk": "Medium", "alert": "Missing Anti-clickjacking Header",
          "solution": "Configure the web server to include X-Frame-Options."}]
    )
    assert findings[0].remediation.startswith("Configure the web server")


def test_a_real_scan_produces_findings_that_say_what_to_change():
    """End to end: every finding a registry run produces carries a fix."""
    from app.engine.run_record import append_finding
    from app.models.scan import Scan, ScanStatus

    scan = Scan(target_base_url="http://t", status=ScanStatus.draft)
    for ef in factories.run_registry(
        factories.engine_operations(), credentials=factories.two_identities()
    ):
        append_finding(scan, ef)

    assert scan.findings
    bare = sorted({f.check for f in scan.findings if not f.remediation})
    assert not bare, f"findings with no remediation: {bare}"


# ---- SARIF carries it where CI can see it --------------------------------------

def test_sarif_rule_help_and_result_remediation():
    from types import SimpleNamespace

    from app.domain.enums import Verdict
    from app.scans.sarif import to_sarif

    finding = SimpleNamespace(
        check="bola",
        owasp_id="API1:2023",
        severity=Severity.high,
        confidence=Confidence.verified,
        title="Possible BOLA on GET /accounts/{id}",
        description="cross-identity read",
        evidence={"path": "/accounts/7", "method": "GET"},
        remediation="Authorize the object in the handler for GET /accounts/7.",
        references=["https://owasp.org/API-Security/editions/2023/en/0x11-t10/"],
        verdict=Verdict.confirmed,
    )
    scan = SimpleNamespace(
        target_base_url="https://api.example.com", findings=[finding]
    )
    run = to_sarif(scan)["runs"][0]

    rule = run["tool"]["driver"]["rules"][0]
    assert rule["properties"]["cwe"] == "CWE-639"
    assert "**References**" in rule["help"]["markdown"]
    assert rule["help"]["text"]
    # Rule help is evidence-free; it must not leak raw template placeholders.
    assert "{" not in rule["help"]["text"]
    assert "{method}" not in rule["help"]["markdown"]

    result = run["results"][0]
    assert "Fix: Authorize the object" in result["message"]["text"]
    assert result["properties"]["remediation"].startswith("Authorize the object")


def test_sarif_derives_remediation_for_a_finding_recorded_before_the_catalogue():
    from types import SimpleNamespace

    from app.domain.enums import Verdict
    from app.scans.sarif import to_sarif

    finding = SimpleNamespace(
        check="ssrf",
        owasp_id="API7:2023",
        severity=Severity.medium,
        confidence=Confidence.heuristic,
        title="URL parameter",
        description="d",
        evidence={"path": "/webhooks", "param": "callback"},
        remediation="",           # stored empty by an older run
        references=[],
        verdict=Verdict.unreviewed,
    )
    scan = SimpleNamespace(
        target_base_url="https://api.example.com", findings=[finding]
    )
    result = to_sarif(scan)["runs"][0]["results"][0]
    assert "/webhooks" in result["properties"]["remediation"]


def test_pdf_export_survives_markup_in_evidence_derived_text():
    """Remediation carries paths and params from the target — escape them.

    reportlab parses a paragraph as markup, so an unescaped `<` or `&` from a
    target's own URL would abort the export of the whole report.
    """
    from app.domain.enums import Verdict
    from app.models.finding import Finding
    from app.models.scan import Scan, ScanStatus
    from app.scans.report import build_report

    scan = Scan(target_base_url="https://api.example.com", status=ScanStatus.completed)
    scan.findings.append(
        Finding(
            check="ssrf",
            owasp_id="API7:2023",
            severity=Severity.medium,
            confidence=Confidence.heuristic,
            title="t",
            description="d",
            evidence={},
            verdict=Verdict.unreviewed,
            remediation="The '<script>&' parameter on /a?b=1&c=2 accepts a URL.",
            references=[],
        )
    )
    assert build_report(scan)


def test_html_report_escapes_remediation_and_links_references():
    from app.domain.enums import Verdict
    from app.models.finding import Finding
    from app.models.scan import Scan, ScanStatus
    from app.scans.report import build_report_html

    scan = Scan(target_base_url="https://api.example.com", status=ScanStatus.completed)
    scan.findings.append(
        Finding(
            check="bola",
            owasp_id="API1:2023",
            severity=Severity.high,
            confidence=Confidence.verified,
            title="t",
            description="d",
            evidence={},
            verdict=Verdict.unreviewed,
            remediation="Authorize <the> object.",
            references=["https://owasp.org/API-Security/"],
        )
    )
    html = build_report_html(scan)
    assert "Authorize &lt;the&gt; object." in html
    assert '<a href="https://owasp.org/API-Security/"' in html


def test_sarif_shape():
    from app.scans.sarif import to_sarif

    finding = SimpleNamespace(
        check="bola",
        owasp_id="API1:2023",
        severity=Severity.high,
        confidence=Confidence.verified,
        title="Possible BOLA on GET /accounts/{id}",
        description="cross-identity read",
        evidence={"path": "/accounts/1"},
        remediation="",
        references=[],
        verdict=Verdict.confirmed,
    )
    scan = SimpleNamespace(
        target_base_url="https://api.example.com", findings=[finding]
    )
    doc = to_sarif(scan)
    assert doc["version"] == "2.1.0"
    run = doc["runs"][0]
    assert run["tool"]["driver"]["name"] == "aidetector"
    assert run["results"][0]["ruleId"] == "bola"
    assert run["results"][0]["level"] == "error"
    assert run["results"][0]["properties"]["cwe"] == "CWE-639"
