"""sqlmap confirmation tests — selection/parsing are pure; the runner is faked."""
from __future__ import annotations

from app.domain.enums import Severity
from app.engine.sqlmap_confirm import (
    SqlmapConfirmer,
    build_command,
    build_url,
    parse_output,
    select_sqli_targets,
)
from tests.factories import injection_lead

VULN_OUTPUT = """
sqlmap identified the following injection point(s) with a total of 42 HTTP(s) requests:
---
Parameter: id (GET)
    Type: boolean-based blind
    Title: AND boolean-based blind - WHERE or HAVING clause
    Type: time-based blind
    Title: MySQL >= 5.0.12 AND time-based blind (query SLEEP)
---
GET parameter 'id' is vulnerable. Do you want to keep testing the others?
"""

NOT_VULN_OUTPUT = """
[WARNING] GET parameter 'id' does not seem to be injectable
[CRITICAL] all tested parameters do not appear to be injectable
"""



def test_select_sqli_targets_filters_dedupes_and_caps():
    findings = [
        injection_lead("sqli", "/a", "x"),
        injection_lead("sqli", "/a", "x"),          # duplicate (path, param)
        injection_lead("xss", "/a", "y"),           # wrong family
        injection_lead("sqli", "/b", "z", check="signature_injection"),
        injection_lead("sqli", "/c", "w"),
    ]
    targets = select_sqli_targets(findings, max_targets=2)
    assert [(t["path"], t["param"]) for t in targets] == [("/a", "x"), ("/b", "z")]
    assert targets[1]["source_check"] == "signature_injection"
    assert targets[0]["operation_id"] == "op-1"


def test_build_url_and_command():
    url = build_url("http://t:9000/", "/items", "id")
    assert url == "http://t:9000/items?id=1"
    argv = build_command("sqlmap", url)
    assert argv[0] == "sqlmap" and "-u" in argv and url in argv
    assert "--batch" in argv  # never interactive


def test_parse_output_detects_vulnerability_and_techniques():
    vuln, techniques = parse_output(VULN_OUTPUT)
    assert vuln is True
    assert "boolean-based blind" in techniques[0]
    assert parse_output(NOT_VULN_OUTPUT) == (False, [])


def test_confirmer_maps_vulnerable_target():
    calls = []

    def fake_execute(argv, timeout):
        calls.append(argv)
        return 0, VULN_OUTPUT

    confirmer = SqlmapConfirmer("sqlmap", execute=fake_execute)
    targets = select_sqli_targets([injection_lead("sqli", "/items", "id")])
    findings = confirmer.run("http://t:9000", targets)
    assert len(findings) == 1
    f = findings[0]
    assert f.check == "sqlmap_confirm"
    assert f.severity == Severity.high
    assert f.owasp_id == "CWE-89"
    assert f.evidence["url"] == "http://t:9000/items?id=1"
    assert f.evidence["techniques"]
    assert f.operation_id == "op-1"


def test_confirmer_not_vulnerable_yields_nothing():
    confirmer = SqlmapConfirmer("sqlmap", execute=lambda argv, t: (0, NOT_VULN_OUTPUT))
    targets = select_sqli_targets([injection_lead("sqli", "/items", "id")])
    assert confirmer.run("http://t:9000", targets) == []


def test_confirmer_skips_failing_target_and_continues():
    def flaky(argv, timeout):
        if "bad" in argv[argv.index("-u") + 1]:
            raise RuntimeError("boom")
        return 0, VULN_OUTPUT

    confirmer = SqlmapConfirmer("sqlmap", execute=flaky)
    targets = select_sqli_targets(
        [injection_lead("sqli", "/bad", "x"), injection_lead("sqli", "/good", "y")]
    )
    findings = confirmer.run("http://t:9000", targets)
    assert len(findings) == 1
    assert findings[0].evidence["path"] == "/good"


def test_confirmer_missing_binary_returns_empty_without_raising():
    def missing(argv, timeout):
        raise FileNotFoundError("sqlmap")

    confirmer = SqlmapConfirmer("sqlmap", execute=missing)
    targets = select_sqli_targets([injection_lead("sqli", "/items", "id")])
    assert confirmer.run("http://t:9000", targets) == []


def test_select_targets_reads_a_plain_finding_dict():
    # A local run's findings are upload dicts, not ORM rows; the selector must
    # read either, so both lanes pick the same sqli leads.
    from app.engine.sqlmap_confirm import select_sqli_targets

    dict_lead = {
        "check": "signature_injection",
        "operation_id": "op-1",
        "evidence": {"family": "sqli", "location": "query", "method": "GET",
                     "path": "/items", "param": "id"},
    }
    # A non-GET/body lead is still excluded, dict or not.
    body_lead = {"check": "x", "evidence": {"family": "sqli", "location": "body",
                 "method": "POST", "path": "/p", "param": "q"}}
    targets = select_sqli_targets([dict_lead, body_lead], max_targets=5)
    assert targets == [{"path": "/items", "param": "id",
                        "operation_id": "op-1", "source_check": "signature_injection"}]
