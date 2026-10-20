"""tplmap confirmation tests — selection/parsing are pure; the runner is faked."""
from __future__ import annotations

from app.domain.enums import Severity
from app.engine.tplmap_confirm import (
    TplmapConfirmer,
    build_command,
    parse_output,
    select_ssti_targets,
)
from tests.factories import injection_lead

VULN_OUTPUT = """
[+] Tplmap identified the following injection point:
    ORIGIN: GET parameter: name
    Engine: Jinja2
    Injection: {{*}}
    Context: text
"""

NOT_VULN_OUTPUT = """
[-] Tplmap could not detect any template engine.
"""



def test_select_ssti_targets_filters_and_dedupes():
    findings = [
        injection_lead("ssti", "/a", "x"),
        injection_lead("ssti", "/a", "x"),      # duplicate
        injection_lead("cmdi", "/a", "y"),      # wrong family
        injection_lead("ssti", "/b", "z"),
    ]
    targets = select_ssti_targets(findings)
    assert [(t["path"], t["param"]) for t in targets] == [("/a", "x"), ("/b", "z")]


def test_build_command():
    argv = build_command("tplmap", "http://t/hello?name=1")
    assert argv[0] == "tplmap" and "-u" in argv
    assert "http://t/hello?name=1" in argv


def test_parse_output_detects_injection_and_engine():
    vuln, engines = parse_output(VULN_OUTPUT)
    assert vuln is True
    assert engines == ["Jinja2"]
    assert parse_output(NOT_VULN_OUTPUT) == (False, [])


def test_confirmer_maps_vulnerable_target():
    confirmer = TplmapConfirmer("tplmap", execute=lambda argv, t: (0, VULN_OUTPUT))
    targets = select_ssti_targets([injection_lead("ssti", "/hello", "name")])
    findings = confirmer.run("http://t:9000", targets)
    assert len(findings) == 1
    f = findings[0]
    assert f.check == "tplmap_confirm"
    assert f.severity == Severity.high
    assert f.owasp_id == "CWE-1336"
    assert f.evidence["url"] == "http://t:9000/hello?name=1"
    assert f.evidence["engines"] == ["Jinja2"]
    assert "Jinja2" in f.description


def test_confirmer_not_vulnerable_yields_nothing():
    confirmer = TplmapConfirmer("tplmap", execute=lambda argv, t: (0, NOT_VULN_OUTPUT))
    targets = select_ssti_targets([injection_lead("ssti", "/hello", "name")])
    assert confirmer.run("http://t:9000", targets) == []


def test_confirmer_missing_binary_returns_empty_without_raising():
    def missing(argv, timeout):
        raise FileNotFoundError("tplmap")

    confirmer = TplmapConfirmer("tplmap", execute=missing)
    targets = select_ssti_targets([injection_lead("ssti", "/hello", "name")])
    assert confirmer.run("http://t:9000", targets) == []
