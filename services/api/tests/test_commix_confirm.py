"""commix confirmation tests — selection/parsing are pure; the runner is faked."""
from __future__ import annotations

from app.domain.enums import Severity
from app.engine.commix_confirm import (
    CommixConfirmer,
    build_command,
    parse_output,
    select_cmdi_targets,
)
from tests.factories import injection_lead

VULN_OUTPUT = """
(*) Testing the (results-based) command injection technique...
(+) The (GET) parameter 'id' is vulnerable to command injection.
    Type: results-based command injection
    Technique: classic command injection
"""

NOT_VULN_OUTPUT = """
(x) All tested parameters do not appear to be injectable.
"""



def test_select_cmdi_targets_filters_and_dedupes():
    findings = [
        injection_lead("cmdi", "/a", "x"),
        injection_lead("cmdi", "/a", "x"),      # duplicate
        injection_lead("xss", "/a", "y"),       # wrong family
        injection_lead("cmdi", "/b", "z"),
    ]
    targets = select_cmdi_targets(findings)
    assert [(t["path"], t["param"]) for t in targets] == [("/a", "x"), ("/b", "z")]


def test_build_command_is_batch_and_noninteractive():
    argv = build_command("commix", "http://t/ping?host=1")
    assert argv[0] == "commix" and "-u" in argv
    assert "http://t/ping?host=1" in argv
    assert "--batch" in argv


def test_parse_output_detects_vulnerability_and_techniques():
    vuln, techniques = parse_output(VULN_OUTPUT)
    assert vuln is True
    assert any("command injection" in t for t in techniques)
    assert parse_output(NOT_VULN_OUTPUT) == (False, [])


def test_confirmer_maps_vulnerable_target_as_critical():
    confirmer = CommixConfirmer("commix", execute=lambda argv, t: (0, VULN_OUTPUT))
    targets = select_cmdi_targets([injection_lead("cmdi", "/ping", "host")])
    findings = confirmer.run("http://t:9000", targets)
    assert len(findings) == 1
    f = findings[0]
    assert f.check == "commix_confirm"
    assert f.severity == Severity.critical
    assert f.owasp_id == "CWE-78"
    assert f.evidence["url"] == "http://t:9000/ping?host=1"
    assert f.operation_id == "op-1"


def test_confirmer_not_vulnerable_yields_nothing():
    confirmer = CommixConfirmer("commix", execute=lambda argv, t: (0, NOT_VULN_OUTPUT))
    targets = select_cmdi_targets([injection_lead("cmdi", "/ping", "host")])
    assert confirmer.run("http://t:9000", targets) == []


def test_confirmer_missing_binary_returns_empty_without_raising():
    def missing(argv, timeout):
        raise FileNotFoundError("commix")

    confirmer = CommixConfirmer("commix", execute=missing)
    targets = select_cmdi_targets([injection_lead("cmdi", "/ping", "host")])
    assert confirmer.run("http://t:9000", targets) == []
