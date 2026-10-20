"""dalfox confirmation tests — selection/parsing are pure; the runner is faked."""
from __future__ import annotations

import json

from app.domain.enums import Severity
from app.engine.dalfox_confirm import (
    DalfoxConfirmer,
    build_command,
    parse_output,
    select_xss_targets,
)
from tests.factories import injection_lead

VERIFIED_JSON = json.dumps(
    [
        {"type": "V", "method": "GET", "param": "q", "cwe": "CWE-79",
         "data": "http://t/items?q=<script>alert(1)</script>",
         "evidence": "12 line: <script>"},
        {"type": "R", "method": "GET", "param": "q", "data": "reflected only"},
    ]
)
BANNER_THEN_JSON = "dalfox v2.9\n[*] scanning...\n" + VERIFIED_JSON
REFLECTED_ONLY = json.dumps([{"type": "R", "param": "q", "data": "reflected"}])



def test_select_xss_targets_filters_dedupes_and_caps():
    findings = [
        injection_lead("xss", "/a", "x"),
        injection_lead("xss", "/a", "x"),        # duplicate
        injection_lead("sqli", "/a", "y"),       # wrong family
        injection_lead("xss", "/b", "z"),
        injection_lead("xss", "/c", "w"),
    ]
    targets = select_xss_targets(findings, max_targets=2)
    assert [(t["path"], t["param"]) for t in targets] == [("/a", "x"), ("/b", "z")]
    assert targets[0]["operation_id"] == "op-1"


def test_build_command_is_json_and_noninteractive():
    argv = build_command("dalfox", "http://t/items?q=1")
    assert argv[0] == "dalfox" and argv[1] == "url"
    assert "http://t/items?q=1" in argv
    assert "--format" in argv and "json" in argv
    assert "--silence" in argv


def test_parse_output_confirms_only_verified_pocs():
    ok, pocs = parse_output(VERIFIED_JSON)
    assert ok is True
    assert len(pocs) == 1 and pocs[0]["type"] == "V"
    # Tolerates leading banner noise before the JSON array.
    assert parse_output(BANNER_THEN_JSON)[0] is True
    # A reflected-only PoC is what the engine already reported — not a confirm.
    assert parse_output(REFLECTED_ONLY) == (False, [])
    assert parse_output("no json here") == (False, [])


def test_confirmer_maps_verified_target():
    confirmer = DalfoxConfirmer("dalfox", execute=lambda argv, t: (0, VERIFIED_JSON))
    targets = select_xss_targets([injection_lead("xss", "/items", "q")])
    findings = confirmer.run("http://t:9000", targets)
    assert len(findings) == 1
    f = findings[0]
    assert f.check == "dalfox_confirm"
    assert f.severity == Severity.high
    assert f.owasp_id == "CWE-79"
    assert f.evidence["url"] == "http://t:9000/items?q=1"
    assert f.evidence["pocs"]
    assert f.operation_id == "op-1"


def test_confirmer_not_verified_yields_nothing():
    confirmer = DalfoxConfirmer("dalfox", execute=lambda argv, t: (0, REFLECTED_ONLY))
    targets = select_xss_targets([injection_lead("xss", "/items", "q")])
    assert confirmer.run("http://t:9000", targets) == []


def test_confirmer_skips_failing_target_and_continues():
    def flaky(argv, timeout):
        if "bad" in argv[argv.index("url") + 1]:
            raise RuntimeError("boom")
        return 0, VERIFIED_JSON

    confirmer = DalfoxConfirmer("dalfox", execute=flaky)
    targets = select_xss_targets(
        [injection_lead("xss", "/bad", "x"), injection_lead("xss", "/good", "y")]
    )
    findings = confirmer.run("http://t:9000", targets)
    assert len(findings) == 1
    assert findings[0].evidence["path"] == "/good"


def test_confirmer_missing_binary_returns_empty_without_raising():
    def missing(argv, timeout):
        raise FileNotFoundError("dalfox")

    confirmer = DalfoxConfirmer("dalfox", execute=missing)
    targets = select_xss_targets([injection_lead("xss", "/items", "q")])
    assert confirmer.run("http://t:9000", targets) == []
