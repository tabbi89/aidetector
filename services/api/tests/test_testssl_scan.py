"""testssl.sh adapter tests — mapping is pure; the scanner uses a fake executor."""
from __future__ import annotations

import json

from app.domain.enums import Severity
from app.engine.testssl_scan import TestsslScanner, map_testssl_entries

ENTRIES = [
    {"id": "sec_client_renego", "severity": "MEDIUM", "cwe": "200",
     "finding": "Secure Client-Initiated Renegotiation : Vulnerable"},
    {"id": "cipher_order", "severity": "LOW", "finding": "weak order"},
    {"id": "ROBOT", "severity": "HIGH", "cve": "CVE-2017-13099", "cwe": "327",
     "finding": "Vulnerable to ROBOT attack"},
    {"id": "cert_chain_of_trust", "severity": "CRITICAL", "cwe": "295",
     "finding": "certificate chain validation failed"},
    {"id": "service", "severity": "INFO", "finding": "HTTP"},
]


def test_map_entries_keeps_critical_high_and_medium_only():
    findings = map_testssl_entries(ENTRIES)
    assert [f.severity for f in findings] == [
        Severity.medium,
        Severity.high,
        Severity.critical,
    ]
    assert findings[0].check == "testssl" == findings[1].check
    assert findings[0].owasp_id == "CWE-200"
    assert findings[1].owasp_id == "CWE-327"
    assert findings[1].evidence["cve"] == "CVE-2017-13099"
    assert "ROBOT" in findings[1].title
    assert findings[2].owasp_id == "CWE-295"


def test_scanner_parses_json_written_by_the_tool():
    def fake_execute(argv, timeout):
        # The scanner passes its temp JSON path right after --jsonfile.
        path = argv[argv.index("--jsonfile") + 1]
        with open(path, "w", encoding="utf-8") as fh:
            json.dump(ENTRIES, fh)
        return 0, ""

    scanner = TestsslScanner("testssl.sh", execute=fake_execute)
    findings = scanner.run("https://target:8443")
    assert len(findings) == 3
    assert findings[1].severity == Severity.high
    assert findings[2].severity == Severity.critical


def test_scanner_degrades_on_error():
    def boom(argv, timeout):
        raise RuntimeError("no such host")

    scanner = TestsslScanner("testssl.sh", execute=boom)
    assert scanner.run("https://target:8443") == []  # never raises


def test_scanner_degrades_on_malformed_json():
    def fake_execute(argv, timeout):
        path = argv[argv.index("--jsonfile") + 1]
        with open(path, "w", encoding="utf-8") as fh:
            fh.write("{not json")
        return 0, ""

    scanner = TestsslScanner("testssl.sh", execute=fake_execute)
    assert scanner.run("https://target:8443") == []
