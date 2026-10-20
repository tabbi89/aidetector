"""Kali adjunct tests — mapping is pure; the scan flow uses a fake transport."""
from __future__ import annotations

import importlib.util
import json
import os
from pathlib import Path
from types import ModuleType

import pytest

from app.domain.enums import Confidence, Severity
from app.engine.kali import (
    KaliScanner,
    calibrate_discovered_paths,
    filter_known_paths,
    map_crawled_paths,
    map_discovered_paths,
    map_nikto_findings,
    map_nuclei_findings,
    map_param_findings,
    map_whatweb_findings,
)


def test_map_nuclei_findings_maps_severity_and_fields():
    rows = [
        {"template_id": "CVE-2021-44228", "name": "Log4j RCE", "severity": "critical",
         "type": "http", "host": "http://t", "matched_at": "http://t/api",
         "tags": ["cve", "log4j"]},
        {"template_id": "exposed-panel", "name": "Exposed admin panel",
         "severity": "info", "host": "http://t"},
    ]
    findings = map_nuclei_findings(rows)
    assert [f.severity for f in findings] == [Severity.critical, Severity.info]
    assert findings[0].check == "kali_nuclei"
    assert findings[0].title.startswith("nuclei: Log4j RCE")
    assert findings[0].evidence["template_id"] == "CVE-2021-44228"
    assert findings[0].evidence["tags"] == ["cve", "log4j"]
    # No matched_at → falls back to host in the description.
    assert "http://t" in findings[1].description


def test_map_nuclei_grades_info_matches_heuristic():
    # An info template says a component is present, not that it is exploitable.
    rows = [
        {"template_id": "tech-detect", "severity": "info", "host": "http://t"},
        {"template_id": "CVE-2021-44228", "severity": "critical", "host": "http://t"},
        {"template_id": "odd", "severity": "bogus", "host": "http://t"},
    ]
    assert [f.confidence for f in map_nuclei_findings(rows)] == [
        Confidence.heuristic, Confidence.verified, Confidence.heuristic,
    ]


def test_map_nuclei_carries_template_remediation_and_ids():
    rows = [
        {"template_id": "CVE-2021-44228", "name": "Log4j RCE", "severity": "critical",
         "host": "http://t", "matched_at": "http://t/api",
         "remediation": "Upgrade log4j-core to 2.17.1.",
         "cve_ids": ["CVE-2021-44228"], "cwe_ids": ["CWE-502"],
         "references": ["https://logging.apache.org/log4j/2.x/security.html"]},
        {"template_id": "bare", "severity": "low", "host": "http://t",
         "cve_ids": "CVE-not-a-list", "references": None},
    ]
    full, bare = map_nuclei_findings(rows)
    assert full.remediation == "Upgrade log4j-core to 2.17.1."
    assert full.evidence["cve_ids"] == ["CVE-2021-44228"]
    assert full.evidence["cwe_ids"] == ["CWE-502"]
    assert full.evidence["references"] == [
        "https://logging.apache.org/log4j/2.x/security.html"
    ]
    assert "(CVE-2021-44228)" in full.description
    # Missing or malformed fields leave the catalogue line in charge.
    assert bare.remediation == ""
    assert bare.evidence["cve_ids"] == [] and bare.evidence["references"] == []


def _kali_sidecar() -> ModuleType:
    """The sidecar's app module, loaded by path (it is not an importable package)."""
    here = Path(__file__).resolve()
    override = os.getenv("AIDETECTOR_REPO_ROOT", "").strip()
    for root in ([Path(override)] if override else []) + list(here.parents):
        main = root / "services" / "kali" / "app" / "main.py"
        if main.is_file():
            spec = importlib.util.spec_from_file_location("kali_sidecar_main", main)
            assert spec is not None and spec.loader is not None
            module = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(module)
            return module
    pytest.skip("services/kali is not in this checkout")


def test_sidecar_forwards_nuclei_remediation_and_classification():
    line = json.dumps({
        "template-id": "CVE-2021-44228",
        "type": "http",
        "host": "http://t",
        "matched-at": "http://t/api",
        "info": {
            "name": "Log4j RCE",
            "severity": "critical",
            "tags": "cve,log4j",
            "remediation": "  Upgrade log4j-core.  ",
            "reference": ["https://a.example", "https://b.example"],
            "classification": {"cve-id": ["CVE-2021-44228"], "cwe-id": "CWE-502"},
        },
    })
    row = _kali_sidecar().normalize_nuclei_line(line)
    assert row["tags"] == ["cve", "log4j"]
    assert row["remediation"] == "Upgrade log4j-core."
    assert row["cve_ids"] == ["CVE-2021-44228"]
    assert row["cwe_ids"] == ["CWE-502"]
    assert row["references"] == ["https://a.example", "https://b.example"]
    # And the worker maps what the sidecar sends.
    (finding,) = map_nuclei_findings([row])
    assert finding.remediation == "Upgrade log4j-core."
    assert finding.evidence["cve_ids"] == ["CVE-2021-44228"]


def test_sidecar_tolerates_templates_without_classification():
    line = json.dumps({"template-id": "t", "info": {"classification": None}})
    row = _kali_sidecar().normalize_nuclei_line(line)
    assert row["remediation"] == ""
    assert row["cve_ids"] == [] and row["cwe_ids"] == [] and row["references"] == []


def test_map_discovered_paths():
    rows = [
        {"path": "/actuator/env", "status": 200, "url": "http://t/actuator/env"},
        {"path": "", "status": 200},  # skipped
        {"path": "/admin", "status": 403, "url": "http://t/admin"},
    ]
    findings = map_discovered_paths(rows)
    assert len(findings) == 2
    assert all(f.check == "kali_discovery" for f in findings)
    assert all(f.severity == Severity.low for f in findings)
    assert findings[0].evidence["path"] == "/actuator/env"
    assert findings[1].evidence["status"] == 403


def test_calibrate_drops_dominant_wildcard_status():
    # A WAF that 403s every unknown path: the whole wordlist "discovered".
    rows = [{"path": f"/p{i}", "status": 403} for i in range(20)]
    rows.append({"path": "/real", "status": 200})
    kept = calibrate_discovered_paths(rows)
    assert [r["path"] for r in kept] == ["/real"]


def test_calibrate_keeps_a_lone_deny_status():
    # A single 403 is real signal, not a wildcard baseline — keep it.
    rows = [
        {"path": "/actuator/env", "status": 200},
        {"path": "/admin", "status": 403},
        {"path": "/metrics", "status": 500},
    ]
    assert calibrate_discovered_paths(rows) == rows


def test_calibrate_ignores_dominant_success_status():
    # A catch-all that 200s everything is not a deny-style wildcard; don't
    # silently drop 2xx — those can be genuine finds.
    rows = [{"path": f"/p{i}", "status": 200} for i in range(15)]
    assert calibrate_discovered_paths(rows) == rows


class _FakeResp:
    def __init__(self, payload, status=200):
        self._payload = payload
        self.status_code = status

    def json(self):
        return self._payload


class _FakeKaliHttp:
    """One finding per pass; records requests. Unknown endpoints return {}."""

    def __init__(self):
        self.posts = []

    def post(self, url, **kwargs):
        self.posts.append((url, kwargs))
        if "/run/nuclei" in url:
            return _FakeResp({"findings": [
                {"template_id": "tech-detect", "name": "Flask detected",
                 "severity": "low", "host": "http://target:9000"},
            ]})
        if "/run/discover" in url:
            return _FakeResp({"paths": [
                {"path": "/console", "status": 200, "url": "http://target:9000/console"},
            ]})
        if "/run/nikto" in url:
            return _FakeResp({"findings": [
                {"id": "999", "method": "GET", "url": "http://target:9000/old",
                 "message": "Outdated server"},
            ]})
        if "/run/whatweb" in url:
            return _FakeResp({"plugins": [
                {"plugin": "Flask", "value": "1.0"},
            ]})
        if "/run/crawl" in url:
            return _FakeResp({"paths": [
                {"path": "/hidden", "url": "http://target:9000/hidden"},
            ]})
        if "/run/params" in url:
            return _FakeResp({"results": [
                {"url": "http://target:9000/", "method": "GET", "params": ["debug"]},
            ]})
        return _FakeResp({})

    def get(self, url, **kwargs):
        return _FakeResp({})


def test_kali_scanner_runs_all_passes():
    http = _FakeKaliHttp()
    scanner = KaliScanner("http://kali:8091", api_key="k", http=http, rate_limit=2)
    findings = scanner.run("http://target:9000")
    checks = {f.check for f in findings}
    assert checks == {
        "kali_nuclei", "kali_discovery", "kali_nikto",
        "kali_whatweb", "kali_crawl", "kali_params",
    }
    # API key rides along; target is passed to every job.
    urls = {url for url, _ in http.posts}
    assert urls == {
        "http://kali:8091/run/nuclei",
        "http://kali:8091/run/discover",
        "http://kali:8091/run/nikto",
        "http://kali:8091/run/whatweb",
        "http://kali:8091/run/crawl",
        "http://kali:8091/run/params",
    }
    for _, kwargs in http.posts:
        assert kwargs["headers"]["X-API-Key"] == "k"
        assert kwargs["json"]["target"] == "http://target:9000"
        assert kwargs["json"]["rate_limit"] == 2


def test_kali_scanner_one_missing_tool_does_not_drop_others():
    """A 503 for one pass (tool absent) must not lose the other passes."""
    class _PartialHttp(_FakeKaliHttp):
        def post(self, url, **kwargs):
            if "/run/nikto" in url:
                return _FakeResp({"detail": "nikto not installed"}, status=503)
            return super().post(url, **kwargs)

    scanner = KaliScanner("http://kali:8091", http=_PartialHttp())
    findings = scanner.run("http://target:9000")
    checks = {f.check for f in findings}
    assert "kali_nikto" not in checks
    assert {"kali_nuclei", "kali_discovery", "kali_whatweb"} <= checks


def test_map_nikto_findings():
    rows = [{"id": "1", "method": "GET", "url": "http://t/x", "message": "Interesting file"}]
    findings = map_nikto_findings(rows)
    assert len(findings) == 1
    assert findings[0].check == "kali_nikto"
    assert findings[0].severity == Severity.low
    assert "Interesting file" in findings[0].title


def test_map_whatweb_summarizes_to_one_info_finding():
    rows = [{"plugin": "nginx", "value": "1.25"}, {"plugin": "PHP", "value": ""}]
    findings = map_whatweb_findings(rows)
    assert len(findings) == 1
    assert findings[0].check == "kali_whatweb"
    assert findings[0].severity == Severity.info
    assert "nginx (1.25)" in findings[0].evidence["plugins"]
    # No plugins → no finding.
    assert map_whatweb_findings([]) == []


def test_map_crawled_paths():
    rows = [{"path": "/api/secret", "url": "http://t/api/secret"}, {"path": ""}]
    findings = map_crawled_paths(rows)
    assert len(findings) == 1
    assert findings[0].check == "kali_crawl"
    assert findings[0].severity == Severity.low


def test_map_param_findings_needs_params():
    rows = [
        {"url": "http://t/", "method": "GET", "params": ["debug", "admin"]},
        {"url": "http://t/x", "method": "GET", "params": []},  # skipped
    ]
    findings = map_param_findings(rows)
    assert len(findings) == 1
    assert findings[0].check == "kali_params"
    assert findings[0].evidence["params"] == ["debug", "admin"]


def test_filter_known_paths_drops_spec_documented_paths():
    rows = [
        {"path": "/search", "status": 200},              # in spec → drop
        {"path": "/accounts/123", "status": 200},        # matches {account_id} → drop
        {"path": "/accounts/123/extra", "status": 200},  # deeper than template → keep
        {"path": "/users/me", "status": 401},            # not in spec → keep
    ]
    kept = filter_known_paths(
        rows, ["/search", "/accounts/{account_id}", "/admin/users/{user_id}/promote"]
    )
    assert [r["path"] for r in kept] == ["/accounts/123/extra", "/users/me"]


def test_filter_known_paths_without_spec_keeps_everything():
    rows = [{"path": "/x", "status": 200}]
    assert filter_known_paths(rows, []) == rows


def test_kali_scanner_filters_discovery_against_spec():
    http = _FakeKaliHttp()
    scanner = KaliScanner("http://kali:8091", http=http)
    findings = scanner.run("http://target:9000", spec_paths=["/console"])
    # /console is documented in the spec → the ffuf discovery of it is dropped;
    # the crawl of /hidden and the other passes still report.
    checks = [f.check for f in findings]
    assert "kali_discovery" not in checks
    assert "kali_nuclei" in checks and "kali_crawl" in checks


def test_kali_scanner_passes_extra_targets():
    """Scanner passes (nuclei/nikto/whatweb/crawl) carry the spec's operation
    URLs as extra targets; the fuzzing passes (discover/params) stay on the base
    target so their bounded workload is not multiplied per operation."""
    http = _FakeKaliHttp()
    scanner = KaliScanner("http://kali:8091", http=http)
    scanner.run(
        "http://target:9000",
        # duplicates, empties, and the base URL itself are dropped
        spec_urls=["http://target:9000/v1/x", "http://target:9000/v1/x", "",
                   "http://target:9000"],
    )
    by_url = {url: kwargs for url, kwargs in http.posts}
    for path in ("/run/nuclei", "/run/nikto", "/run/whatweb", "/run/crawl"):
        assert by_url[f"http://kali:8091{path}"]["json"]["extra_targets"] == [
            "http://target:9000/v1/x"
        ]
    for path in ("/run/discover", "/run/params"):
        assert "extra_targets" not in by_url[f"http://kali:8091{path}"]["json"]


def test_kali_scanner_degrades_on_error():
    class _Boom:
        def post(self, url, **kwargs):
            raise RuntimeError("service down")

        def get(self, url, **kwargs):
            raise RuntimeError("service down")

    scanner = KaliScanner("http://kali:8091", http=_Boom())
    assert scanner.run("http://target:9000") == []  # never raises


def test_kali_scanner_tolerates_bad_shapes():
    class _Weird:
        def post(self, url, **kwargs):
            return _FakeResp({"findings": "oops", "paths": None})

        def get(self, url, **kwargs):
            return _FakeResp({})

    scanner = KaliScanner("http://kali:8091", http=_Weird())
    assert scanner.run("http://target:9000") == []
