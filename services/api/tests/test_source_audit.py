"""Local language-version inspection: no project execution or live CVE traffic."""

from __future__ import annotations

from pathlib import Path

import httpx
import pytest

from app.domain.enums import Confidence, Severity
from app.engine.fingerprint import fingerprint
from app.runner import source_audit as audit
from app.scans.diff import diff_snapshots
from app.scans.run_options import unperformed


@pytest.fixture(autouse=True)
def no_rate_wait(monkeypatch):
    monkeypatch.setattr(audit, "REQUEST_INTERVAL", 0)


def write(root: Path, name: str, text: str) -> None:
    path = root / name
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text)


def advisory():
    return {
        "id": "CVE-2025-12345",
        "descriptions": [{"lang": "en", "value": "A runtime vulnerability."}],
        "metrics": {"cvssMetricV31": [{"cvssData": {"baseSeverity": "HIGH"}}]},
        "configurations": [
            {
                "nodes": [
                    {
                        "cpeMatch": [
                            {
                                "vulnerable": True,
                                "criteria": "cpe:2.3:a:php:php:*:*:*:*:*:*:*:*",
                                "versionStartIncluding": "8.2.0",
                                "versionEndExcluding": "8.2.10",
                            }
                        ]
                    }
                ]
            }
        ],
    }


def response(vulns=None):
    return {
        "totalResults": len(vulns or []),
        "vulnerabilities": [{"cve": value} for value in vulns or []],
    }


def test_six_languages_and_exact_versions_are_queried_without_dependencies(tmp_path):
    write(
        tmp_path,
        ".tool-versions",
        "php 8.2.0\npython 3.12.0\nkotlin 2.0.0\njava 21.0.1\nnodejs 20.0.0\ngolang 1.23.0\n",
    )
    write(tmp_path, "composer.lock", '{"packages": [{"name":"never/send","version":"1.0.0"}]}')
    write(tmp_path, "package-lock.json", '{"packages":{"private":{"version":"1.0.0"}}}')
    seen = []

    def handle(request):
        seen.append(request)
        assert request.url.host == "services.nvd.nist.gov"
        assert request.method == "GET" and not request.content
        assert "never/send" not in str(request.url) and "private" not in str(request.url)
        return httpx.Response(200, json=response())

    events = []
    with httpx.Client(transport=httpx.MockTransport(handle)) as client:
        findings, complete = audit.audit(
            str(tmp_path), emit=lambda *e: events.append(e), client=client
        )
    assert complete and not findings
    assert len(seen) == 6
    assert {r.url.params["cpeName"].split(":")[4] for r in seen} == {
        "php",
        "python",
        "kotlin",
        "openjdk",
        "node.js",
        "go",
    }
    assert all(r.url.params["isVulnerable"] == "" for r in seen)
    assert "Kotlin" in events[0][1]


@pytest.mark.parametrize(
    ("name", "text", "language", "version"),
    [
        ("Dockerfile", "FROM --platform=linux/amd64 php:8.2.0-fpm-bookworm", "PHP", "8.2.0"),
        ("Dockerfile", "FROM python:3.12.1-slim", "Python", "3.12.1"),
        ("Dockerfile", "FROM node:20.0.0-alpine", "Node.js", "20.0.0"),
        ("Dockerfile", "FROM golang:1.23.1", "Go", "1.23.1"),
        ("Dockerfile", "FROM eclipse-temurin:21.0.1-jdk", "Java", "21.0.1"),
        (".sdkmanrc", "java=21.0.1-tem\nkotlin=2.0.0", "Kotlin", "2.0.0"),
        ("build.gradle.kts", 'plugins { kotlin("jvm") version "2.0.0" }', "Kotlin", "2.0.0"),
        (
            "build.gradle",
            "plugins { id 'org.jetbrains.kotlin.jvm' version '2.0.0' }",
            "Kotlin",
            "2.0.0",
        ),
        ("gradle.properties", "kotlin.version=2.0.0", "Kotlin", "2.0.0"),
        ("go.mod", "module example\ngo 1.23\ntoolchain go1.23.1", "Go", "1.23.1"),
        (".nvmrc", "v20.0.0\n", "Node.js", "20.0.0"),
    ],
)
def test_supported_version_declarations(tmp_path, name, text, language, version):
    write(tmp_path, name, text)
    result = audit.inventory(str(tmp_path))
    assert any(r.language == language and r.version == version for r in result.runtimes)


def test_asdf_comments_and_fallback_versions_are_all_checked(tmp_path):
    write(tmp_path, "Dockerfile", "FROM php:8.3.0-fpm")
    write(tmp_path, ".tool-versions", "# project versions\nphp 8.2.0 8.1.0 # fallbacks\n")
    seen = []

    def handle(request):
        seen.append(request.url.params["cpeName"].split(":")[5])
        return httpx.Response(200, json=response())

    with httpx.Client(transport=httpx.MockTransport(handle)) as client:
        findings, complete = audit.audit(str(tmp_path), emit=lambda *_: None, client=client)
    assert complete and not findings
    assert set(seen) == {"8.1.0", "8.2.0", "8.3.0"}


@pytest.mark.parametrize("declaration", ["php # missing pin", "php 8.2.0 system # fallback"])
def test_unresolved_asdf_versions_are_gaps_even_with_another_php_pin(tmp_path, declaration):
    write(tmp_path, "Dockerfile", "FROM php:8.3.0-fpm")
    write(tmp_path, ".tool-versions", declaration)
    with httpx.Client(
        transport=httpx.MockTransport(lambda _: httpx.Response(200, json=response()))
    ) as client:
        findings, complete = audit.audit(str(tmp_path), emit=lambda *_: None, client=client)
    assert not findings and not complete
    assert unperformed("source_runtime_cve", {"source_audit_complete": complete})


@pytest.mark.parametrize(
    "name", [".php-version", ".tool-versions", "Dockerfile", "server.Dockerfile"]
)
@pytest.mark.parametrize("broken", [False, True])
def test_skipped_version_symlinks_keep_older_cves_not_retested(tmp_path, name, broken):
    write(tmp_path, "current/.php-version", "8.3.0")
    if not broken:
        write(tmp_path, "shared-pin", "8.1.0")
    (tmp_path / name).symlink_to("shared-pin")
    events = []
    with httpx.Client(
        transport=httpx.MockTransport(lambda _: httpx.Response(200, json=response()))
    ) as client:
        findings, complete = audit.audit(
            str(tmp_path), emit=lambda *e: events.append(e), client=client
        )
    assert not complete and not findings
    assert any(
        stage == "source_audit_gap" and name in message and "symlink" in message
        for stage, message in events
    )
    assert unperformed("source_runtime_cve", {"source_audit_complete": complete})


def test_converting_a_version_file_to_a_symlink_does_not_resolve_its_cve(tmp_path):
    write(tmp_path, ".php-version", "8.2.0")
    write(tmp_path, "Dockerfile", "FROM php:8.3.0-fpm")

    def handle(request):
        vuln = [advisory()] if ":8.2.0:" in request.url.params["cpeName"] else []
        return httpx.Response(200, json=response(vuln))

    with httpx.Client(transport=httpx.MockTransport(handle)) as client:
        older, complete = audit.audit(str(tmp_path), emit=lambda *_: None, client=client)
        assert complete and len(older) == 1
        (tmp_path / ".php-version").unlink()
        write(tmp_path, "shared-version", "8.2.0")
        (tmp_path / ".php-version").symlink_to("shared-version")
        newer, complete = audit.audit(str(tmp_path), emit=lambda *_: None, client=client)
    assert not newer and not complete
    finding = older[0]
    row = {
        "check": finding.check,
        "title": finding.title,
        "severity": finding.severity.value,
        "fingerprint": fingerprint(
            finding.check, finding.owasp_id, finding.title, finding.evidence
        ),
    }
    diff = diff_snapshots(
        [row],
        [],
        not_retested=lambda old: unperformed(old["check"], {"source_audit_complete": complete}),
    )
    assert diff.not_retested == [row] and not diff.resolved


@pytest.mark.parametrize("second_version", ["8.2.0", "8.3.0"])
def test_runtime_cve_groups_keep_every_docker_stage_and_version(tmp_path, second_version):
    write(
        tmp_path,
        "Dockerfile",
        f"FROM php:8.2.0 AS build\nFROM php:{second_version}-fpm AS production\n",
    )
    seen = []

    def handle(request):
        version = request.url.params["cpeName"].split(":")[5]
        seen.append(version)
        vuln = advisory()
        vuln["metrics"]["cvssMetricV31"][0]["cvssData"]["baseSeverity"] = (
            "CRITICAL" if version == "8.3.0" else "HIGH"
        )
        match = vuln["configurations"][0]["nodes"][0]["cpeMatch"][0]
        match["versionStartIncluding"] = version
        match["versionEndExcluding"] = version.rsplit(".", 1)[0] + ".10"
        return httpx.Response(200, json=response([vuln]))

    with httpx.Client(transport=httpx.MockTransport(handle)) as client:
        findings, complete = audit.audit(str(tmp_path), emit=lambda *_: None, client=client)
    assert complete and len(findings) == 1
    finding = findings[0]
    assert set(seen) == {"8.2.0", second_version}
    assert len(seen) == len(set(seen)), "stage declarations must share lookups of the same version"
    assert finding.evidence["affected_versions"] == sorted({"8.2.0", second_version})
    assert finding.evidence["declarations"] == [
        {"version": "8.2.0", "stage": "build"},
        {"version": second_version, "stage": "production"},
    ]
    for label in ("8.2.0 (build)", f"{second_version} (production)"):
        assert label in finding.description and label in finding.remediation
    assert finding.severity == (Severity.critical if second_version == "8.3.0" else Severity.high)
    assert "8.2.10" in finding.remediation
    if second_version == "8.3.0":
        assert "8.3.10" in finding.remediation
    original = {
        "ecosystem": "php",
        "package": "php",
        "advisory": "CVE-2025-12345",
        "location": "Dockerfile",
        "version": "8.2.0",
    }
    assert fingerprint(
        finding.check, finding.owasp_id, finding.title, finding.evidence
    ) == fingerprint(finding.check, finding.owasp_id, "Previous single-version finding", original)


def test_unnamed_docker_stages_are_retained_without_line_number_identity(tmp_path):
    write(tmp_path, "Dockerfile", "# image\nFROM php:8.2.0\n\nFROM php:8.2.0-fpm\n")
    with httpx.Client(
        transport=httpx.MockTransport(lambda _: httpx.Response(200, json=response([advisory()])))
    ) as client:
        findings, complete = audit.audit(str(tmp_path), emit=lambda *_: None, client=client)
    assert complete and len(findings) == 1
    assert findings[0].evidence["declarations"] == [
        {"version": "8.2.0", "stage": "stage 1"},
        {"version": "8.2.0", "stage": "stage 2"},
    ]


def test_source_pin_is_a_lead_with_fix_and_stable_identity(tmp_path):
    write(tmp_path, ".php-version", "8.2.0")
    with httpx.Client(
        transport=httpx.MockTransport(lambda _: httpx.Response(200, json=response([advisory()])))
    ) as client:
        findings, complete = audit.audit(str(tmp_path), emit=lambda *_: None, client=client)
    assert complete and len(findings) == 1
    finding = findings[0]
    assert finding.confidence == Confidence.heuristic and finding.severity == Severity.high
    assert "8.2.10" in finding.remediation
    assert finding.evidence["location"] == ".php-version"
    assert "nvd.nist.gov/vuln/detail/CVE-2025-12345" in finding.description
    before = fingerprint(finding.check, finding.owasp_id, finding.title, finding.evidence)
    evidence = {**finding.evidence, "version": "8.2.1", "affected_until_excluding": ["8.2.12"]}
    assert fingerprint(finding.check, finding.owasp_id, "changed summary", evidence) == before


def test_symlinks_vendor_files_and_dependency_manifests_are_never_read(tmp_path):
    write(tmp_path, ".php-version", "8.2.0")
    write(tmp_path, "vendor/lib/.python-version", "3.1.0")
    write(tmp_path, "node_modules/lib/.node-version", "1.0.0")
    write(tmp_path, "package.json", '{"engines":{"node":"1.0.0"}}')
    write(tmp_path, "requirements.txt", "python==3.1.0")
    outside = tmp_path.parent / "outside-runtime-version"
    outside.write_text("3.1.0")
    (tmp_path / ".python-version").symlink_to(outside)
    result = audit.inventory(str(tmp_path))
    assert [(r.language, r.version) for r in result.runtimes] == [("PHP", "8.2.0")]


@pytest.mark.parametrize(
    "text",
    [
        "FROM php:8.2",
        "FROM node:latest",
        "FROM python:${PYTHON_VERSION}",
        "FROM private.example/php:8.2.0",
    ],
)
def test_ambiguous_or_private_images_never_invent_a_runtime_version(tmp_path, text):
    write(tmp_path, "Dockerfile", text)
    result = audit.inventory(str(tmp_path))
    assert not result.runtimes
    assert result.gaps


def test_minimum_language_version_is_not_the_installed_go_version(tmp_path):
    write(tmp_path, "go.mod", "module example\ngo 1.23.0")
    result = audit.inventory(str(tmp_path))
    assert result.languages == {"Go"} and not result.runtimes and result.gaps


@pytest.mark.parametrize(
    "status,body",
    [
        (429, {}),
        (503, {}),
        (200, {}),
        (200, {"totalResults": 101, "vulnerabilities": []}),
        (200, {"totalResults": 1, "vulnerabilities": [{"cve": {"id": "bad"}}]}),
    ],
)
def test_unavailable_partial_or_invalid_lookups_are_gaps(tmp_path, status, body):
    write(tmp_path, ".php-version", "8.2.0")
    events = []
    with httpx.Client(
        transport=httpx.MockTransport(lambda _: httpx.Response(status, json=body))
    ) as client:
        _, complete = audit.audit(str(tmp_path), emit=lambda *e: events.append(e), client=client)
    assert not complete
    assert any(stage == "source_audit_gap" for stage, _ in events)


def test_duplicate_declarations_share_a_lookup_and_rejected_cves_are_ignored(tmp_path):
    write(tmp_path, ".php-version", "8.2.0")
    write(tmp_path, "Dockerfile", "FROM php:8.2.0-fpm")
    count = 0
    rejected = {**advisory(), "vulnStatus": "Rejected"}

    def handle(_):
        nonlocal count
        count += 1
        return httpx.Response(200, json=response([rejected]))

    with httpx.Client(transport=httpx.MockTransport(handle)) as client:
        findings, complete = audit.audit(str(tmp_path), emit=lambda *_: None, client=client)
    assert complete and not findings and count == 1


def test_cancelled_or_over_budget_scan_makes_no_advisory_request(tmp_path, monkeypatch):
    write(tmp_path, ".php-version", "8.2.0")
    monkeypatch.setattr(audit, "MAX_REQUESTS", 0)
    with httpx.Client(
        transport=httpx.MockTransport(lambda _: pytest.fail("no request expected"))
    ) as client:
        _, complete = audit.audit(str(tmp_path), emit=lambda *_: None, client=client)
    assert not complete


@pytest.mark.parametrize("gaps", [None, {}, {"source_audit_complete": False}, {"not_run": []}])
def test_diff_does_not_resolve_runtime_cves_without_a_complete_source_check(gaps):
    assert unperformed("source_runtime_cve", gaps)
    assert not unperformed("source_runtime_cve", {"source_audit_complete": True})
