"""Read declared language versions and query live NVD CVEs without executing code.

Only runtime CPEs leave the machine. No dependency inventories are read. A source
pin is a lead: deployment, vendor backports and exploitability need confirmation.
"""

from __future__ import annotations

import json
import os
import re
import stat
import threading
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any
from urllib.parse import quote

import httpx

from app.agent.source import _SKIP_DIRS
from app.domain.enums import SEVERITY_RANK, Confidence, Severity
from app.engine.base import EngineFinding

MAX_FILES = 4000
MAX_DIRECTORIES = 500
MAX_FILE_BYTES = 256 * 1024
MAX_TOTAL_BYTES = 4 * 1024 * 1024
MAX_REQUESTS = 10
MAX_SECONDS = 60.0
MAX_RESPONSE_BYTES = 2 * 1024 * 1024
MAX_FINDINGS = 1000
# NVD's unauthenticated API allows five requests per rolling 30 seconds.
REQUEST_INTERVAL = 6.1
_EXACT = re.compile(r"\d+\.\d+\.\d+\Z")
_LANGUAGES = {
    ".php": "PHP",
    ".py": "Python",
    ".kt": "Kotlin",
    ".kts": "Kotlin",
    ".java": "Java",
    ".js": "Node.js",
    ".ts": "Node.js",
    ".go": "Go",
}
# Java pins are compared with upstream OpenJDK. Distribution backports and
# Oracle JDK builds need manual validation; never claim deployed exploitability.
_RUNTIMES = {
    "php": ("PHP", "php", "php"),
    "python": ("Python", "python", "python"),
    "node": ("Node.js", "nodejs", "node.js"),
    "nodejs": ("Node.js", "nodejs", "node.js"),
    "golang": ("Go", "golang", "go"),
    "go": ("Go", "golang", "go"),
    "java": ("Java", "oracle", "openjdk"),
    "openjdk": ("Java", "oracle", "openjdk"),
    "eclipse-temurin": ("Java", "oracle", "openjdk"),
    "kotlin": ("Kotlin", "jetbrains", "kotlin"),
}
_VERSION_FILES = {
    ".php-version": "php",
    ".python-version": "python",
    ".node-version": "node",
    ".nvmrc": "node",
    ".go-version": "go",
    ".java-version": "java",
    ".kotlin-version": "kotlin",
}
_MANIFESTS = {
    *_VERSION_FILES,
    ".tool-versions",
    ".sdkmanrc",
    "Dockerfile",
    "go.mod",
    "build.gradle.kts",
    "build.gradle",
    "gradle.properties",
}


@dataclass(frozen=True, order=True)
class Runtime:
    language: str
    vendor: str
    product: str
    version: str
    path: str
    stage: str = ""

    @property
    def cpe(self) -> str:
        return f"cpe:2.3:a:{self.vendor}:{self.product}:{self.version}:*:*:*:*:*:*:*"


@dataclass
class Inventory:
    languages: set[str] = field(default_factory=set)
    runtimes: set[Runtime] = field(default_factory=set)
    gaps: list[str] = field(default_factory=list)

    def add(self, kind: str, version: str, path: str, *, stage: str = "") -> None:
        if kind not in _RUNTIMES:
            return
        language, vendor, product = _RUNTIMES[kind]
        self.languages.add(language)
        version = version.removeprefix("v")
        if not _EXACT.fullmatch(version):
            self.gaps.append(f"{path}: {language} needs an exact major.minor.patch version")
            return
        self.runtimes.add(Runtime(language, vendor, product, version, path, stage))


def inventory(directory: str) -> Inventory:
    result = Inventory()
    root = Path(directory).resolve()
    if not root.is_dir():
        result.gaps.append("project directory is unavailable")
        return result
    total_bytes = directories = files = 0
    for parent, dirs, names in os.walk(
        root,
        followlinks=False,
        onerror=lambda _: result.gaps.append("project directory unreadable"),
    ):
        directories += 1
        if directories > MAX_DIRECTORIES:
            result.gaps.append("project directory limit reached")
            break
        folder = Path(parent)
        depth = len(folder.relative_to(root).parts)
        dirs[:] = sorted(d for d in dirs if d not in _SKIP_DIRS and not (folder / d).is_symlink())
        if depth >= 5:
            if dirs:
                result.gaps.append("project depth limit reached")
            dirs[:] = []
        for name in sorted(names):
            files += 1
            if files > MAX_FILES:
                result.gaps.append("project file limit reached")
                return result
            path = folder / name
            if path.is_symlink():
                if name in _MANIFESTS or name.endswith(".Dockerfile"):
                    relative = path.relative_to(root).as_posix()
                    result.gaps.append(f"{relative}: symlinked version file was not read")
                continue
            if language := _LANGUAGES.get(path.suffix):
                result.languages.add(language)
            if name not in _MANIFESTS and not name.endswith(".Dockerfile"):
                continue
            relative = path.relative_to(root).as_posix()
            try:
                fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
                with os.fdopen(fd, "rb") as stream:
                    info = os.fstat(stream.fileno())
                    if not stat.S_ISREG(info.st_mode) or info.st_size > MAX_FILE_BYTES:
                        result.gaps.append(f"{relative}: version file too large or not regular")
                        continue
                    data = stream.read(MAX_FILE_BYTES + 1)
                total_bytes += len(data)
                if len(data) > MAX_FILE_BYTES or total_bytes > MAX_TOTAL_BYTES:
                    result.gaps.append("project version-file byte limit reached")
                    return result
                _parse(name, data.decode("utf-8"), relative, result)
            except (OSError, ValueError):
                result.gaps.append(f"{relative}: version file could not be read")
    versioned = {runtime.language for runtime in result.runtimes}
    for language in sorted(result.languages - versioned):
        result.gaps.append(f"{language}: no supported exact version declaration found")
    if not result.languages:
        result.gaps.append("no supported project language detected")
    return result


def _parse(name: str, text: str, path: str, out: Inventory) -> None:
    if name in _VERSION_FILES:
        out.add(_VERSION_FILES[name], text.strip(), path)
    elif name == ".tool-versions":
        for line in text.splitlines():
            parts = line.partition("#")[0].split()
            if not parts or parts[0] not in _RUNTIMES:
                continue
            if len(parts) == 1:
                out.add(parts[0], "", path)
            for version in parts[1:]:
                out.add(parts[0], version, path)
    elif name == ".sdkmanrc":
        for kind, version in re.findall(r"(?m)^\s*(java|kotlin)\s*=\s*([^\s#]+)", text):
            out.add(kind, version.split("-", 1)[0], path)
    elif name == "Dockerfile" or name.endswith(".Dockerfile"):
        pattern = (
            r"(?im)^[ \t]*FROM[ \t]+(?:--platform=\S+[ \t]+)?(\S+)"
            r"(?:[ \t]+AS[ \t]+([A-Za-z0-9_][A-Za-z0-9_.-]{0,127})(?=[ \t\r\n]|$))?"
        )
        for index, (image, alias) in enumerate(re.findall(pattern, text), start=1):
            tag = image.split("@", 1)[0]
            if ":" in tag:
                kind, version = tag.rsplit(":", 1)
                kind = kind.removeprefix("docker.io/library/")
                out.add(kind, version.split("-", 1)[0], path, stage=alias or f"stage {index}")
    elif name == "go.mod":
        out.languages.add("Go")
        match = re.search(r"(?m)^toolchain\s+go(\S+)", text)
        if match:
            out.add("go", match[1], path)
        # The go directive is a minimum language version, not installed Go.
    elif name in {"build.gradle", "build.gradle.kts"}:
        for version in re.findall(r'kotlin\("[\w.-]+"\)\s+version\s+"([^\"]+)"', text):
            out.add("kotlin", version, path)
        for version in re.findall(
            r"""id\s*[('"\s]+org\.jetbrains\.kotlin\.[\w.-]+[)'"\s]+version\s*[('"\s]+([^)'"\s]+)""",
            text,
        ):
            out.add("kotlin", version, path)
    elif name == "gradle.properties":
        for version in re.findall(r"(?m)^\s*kotlin[._]version\s*=\s*([^\s#]+)", text):
            out.add("kotlin", version, path)


class AdvisoryClient:
    def __init__(self, client: httpx.Client, cancelled: Callable[[], bool]) -> None:
        self.client = client
        self.cancelled = cancelled
        self.deadline = time.monotonic() + MAX_SECONDS
        self.requests = 0
        self.last_request = 0.0

    def query(self, runtime: Runtime) -> dict[str, Any]:
        while self.requests and time.monotonic() - self.last_request < REQUEST_INTERVAL:
            if self.cancelled() or time.monotonic() >= self.deadline:
                raise ValueError("advisory lookup cancelled or timed out")
            threading.Event().wait(0.1)
        remaining = self.deadline - time.monotonic()
        if self.cancelled() or self.requests >= MAX_REQUESTS or remaining <= 0:
            raise ValueError("advisory lookup budget exhausted or cancelled")
        self.requests += 1
        self.last_request = time.monotonic()
        # Fixed endpoint: no credentials, proxies or project-controlled URLs.
        with self.client.stream(
            "GET",
            "https://services.nvd.nist.gov/rest/json/cves/2.0",
            params={"cpeName": runtime.cpe, "isVulnerable": "", "resultsPerPage": "100"},
            timeout=min(5.0, remaining),
        ) as response:
            response.raise_for_status()
            data = bytearray()
            for chunk in response.iter_bytes():
                data.extend(chunk)
                if (
                    len(data) > MAX_RESPONSE_BYTES
                    or time.monotonic() > self.deadline
                    or self.cancelled()
                ):
                    raise ValueError("advisory response limit reached")
            value = json.loads(data)
        if (
            not isinstance(value, dict)
            or not isinstance(value.get("vulnerabilities"), list)
            or type(value.get("totalResults")) is not int
        ):
            raise ValueError("invalid NVD response")
        return value


def _severity(value: Any) -> Severity:
    try:
        return Severity(str(value).lower())
    except ValueError:
        return Severity.medium


def _finding(runtime: Runtime, vuln: dict) -> EngineFinding:
    advisory = str(vuln["id"])
    if not re.fullmatch(r"CVE-\d{4}-\d+", advisory):
        raise ValueError("invalid CVE identifier")
    summary = next((d["value"] for d in vuln.get("descriptions", []) if d.get("lang") == "en"), "")
    metrics = vuln.get("metrics") or {}
    metric = (
        metrics.get("cvssMetricV40")
        or metrics.get("cvssMetricV31")
        or metrics.get("cvssMetricV30")
        or metrics.get("cvssMetricV2")
        or [{}]
    )[0]
    severity = metric.get("baseSeverity") or metric.get("cvssData", {}).get("baseSeverity")
    fixes = _nvd_fixes(vuln.get("configurations") or [], runtime)
    url = "https://nvd.nist.gov/vuln/detail/" + quote(advisory, safe="")
    fix = (
        f"NVD lists affected-range upper bounds (exclusive): {', '.join(fixes)}. "
        "Confirm the patched release for your branch with the vendor."
        if fixes
        else "Consult the vendor advisory for a supported patched release; "
        "NVD supplies no fixed version."
    )
    return EngineFinding(
        check="source_runtime_cve",
        owasp_id="API8:2023",
        severity=_severity(severity),
        confidence=Confidence.heuristic,
        title=f"{advisory}: {runtime.language} {runtime.version}"[:255],
        description=(
            f"{runtime.path} declares {runtime.language} {runtime.version}. "
            f"NVD matched this upstream version: {summary[:1200]}. "
            "Source configuration does not prove the deployed version or exploitability. "
            "Vendor/distribution backports and Kotlin component applicability need confirmation. "
            f"Reference: {url}"
        ),
        evidence={
            "ecosystem": runtime.vendor,
            "package": runtime.product,
            "language": runtime.language,
            "version": runtime.version,
            "affected_versions": [runtime.version],
            "declarations": [{"version": runtime.version, "stage": runtime.stage}],
            "advisory": advisory,
            "location": runtime.path,
            "affected_until_excluding": fixes,
            "advisory_url": url,
        },
        remediation=(
            f"Update {runtime.language} in {runtime.path}. {fix} "
            "Rebuild, deploy and rerun the scan."
        ),
    )


def _group_findings(findings: list[EngineFinding]) -> list[EngineFinding]:
    """Retain every declaration before persistence deduplicates by fingerprint.

    Group by the existing source_runtime_cve identity; stages and versions are
    evidence, so changing a runtime does not invalidate stored human triage.
    """
    grouped: dict[tuple[str, ...], EngineFinding] = {}
    for finding in findings:
        evidence = finding.evidence
        key = tuple(evidence[k] for k in ("ecosystem", "package", "advisory", "location"))
        if key not in grouped:
            grouped[key] = finding
            continue
        existing = grouped[key]
        prior = existing.evidence
        prior["affected_versions"] = sorted(
            set(prior["affected_versions"] + evidence["affected_versions"])
        )
        prior["affected_until_excluding"] = sorted(
            set(prior["affected_until_excluding"] + evidence["affected_until_excluding"])
        )
        for declaration in evidence["declarations"]:
            if declaration not in prior["declarations"]:
                prior["declarations"].append(declaration)
        existing.severity = max(
            (existing.severity, finding.severity), key=SEVERITY_RANK.__getitem__
        )

    for finding in grouped.values():
        evidence = finding.evidence
        if len(evidence["declarations"]) < 2:
            continue
        versions = ", ".join(evidence["affected_versions"])
        declarations = "; ".join(
            f"{item['version']} ({item['stage']})" if item["stage"] else item["version"]
            for item in evidence["declarations"]
        )
        language = evidence["language"]
        finding.title = f"{evidence['advisory']}: {language} {versions}"[:255]
        finding.description = (
            f"Affected declarations in {evidence['location']}: {declarations}. "
            + finding.description
        )
        fixes = evidence["affected_until_excluding"]
        guidance = (
            f"NVD affected-range upper bounds (exclusive): {', '.join(fixes)}. "
            if fixes
            else "NVD supplies no fixed version. "
        )
        finding.remediation = (
            f"Update every affected {language} declaration in {evidence['location']}: "
            f"{declarations}. "
            + guidance
            + "Confirm a supported patched release for each branch with the vendor. "
            "Rebuild, deploy and rerun the scan."
        )
    return list(grouped.values())


def audit(
    directory: str,
    *,
    emit: Callable[[str, str], None],
    cancelled: Callable[[], bool] = lambda: False,
    client: httpx.Client | None = None,
) -> tuple[list[EngineFinding], bool]:
    """Return runtime CVE leads and whether inventory/lookups completed without gaps."""
    items = inventory(directory)
    emit(
        "source_inventory",
        "Project languages: " + (", ".join(sorted(items.languages)) or "none detected"),
    )
    for runtime in sorted(items.runtimes):
        emit("source_inventory", f"{runtime.language} {runtime.version} declared in {runtime.path}")
    findings: list[EngineFinding] = []
    owns_client = client is None
    client = client or httpx.Client(follow_redirects=False, trust_env=False)
    api = AdvisoryClient(client, cancelled)
    cache: dict[str, dict] = {}
    try:
        for runtime in sorted(items.runtimes)[:40]:
            try:
                if runtime.cpe not in cache:
                    cache[runtime.cpe] = api.query(runtime)
                doc = cache[runtime.cpe]
                if doc["totalResults"] > len(doc["vulnerabilities"]):
                    items.gaps.append("NVD results truncated; more advisory pages available")
                for item in doc["vulnerabilities"]:
                    if len(findings) >= MAX_FINDINGS:
                        items.gaps.append("runtime CVE finding limit reached")
                        break
                    vuln = item["cve"]
                    if vuln.get("vulnStatus") != "Rejected":
                        findings.append(_finding(runtime, vuln))
            except (httpx.HTTPError, ValueError, TypeError, KeyError, AttributeError):
                items.gaps.append(
                    f"{runtime.path}: {runtime.language} CVE lookup unavailable or incomplete"
                )
        if len(items.runtimes) > 40:
            items.gaps.append("runtime declaration limit reached")
    finally:
        if owns_client:
            client.close()
    findings = _group_findings(findings)
    for gap in list(dict.fromkeys(items.gaps))[:15]:
        emit("source_audit_gap", gap)
    emit(
        "source_audit",
        f"Runtime CVE checks {'incomplete' if items.gaps else 'completed'}: "
        f"{len(findings)} advisory matches",
    )
    return findings, not items.gaps


def _nvd_fixes(configurations: list, runtime: Runtime) -> list[str]:
    fixes: set[str] = set()
    current = tuple(int(n) for n in runtime.version.split("."))
    for config in configurations:
        for node in config.get("nodes") or []:
            for match in node.get("cpeMatch") or []:
                parts = str(match.get("criteria", "")).split(":")
                end = str(match.get("versionEndExcluding", ""))
                start = str(match.get("versionStartIncluding", "0.0.0"))
                if (
                    match.get("vulnerable") is True
                    and len(parts) > 5
                    and parts[3:5] == [runtime.vendor, runtime.product]
                    and _EXACT.fullmatch(start)
                    and _EXACT.fullmatch(end)
                    and tuple(int(n) for n in start.split("."))
                    <= current
                    < tuple(int(n) for n in end.split("."))
                ):
                    fixes.add(end)
    return sorted(fixes)[:12]
