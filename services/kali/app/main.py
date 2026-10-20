"""Kali adjunct service — a thin job API around CLI scanner tools.

Driven by the aidetector worker the same way the ZAP daemon is (see
``services/api/app/engine/kali.py``): it receives a target, runs a bounded
tool invocation, and returns normalized JSON. Six passes:

- ``POST /run/nuclei``   — nuclei template scan (CVEs, exposures, misconfigs)
- ``POST /run/discover`` — ffuf content discovery (bundled wordlist, or SecLists
  when ``deep`` is set and the seclists package is installed)
- ``POST /run/nikto``    — nikto web-server misconfig / known-file scan
- ``POST /run/whatweb``  — whatweb technology fingerprint
- ``POST /run/crawl``    — katana crawl (incl. JS endpoints) for shadow paths
- ``POST /run/params``   — Arjun hidden HTTP-parameter discovery

Safety posture mirrors the parent project:

- No ``shell=True``; argv lists only, and targets are validated as http(s) URLs
  so a hostile target string cannot inject CLI flags.
- Every invocation is bounded by a wall-clock timeout and a request-rate limit.
- Tools run OUTSIDE the engine's 500-request budget by design; the worker gates
  this service behind an explicit per-run opt-in (``kali: true``).
- Optional ``KALI_API_KEY`` env var → callers must send ``X-API-Key``.
"""
from __future__ import annotations

import json
import logging
import os
import shutil
import subprocess
import tempfile
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from fastapi import Depends, FastAPI, Header, HTTPException
from pydantic import BaseModel, Field

log = logging.getLogger("kali-service")
logging.basicConfig(level=logging.INFO)

API_KEY = os.environ.get("KALI_API_KEY", "")
WORDLIST = Path(__file__).parent / "wordlist.txt"
# SecLists API wordlist, installed by the `seclists` Kali package. Used only
# when a discovery run opts in via ``deep`` and the file is present; otherwise
# the bounded bundled wordlist is used. Deeper = slower, so it stays opt-in.
SECLISTS_WORDLIST = Path(
    "/usr/share/seclists/Discovery/Web-Content/api/api-endpoints.txt"
)
MAX_FINDINGS = 200
MAX_PATHS = 100
MAX_PARAMS = 100

app = FastAPI(title="aidetector kali adjunct", docs_url=None, redoc_url=None)


MAX_EXTRA_TARGETS = 25


class ScanRequest(BaseModel):
    target: str = Field(min_length=1, max_length=2048)
    timeout_seconds: int = Field(default=600, ge=1, le=3600)
    rate_limit: int = Field(default=10, ge=1, le=100)
    # Discovery only: use the larger SecLists wordlist when available. Ignored
    # by the other passes. Off by default to keep discovery bounded.
    deep: bool = False
    # Additional http(s) URLs (the scan's rendered operation paths) for the
    # scanner passes (nuclei/nikto/whatweb/katana) to cover alongside the base
    # target. Bounded; ignored by the fuzzing passes (ffuf/arjun).
    extra_targets: list[str] = Field(default_factory=list, max_length=MAX_EXTRA_TARGETS)


def require_key(x_api_key: str | None = Header(default=None)) -> None:
    if API_KEY and x_api_key != API_KEY:
        raise HTTPException(status_code=401, detail="missing or bad X-API-Key")


def validate_target(target: str) -> str:
    """Only plain http(s) URLs; rejects anything that could parse as a flag."""
    parsed = urlparse(target)
    if parsed.scheme not in ("http", "https") or not parsed.netloc or " " in target:
        raise HTTPException(status_code=422, detail="target must be an http(s) URL")
    return target


def resolve_targets(body: ScanRequest) -> list[str]:
    """Base target first, then validated, de-duplicated extra targets."""
    targets = [validate_target(body.target)]
    for t in body.extra_targets:
        v = validate_target(str(t))
        if v not in targets:
            targets.append(v)
    return targets


def run_tool(argv: list[str], timeout: int) -> tuple[str, bool]:
    """Run a CLI tool; return (stdout, timed_out). Raises if the binary is absent."""
    try:
        r = subprocess.run(argv, capture_output=True, text=True, timeout=timeout)  # noqa: S603
        return r.stdout, False
    except subprocess.TimeoutExpired as exc:
        out = exc.stdout or b""
        return (out.decode("utf-8", "replace") if isinstance(out, bytes) else out), True


@app.get("/health")
def health() -> dict[str, Any]:
    tools = ("nuclei", "ffuf", "nikto", "whatweb", "katana", "arjun")
    return {
        "status": "ok",
        "tools": {t: shutil.which(t) is not None for t in tools},
    }


MAX_REFERENCES = 10


def _str_list(value: Any) -> list[str]:
    """A nuclei field that may be a list, a comma-separated string, or absent."""
    if isinstance(value, str):
        value = value.split(",")
    if not isinstance(value, list):
        return []
    return [str(v).strip() for v in value if v is not None and str(v).strip()]


def normalize_nuclei_line(line: str) -> dict[str, Any] | None:
    line = line.strip()
    if not line:
        return None
    try:
        d = json.loads(line)
    except json.JSONDecodeError:
        return None
    if not isinstance(d, dict):
        return None
    info = d.get("info") if isinstance(d.get("info"), dict) else {}
    classification = (
        info.get("classification") if isinstance(info.get("classification"), dict) else {}
    )
    remediation = info.get("remediation")
    return {
        "template_id": d.get("template-id"),
        "name": info.get("name") or d.get("template-id"),
        "severity": info.get("severity") or "info",
        "type": d.get("type"),
        "host": d.get("host"),
        "matched_at": d.get("matched-at") or d.get("matched") or d.get("host"),
        "tags": _str_list(info.get("tags")),
        # The template's own fix, CVE/CWE ids and references; the worker uses the
        # remediation in place of the generic catalogue line when it is present.
        "remediation": remediation.strip()[:2000] if isinstance(remediation, str) else "",
        "cve_ids": _str_list(classification.get("cve-id")),
        "cwe_ids": _str_list(classification.get("cwe-id")),
        "references": _str_list(info.get("reference"))[:MAX_REFERENCES],
    }


@app.post("/run/nuclei", dependencies=[Depends(require_key)])
def run_nuclei(body: ScanRequest) -> dict[str, Any]:
    """Bounded nuclei template scan; returns normalized JSONL results."""
    targets = resolve_targets(body)
    if shutil.which("nuclei") is None:
        raise HTTPException(status_code=503, detail="nuclei not installed")
    argv = ["nuclei", "-silent"]
    for t in targets:  # nuclei accepts repeated -u targets
        argv += ["-u", t]
    argv += [
        "-jsonl",
        "-timeout", "10",
        "-retries", "1",
        "-rate-limit", str(body.rate_limit),
        "-bulk-size", "10",
        "-concurrency", "10",
    ]
    stdout, timed_out = run_tool(argv, body.timeout_seconds)
    findings: list[dict[str, Any]] = []
    for line in stdout.splitlines():
        row = normalize_nuclei_line(line)
        if row is not None:
            findings.append(row)
        if len(findings) >= MAX_FINDINGS:
            break
    return {"findings": findings, "count": len(findings), "timed_out": timed_out}


def parse_ffuf_output(raw: str) -> list[dict[str, Any]]:
    paths: list[dict[str, Any]] = []
    try:
        data = json.loads(raw)
    except json.JSONDecodeError:
        return paths
    results = data.get("results") if isinstance(data, dict) else None
    for r in results if isinstance(results, list) else []:
        if not isinstance(r, dict):
            continue
        fuzz = r.get("input") if isinstance(r.get("input"), dict) else {}
        path = str(fuzz.get("FUZZ") or "")
        if not path:
            continue
        paths.append(
            {
                "path": f"/{path.lstrip('/')}",
                "status": r.get("status"),
                "length": r.get("length"),
                "url": r.get("url"),
            }
        )
        if len(paths) >= MAX_PATHS:
            break
    return paths


@app.post("/run/discover", dependencies=[Depends(require_key)])
def run_discover(body: ScanRequest) -> dict[str, Any]:
    """Bounded ffuf content discovery against the bundled API wordlist."""
    target = validate_target(body.target)
    if shutil.which("ffuf") is None:
        raise HTTPException(status_code=503, detail="ffuf not installed")
    # Deep runs use the SecLists API wordlist when installed; otherwise fall
    # back to the bounded bundled list so discovery never becomes unbounded.
    wordlist = (
        SECLISTS_WORDLIST
        if body.deep and SECLISTS_WORDLIST.is_file()
        else WORDLIST
    )
    if not wordlist.is_file():
        raise HTTPException(status_code=503, detail="wordlist missing")
    fd, out_path = tempfile.mkstemp(prefix="ffuf-", suffix=".json")
    os.close(fd)
    try:
        argv = [
            "ffuf",
            "-noninteractive",
            "-s",
            "-u", f"{target.rstrip('/')}/FUZZ",
            "-w", str(wordlist),
            "-mc", "all",
            "-fc", "404",
            # Auto-calibrate: ffuf probes random paths first and filters
            # responses matching that baseline, so a host that blanket-denies
            # unknown paths (403/401 for everything) doesn't flood results.
            "-ac",
            "-rate", str(body.rate_limit),
            "-of", "json",
            "-o", out_path,
        ]
        _, timed_out = run_tool(argv, body.timeout_seconds)
        try:
            with open(out_path, encoding="utf-8") as fh:
                raw = fh.read()
        except OSError:
            raw = ""
        paths = parse_ffuf_output(raw)
        return {"paths": paths, "count": len(paths), "timed_out": timed_out}
    finally:
        try:
            os.unlink(out_path)
        except OSError:
            pass


# --- nikto: web-server misconfig / known-file scan -------------------------
def parse_nikto_output(raw: str) -> list[dict[str, Any]]:
    """Parse nikto's JSON report into normalized vulnerability rows."""
    findings: list[dict[str, Any]] = []
    try:
        data = json.loads(raw)
    except json.JSONDecodeError:
        return findings
    # nikto -Format json emits either a dict with "vulnerabilities" or a list
    # of such dicts (one per host). Normalize both.
    hosts = data if isinstance(data, list) else [data]
    for host in hosts:
        if not isinstance(host, dict):
            continue
        vulns = host.get("vulnerabilities")
        for v in vulns if isinstance(vulns, list) else []:
            if not isinstance(v, dict):
                continue
            findings.append(
                {
                    "id": v.get("id"),
                    "method": v.get("method"),
                    "url": v.get("url"),
                    "message": v.get("msg") or v.get("message"),
                    "references": v.get("references"),
                }
            )
            if len(findings) >= MAX_FINDINGS:
                return findings
    return findings


@app.post("/run/nikto", dependencies=[Depends(require_key)])
def run_nikto(body: ScanRequest) -> dict[str, Any]:
    """Bounded nikto scan; returns normalized JSON vulnerabilities."""
    targets = resolve_targets(body)
    if shutil.which("nikto") is None:
        raise HTTPException(status_code=503, detail="nikto not installed")
    fd, out_path = tempfile.mkstemp(prefix="nikto-", suffix=".json")
    os.close(fd)
    try:
        argv = [
            "nikto",
            "-h", ",".join(targets),  # nikto accepts a comma-separated host list
            "-Format", "json",
            "-output", out_path,
            "-nointeractive",
            "-nocheck",
            "-maxtime", f"{body.timeout_seconds}s",
            "-Pause", f"{1 / body.rate_limit:.3f}",
        ]
        _, timed_out = run_tool(argv, body.timeout_seconds + 30)
        try:
            with open(out_path, encoding="utf-8") as fh:
                raw = fh.read()
        except OSError:
            raw = ""
        findings = parse_nikto_output(raw)
        return {"findings": findings, "count": len(findings), "timed_out": timed_out}
    finally:
        try:
            os.unlink(out_path)
        except OSError:
            pass


# --- whatweb: technology fingerprint ---------------------------------------
def parse_whatweb_output(raw: str) -> list[dict[str, Any]]:
    """Parse whatweb --log-json into a flat list of {plugin, value} rows."""
    try:
        data = json.loads(raw)
    except json.JSONDecodeError:
        return []
    rows = data if isinstance(data, list) else [data]
    out: list[dict[str, Any]] = []
    for r in rows:
        if not isinstance(r, dict):
            continue
        plugins = r.get("plugins")
        if not isinstance(plugins, dict):
            continue
        for name, detail in plugins.items():
            value = ""
            if isinstance(detail, dict):
                # whatweb nests string/version under "string"/"version" lists.
                bits = []
                for k in ("string", "version", "module"):
                    v = detail.get(k)
                    if isinstance(v, list):
                        bits.extend(str(x) for x in v)
                    elif v:
                        bits.append(str(v))
                value = ", ".join(bits)
            out.append({"plugin": name, "value": value})
    return out


@app.post("/run/whatweb", dependencies=[Depends(require_key)])
def run_whatweb(body: ScanRequest) -> dict[str, Any]:
    """Technology fingerprint of the target via whatweb (informational)."""
    targets = resolve_targets(body)
    if shutil.which("whatweb") is None:
        raise HTTPException(status_code=503, detail="whatweb not installed")
    # whatweb takes every URL as a positional argument.
    argv = [
        "whatweb",
        "--no-errors",
        "--log-json=-",
        "--max-threads=1",
        f"--wait={1 / body.rate_limit:.3f}",
        "-a", "3",
        *targets,
    ]
    stdout, timed_out = run_tool(argv, body.timeout_seconds)
    plugins = parse_whatweb_output(stdout)
    return {"plugins": plugins, "count": len(plugins), "timed_out": timed_out}


# --- katana: crawl (incl. JS endpoints) for shadow paths -------------------
def parse_katana_output(raw: str) -> list[dict[str, Any]]:
    """Parse katana plain (one URL per line) output into unique path rows."""
    seen: set[str] = set()
    paths: list[dict[str, Any]] = []
    for line in raw.splitlines():
        url = line.strip()
        if not url or " " in url:
            continue
        parsed = urlparse(url)
        path = parsed.path or "/"
        if path in seen:
            continue
        seen.add(path)
        paths.append({"path": path, "url": url, "status": None})
        if len(paths) >= MAX_PATHS:
            break
    return paths


@app.post("/run/crawl", dependencies=[Depends(require_key)])
def run_crawl(body: ScanRequest) -> dict[str, Any]:
    """Bounded katana crawl (JS-aware) reporting discovered endpoint paths."""
    targets = resolve_targets(body)
    if shutil.which("katana") is None:
        raise HTTPException(status_code=503, detail="katana not installed")
    argv = [
        "katana",
        "-u", ",".join(targets),  # katana accepts a comma-separated URL list
        "-jc",              # crawl endpoints found in JavaScript
        "-silent",
        "-d", "2",          # bounded depth
        "-c", "10",
        "-timeout", "10",
        "-rl", str(body.rate_limit),
        "-fs", "fqdn",      # stay on the target host
    ]
    stdout, timed_out = run_tool(argv, body.timeout_seconds)
    paths = parse_katana_output(stdout)
    return {"paths": paths, "count": len(paths), "timed_out": timed_out}


# --- arjun: hidden HTTP-parameter discovery --------------------------------
def parse_arjun_output(raw: str) -> list[dict[str, Any]]:
    """Parse arjun -oJ output into {url, method, params} rows."""
    try:
        data = json.loads(raw)
    except json.JSONDecodeError:
        return []
    out: list[dict[str, Any]] = []
    # arjun writes {url: {"params": [...], "method": "GET"}, ...}.
    if isinstance(data, dict):
        for url, detail in data.items():
            if not isinstance(detail, dict):
                continue
            params = detail.get("params")
            params = [str(p) for p in params] if isinstance(params, list) else []
            if not params:
                continue
            out.append(
                {"url": url, "method": detail.get("method"), "params": params[:MAX_PARAMS]}
            )
    return out


@app.post("/run/params", dependencies=[Depends(require_key)])
def run_params(body: ScanRequest) -> dict[str, Any]:
    """Discover hidden query parameters on the target with Arjun."""
    target = validate_target(body.target)
    if shutil.which("arjun") is None:
        raise HTTPException(status_code=503, detail="arjun not installed")
    fd, out_path = tempfile.mkstemp(prefix="arjun-", suffix=".json")
    os.close(fd)
    try:
        argv = [
            "arjun",
            "-u", target,
            "-oJ", out_path,
            "-q",
            "--stable",
            "--rate-limit", str(body.rate_limit),
        ]
        _, timed_out = run_tool(argv, body.timeout_seconds)
        try:
            with open(out_path, encoding="utf-8") as fh:
                raw = fh.read()
        except OSError:
            raw = ""
        results = parse_arjun_output(raw)
        return {"results": results, "count": len(results), "timed_out": timed_out}
    finally:
        try:
            os.unlink(out_path)
        except OSError:
            pass
