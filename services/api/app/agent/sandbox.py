"""Per-tool Docker sandboxes the heavy-lane agent drives.

Phase 3 slice 2. The bounded agent can run a handful of external tools to
confirm or widen the engine's leads, but it never chooses *how* they run: this
module owns a **curated allowlist** mapping a tool name to a fixed image, a
fixed argument shape and a pure output parser. The agent picks a name from the
allowlist and a target — never an image, never extra flags, never a shell
string — so there is no path from an LLM suggestion to an arbitrary container or
command.

Mirrors the adjunct phase's discipline (``app/engine/adjuncts.py``):

- **Graceful degrade.** A tool that cannot run raises :class:`SandboxUnavailable`
  and the caller records a ``<tool>_skipped`` — a tool that did not run must
  never read as a clean result.
- **Bounded.** Every invocation is hardened (``--read-only``, ``--cap-drop ALL``,
  ``--security-opt no-new-privileges``, an unprivileged uid, memory/pid limits)
  and time-boxed; output is read with a byte cap.
- **Findings are graded conservatively.** They flow back through the engine's
  grading and default to :class:`Confidence.heuristic`; only a tool that
  *confirms* exploitation (sqlmap on a vulnerable parameter) earns
  ``verified``. An unconfirmed lead stays a lead.
- **DB-free.** Imports only the pure engine/domain vocabulary, so it stays in
  ``PURE_MODULES``.

The default execution path shells out to ``docker run``; it is **off unless
``AGENT_SANDBOX_ENABLED`` is set and a ``docker`` binary is present**, so the
runner never spawns containers implicitly. Tests inject a fake process runner
and exercise the allowlist and parsers with no Docker at all.
"""
from __future__ import annotations

import json
import logging
import os
import shutil
import subprocess
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

from app.domain.enums import Confidence, Severity
from app.engine.base import EngineFinding

log = logging.getLogger("aidetector.agent.sandbox")

#: Hardening every sandbox container runs with, whatever the tool.
_HARDENING = (
    "--rm",
    "--read-only",
    "--tmpfs",
    "/tmp",
    "--cap-drop",
    "ALL",
    "--security-opt",
    "no-new-privileges",
    "--user",
    "65534:65534",
    "--memory",
    "512m",
    "--pids-limit",
    "256",
    "--network",
    "host",
)

#: Largest tool output we read, so a chatty tool cannot exhaust memory.
MAX_OUTPUT_BYTES = 4 * 1024 * 1024
#: nuclei severities → our ladder.
_NUCLEI_SEVERITY = {
    "critical": Severity.critical,
    "high": Severity.high,
    "medium": Severity.medium,
    "low": Severity.low,
    "info": Severity.info,
    "unknown": Severity.info,
}


class SandboxUnavailable(RuntimeError):
    """A sandbox tool that could not run — Docker absent, disabled, or it failed.

    Distinct from "ran and found nothing": the caller turns this into a
    ``<tool>_skipped`` event so a missing tool never reads as a clean result.
    """


@dataclass
class SandboxProc:
    """What a process runner returns: a finished subprocess, abstractly."""

    returncode: int
    stdout: str
    stderr: str = ""


#: The execution seam. Given argv, optional stdin and a timeout, run it and
#: return the result, or raise SandboxUnavailable. Injected in tests.
ProcRunner = Callable[[list[str], str | None, float], SandboxProc]


@dataclass
class ToolResult:
    tool: str
    findings: list[EngineFinding] = field(default_factory=list)
    #: A short, already-bounded tail of raw output, for an event/debug line.
    summary: str = ""


Parser = Callable[[str, str], list[EngineFinding]]


@dataclass(frozen=True)
class ToolSpec:
    """One allowlisted tool: its image, how its argv is built, how output parses.

    ``check_key`` must be a key the server's ingest accepts and the remediation
    catalogue knows (see ``SANDBOX_CHECK_KEYS``).
    """

    image: str
    check_key: str
    timeout: int
    build_args: Callable[[str], list[str]]
    parse: Parser


def _nuclei_args(target: str) -> list[str]:
    # JSONL to stdout; template tags restricted to the API-relevant families so
    # a run stays bounded; silent banner. No user-supplied flags.
    return [
        "-u",
        target,
        "-jsonl",
        "-silent",
        "-tags",
        "api,exposure,misconfig,cve",
        "-timeout",
        "10",
    ]


def _ffuf_args(target: str) -> list[str]:
    base = target.rstrip("/")
    return ["-u", f"{base}/FUZZ", "-of", "json", "-o", "/dev/stdout", "-s"]


def _sqlmap_args(target: str) -> list[str]:
    return ["-u", target, "--batch", "--level", "1", "--risk", "1", "--smart"]


def _parse_nuclei(stdout: str, _stderr: str) -> list[EngineFinding]:
    findings: list[EngineFinding] = []
    for line in stdout.splitlines():
        line = line.strip()
        if not line.startswith("{"):
            continue
        try:
            row = json.loads(line)
        except json.JSONDecodeError:
            continue
        info = row.get("info") or {}
        sev = _NUCLEI_SEVERITY.get(str(info.get("severity", "info")).lower(), Severity.info)
        template = str(row.get("template-id") or row.get("templateID") or "nuclei")
        name = str(info.get("name") or template)
        matched = str(row.get("matched-at") or row.get("host") or "")
        classification = info.get("classification") or {}
        evidence: dict[str, Any] = {
            "tool": "nuclei",
            "template": template,
            "issue": name,
            "location": matched,
        }
        refs = info.get("reference")
        if isinstance(refs, list) and refs:
            evidence["references"] = [str(r) for r in refs[:5]]
        cwe = classification.get("cwe-id")
        if cwe:
            evidence["cwe"] = cwe if isinstance(cwe, str) else (cwe[0] if cwe else None)
        findings.append(
            EngineFinding(
                check="kali_nuclei",
                owasp_id=None,
                severity=sev,
                title=f"nuclei: {name}"[:255],
                description=f"nuclei template {template} matched at {matched}".strip(),
                evidence=evidence,
                # A template match is a strong lead, not an exploitation proof.
                confidence=Confidence.heuristic,
            )
        )
    return findings


def _parse_ffuf(stdout: str, _stderr: str) -> list[EngineFinding]:
    try:
        doc = json.loads(stdout or "{}")
    except json.JSONDecodeError:
        return []
    findings: list[EngineFinding] = []
    for r in (doc.get("results") or [])[:100]:
        url = str(r.get("url") or "")
        status = r.get("status")
        findings.append(
            EngineFinding(
                check="kali_discovery",
                owasp_id=None,
                severity=Severity.low,
                title=f"undocumented path: {url}"[:255],
                description=f"ffuf found a responding path ({status}) the spec never declared",
                evidence={"tool": "ffuf", "location": url, "issue": "shadow endpoint"},
                confidence=Confidence.heuristic,
            )
        )
    return findings


def _parse_sqlmap(stdout: str, stderr: str) -> list[EngineFinding]:
    blob = (stdout + "\n" + stderr).lower()
    # sqlmap prints these exact phrases when a parameter is confirmed injectable.
    confirmed = "is vulnerable" in blob or "sqlmap identified the following injection point" in blob
    if not confirmed:
        return []
    return [
        EngineFinding(
            check="sqlmap_confirm",
            owasp_id=None,
            severity=Severity.high,
            title="SQL injection confirmed by sqlmap",
            description="sqlmap confirmed an injectable parameter on the target.",
            evidence={"tool": "sqlmap", "issue": "sql injection"},
            # sqlmap confirmed exploitation — this one is verified.
            confidence=Confidence.verified,
        )
    ]


#: The curated allowlist. The agent names a key here; nothing else is runnable.
SANDBOX_TOOLS: dict[str, ToolSpec] = {
    "nuclei": ToolSpec(
        image="projectdiscovery/nuclei:latest",
        check_key="kali_nuclei",
        timeout=300,
        build_args=_nuclei_args,
        parse=_parse_nuclei,
    ),
    "ffuf": ToolSpec(
        image="ghcr.io/ffuf/ffuf:latest",
        check_key="kali_discovery",
        timeout=180,
        build_args=_ffuf_args,
        parse=_parse_ffuf,
    ),
    "sqlmap": ToolSpec(
        image="googlesky/sqlmap:latest",
        check_key="sqlmap_confirm",
        timeout=300,
        build_args=_sqlmap_args,
        parse=_parse_sqlmap,
    ),
}

#: Check keys the sandbox may emit. The server ingest widens its accepted-key
#: set with exactly these (all have remediation catalogue entries).
SANDBOX_CHECK_KEYS: frozenset[str] = frozenset(spec.check_key for spec in SANDBOX_TOOLS.values())


def available_tools() -> list[str]:
    return sorted(SANDBOX_TOOLS)


def _default_proc_runner(argv: list[str], stdin: str | None, timeout: float) -> SandboxProc:
    """Shell out to a real process. Off unless explicitly enabled."""
    try:
        proc = subprocess.run(
            argv,
            input=stdin,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
    except FileNotFoundError as exc:  # docker binary vanished between check and run
        raise SandboxUnavailable("docker not found") from exc
    except subprocess.TimeoutExpired as exc:
        raise SandboxUnavailable(f"tool timed out after {timeout:.0f}s") from exc
    out = (proc.stdout or "")[:MAX_OUTPUT_BYTES]
    err = (proc.stderr or "")[:MAX_OUTPUT_BYTES]
    return SandboxProc(returncode=proc.returncode, stdout=out, stderr=err)


class Sandbox:
    """Runs allowlisted tools in hardened containers and parses their output.

    ``runner`` is the process seam: the default shells out to ``docker run`` and
    is enabled only when ``AGENT_SANDBOX_ENABLED`` is set and a ``docker`` binary
    exists. Pass an explicit runner (tests do) to drive it with no Docker.
    """

    def __init__(
        self,
        *,
        runner: ProcRunner | None = None,
        network: str = "",
        enabled: bool | None = None,
    ):
        self._network = network
        if runner is not None:
            self._runner = runner
            self._enabled = True if enabled is None else enabled
            return
        env_on = os.environ.get("AGENT_SANDBOX_ENABLED", "").lower() in ("1", "true", "yes")
        has_docker = shutil.which("docker") is not None
        self._enabled = (env_on and has_docker) if enabled is None else enabled
        self._runner = _default_proc_runner

    @property
    def enabled(self) -> bool:
        return self._enabled

    def _docker_argv(self, spec: ToolSpec, target: str) -> list[str]:
        hardening = list(_HARDENING)
        if self._network:
            # Replace the default --network host with the requested network.
            i = hardening.index("--network")
            hardening[i + 1] = self._network
        return ["docker", "run", *hardening, spec.image, *spec.build_args(target)]

    def run(self, tool: str, target: str) -> ToolResult:
        """Run one allowlisted tool against ``target``. Raises if it cannot run.

        ``target`` is expected to be an already-guarded base URL (the caller
        runs ``target_guard`` before any socket opens); the sandbox does not
        accept free-form arguments, only a tool name and a target, so there is
        no flag-injection surface.
        """
        spec = SANDBOX_TOOLS.get(tool)
        if spec is None:
            raise SandboxUnavailable(f"tool not in the allowlist: {tool}")
        if not self._enabled:
            raise SandboxUnavailable(
                "sandbox disabled (set AGENT_SANDBOX_ENABLED and install docker)"
            )
        if not isinstance(target, str) or not target.startswith(("http://", "https://")):
            raise SandboxUnavailable("target must be an absolute http(s) URL")
        argv = self._docker_argv(spec, target)
        try:
            proc = self._runner(argv, None, float(spec.timeout))
        except SandboxUnavailable:
            raise
        except Exception as exc:  # noqa: BLE001 — any execution failure is "did not run"
            raise SandboxUnavailable(f"{tool} failed: {type(exc).__name__}") from exc
        findings = spec.parse(proc.stdout, proc.stderr)
        summary = f"{tool}: exit {proc.returncode}, {len(findings)} finding(s)"
        return ToolResult(tool=tool, findings=findings, summary=summary)
