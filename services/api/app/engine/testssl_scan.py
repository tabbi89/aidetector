"""testssl.sh — deep transport audit, opt-in upgrade of the built-in TLS check.

The engine's ``tls`` check analyses the leaf certificate and one negotiated
connection (stdlib ``ssl`` + ``cryptography``): no full chain, no OCSP/CRL, no
cipher-suite enumeration. testssl.sh covers all of that and emits JSON, which
this adjunct maps into findings.

Deliberately a *side path*, not a check in ``ALL_CHECKS``:

- A full testssl sweep takes minutes, so it is **opt-in via config**
  (``TESTSSL_BIN``), like OAST: unset → silent no-op. HTTPS targets only — a
  plaintext target is already flagged by the built-in TLS check.
- Runs outside the engine's request budget (it is a transport probe, not HTTP).
- **Degrades gracefully**: missing binary, timeout or bad output returns no
  findings and never fails a scan.

The mapper is pure and unit-tested; the subprocess dance is thin around it.
"""
from __future__ import annotations

import json
import logging
import os
import tempfile
from typing import Any

from app.domain.enums import Confidence, Severity
from app.engine.base import EngineFinding
from app.engine.confirm_base import Execute, default_execute

log = logging.getLogger("aidetector.testssl")

# testssl.sh severities → our ladder. INFO/LOW are skipped: a full sweep emits
# dozens of informational lines that would drown the findings list. CRITICAL
# must not be dropped — it includes demonstrated attack checks such as ROBOT.
_SEVERITY_MAP = {
    "CRITICAL": Severity.critical,
    "HIGH": Severity.high,
    "MEDIUM": Severity.medium,
}


def map_testssl_entries(entries: list[dict[str, Any]]) -> list[EngineFinding]:
    """Map testssl.sh ``--json`` records into findings. Pure — no I/O."""
    findings: list[EngineFinding] = []
    for e in entries:
        severity = _SEVERITY_MAP.get(str(e.get("severity", "")).upper())
        if severity is None:
            continue
        finding = str(e.get("finding", "")).strip()
        entry_id = str(e.get("id", "")).strip()
        if not finding:
            continue
        cwe = str(e.get("cwe", "")).strip()
        findings.append(
            EngineFinding(
                check="testssl",
                confidence=Confidence.verified,
                owasp_id=f"CWE-{cwe}" if cwe.isdigit() else None,
                severity=severity,
                title=f"TLS: {finding[:120]}",
                description=(
                    f"{finding} Reported by testssl.sh (test id: {entry_id or 'n/a'})."
                ),
                evidence={
                    "id": entry_id,
                    "testssl_severity": str(e.get("severity", "")).upper(),
                    "finding": finding,
                    "cve": str(e.get("cve", "")).strip() or None,
                    "cwe": cwe or None,
                    "source": "testssl",
                },
            )
        )
    return findings


class TestsslScanner:
    """Runs testssl.sh against a URL and maps HIGH/MEDIUM results.

    ``execute`` is injectable so tests never spawn a process. Best-effort:
    any error returns ``[]`` so the scan still completes (like ZapScanner).
    """

    # Name starts with "Test" — keep pytest from treating this as a test class.
    __test__ = False

    def __init__(
        self,
        testssl_bin: str,
        *,
        execute: Execute = default_execute,
        timeout_seconds: int = 300,
    ) -> None:
        self._bin = testssl_bin
        self._execute = execute
        self._timeout = timeout_seconds
        # Set when a run failed rather than found nothing (see ZapScanner.error).
        self.error: str | None = None

    def run(self, url: str) -> list[EngineFinding]:
        fd, json_path = tempfile.mkstemp(prefix="testssl-", suffix=".json")
        os.close(fd)
        try:
            argv = [
                self._bin,
                "--quiet",
                "--color", "0",
                "--jsonfile", json_path,
                url,
            ]
            self._execute(argv, self._timeout)
            with open(json_path, encoding="utf-8") as fh:
                raw = json.load(fh)
            entries = raw if isinstance(raw, list) else []
            return map_testssl_entries(entries)
        except Exception as exc:  # noqa: BLE001 — testssl is optional; never fail a scan
            log.warning("testssl pass failed; continuing without it", exc_info=True)
            self.error = f"{type(exc).__name__}: {exc}"
            return []
        finally:
            try:
                os.unlink(json_path)
            except OSError:
                pass
