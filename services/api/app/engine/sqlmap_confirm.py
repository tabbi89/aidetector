"""sqlmap confirmation — upgrades heuristic SQLi leads to verified findings.

The engine's reflection checks only prove a marker comes back; they never test
boolean/error/UNION/stacked/time behaviour. This adjunct re-tests *parameters
the engine already flagged as SQLi leads* with sqlmap, so a finding here is a
confirmation (sqlmap reproduced injectability), not another lead.

Deliberately a *side path*, not a check in ``ALL_CHECKS``:

- **sqlmap makes its own requests** — outside the engine's 750-request budget
  and cooperative cancellation. It is bounded instead by a wall-clock timeout
  per target, conservative ``--level/--risk`` and a cap on how many leads are
  re-tested (``max_targets``).
- **Opt-in via config** (``SQLMAP_BIN``), like OAST: unset → silent no-op.
- **Degrades gracefully**, like the AI cascade and ZAP: a missing binary,
  timeout or crash on one target skips that target and never fails a scan.

The mappers are pure and unit-tested; the subprocess dance is thin around them.
"""
from __future__ import annotations

import re
from contextlib import ExitStack
from pathlib import Path
from tempfile import TemporaryDirectory
from typing import Any
from urllib.parse import urlencode, urlsplit

from app.domain.enums import Confidence, Severity
from app.engine.base import EngineFinding
from app.engine.confirm_base import LeadConfirmer, build_url, select_family_targets
from app.engine.credentials import wire_kwargs

__all__ = [
    "SQLI_FAMILY",
    "SqlmapConfirmer",
    "build_command",
    # Re-exported: this module's URL shape is part of its tested surface.
    "build_url",
    "parse_output",
    "select_sqli_targets",
]

# Only leads from these checks carry a "sqli" family worth re-testing.
SQLI_FAMILY = "sqli"

# sqlmap prints this when it reproduces an injection; "is not injectable"
# appears otherwise, so the marker is unambiguous.
_VULNERABLE_MARKERS = (
    re.compile(r"parameter '[^']+' is vulnerable"),
    re.compile(r"identified the following injection point"),
)
_TECHNIQUE_LINE = re.compile(r"^\s*Type:\s*(.+)$", re.MULTILINE)


def select_sqli_targets(findings: list[Any], *, max_targets: int = 5) -> list[dict[str, Any]]:
    return select_family_targets(findings, SQLI_FAMILY, max_targets=max_targets)


# sqlmap writes per-target session data (session.db, logs) under an output dir
# that defaults to its cwd — which in the worker is /app (the mounted source
# tree). Pin it to a temp path so scans never pollute the repo.
_SQLMAP_OUTPUT_DIR = "/tmp/runpentests-sqlmap"  # noqa: S108 — scratch, not sensitive


def build_command(sqlmap_bin: str, url: str) -> list[str]:
    """Conservative, non-interactive sqlmap invocation.

    ``--batch`` never prompts; level/risk 1 keep the request footprint small;
    ``--output-dir`` keeps session artifacts out of the mounted source tree; the
    wall-clock timeout is the hard bound.
    """
    return [
        sqlmap_bin,
        "-u", url,
        "--batch",
        "--level=1",
        "--risk=1",
        "--technique=BEUST",
        "--retries=1",
        "--timeout=10",
        "--threads=1",
        "--time-sec=5",
        f"--output-dir={_SQLMAP_OUTPUT_DIR}",
    ]


def parse_output(stdout: str) -> tuple[bool, list[str]]:
    """Decide vulnerable/not from sqlmap output; return detected techniques."""
    vulnerable = any(p.search(stdout) for p in _VULNERABLE_MARKERS)
    techniques = [t.strip() for t in _TECHNIQUE_LINE.findall(stdout)]
    return vulnerable, techniques


class SqlmapConfirmer(LeadConfirmer):
    """Re-tests flagged SQLi leads with sqlmap and maps hits to findings."""

    tool = "sqlmap"
    default_timeout_seconds = 300

    def build_command(self, url: str) -> list[str]:
        return build_command(self._bin, url)

    def target_command(self, target: dict[str, Any], url: str, stack: ExitStack) -> list[str]:
        if "request" not in target:
            return self.build_command(url)
        folder = Path(stack.enter_context(TemporaryDirectory(prefix="runpentests-confirm-")))
        parsed = urlsplit(url)
        # The engine's own request path moves a query-string key out of its
        # pseudo-header at the transport call; this request file is the one
        # place that call is not made, so make it here. The key joins the file's
        # query only — ``url`` is evidence and must never carry it.
        wire = wire_kwargs(target["request"])
        headers = {"Host": parsed.netloc, **(wire.get("headers") or {})}
        if any("\r" in str(v) or "\n" in str(v) for v in headers.values()):
            raise ValueError("invalid request header")
        query = parsed.query
        moved = {
            k: v for k, v in (wire.get("params") or {}).items()
            if k not in (target["request"].get("params") or {})
        }
        if moved:
            query = "&".join(filter(None, [query, urlencode(moved)]))
        path = parsed.path + ("?" + query if query else "")
        raw = "GET " + path + " HTTP/1.1\r\n"
        raw += "".join(f"{k}: {v}\r\n" for k, v in headers.items()) + "\r\n"
        request_file = folder / "request.txt"
        request_file.write_text(raw)
        request_file.chmod(0o600)
        command = self.build_command(url)
        at = command.index("-u")
        command[at:at + 2] = ["-r", str(request_file)]
        command = [arg for arg in command if not arg.startswith("--output-dir=")]
        command.extend(["-p", target["param"], f"--output-dir={folder / 'output'}"])
        if parsed.scheme == "https":
            command.append("--force-ssl")
        return command

    def parse_output(self, stdout: str) -> tuple[bool, list[str]]:
        return parse_output(stdout)

    def make_finding(
        self, target: dict[str, Any], url: str, stdout: str, detail: Any
    ) -> EngineFinding:
        techniques = list(detail)
        return EngineFinding(
            check="sqlmap_confirm",
            confidence=Confidence.verified,
            owasp_id="CWE-89",
            severity=Severity.high,
            title=f"SQLi confirmed (sqlmap): '{target['param']}' on {target['path']}",
            description=(
                f"sqlmap reproduced SQL injection on the '{target['param']}' "
                f"parameter at {target['path']}, confirming the engine's "
                "reflection lead. This is a verified finding, not a lead."
            ),
            evidence={
                "url": url,
                "path": target["path"],
                "param": target["param"],
                "techniques": techniques,
                "sqlmap_excerpt": stdout[-1500:],
                "source_check": target.get("source_check"),
                "source": "sqlmap",
            },
            operation_id=target.get("operation_id"),
        )
