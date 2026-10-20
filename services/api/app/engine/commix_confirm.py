"""commix confirmation — upgrades heuristic command-injection leads to verified.

The engine's reflection checks only prove a ``;echo marker`` payload is echoed
back; that matches any endpoint that reflects its input. This adjunct re-tests
*parameters the engine already flagged as command-injection leads* with commix,
which performs results-/blind-/time-based OS command injection testing — so a
finding here is a confirmation, not another reflection lead.

Deliberately a *side path*, not a check in ``ALL_CHECKS`` — same posture as
``sqlmap_confirm``:

- **commix makes its own requests** — outside the engine's 750-request budget
  and cooperative cancellation. Bounded by a per-target wall-clock timeout and a
  cap on how many leads are re-tested (``max_targets``).
- **Opt-in via config** (``COMMIX_BIN``), like OAST: unset → silent no-op.
- **Degrades gracefully**: a missing binary, timeout or crash on one target
  skips that target and never fails a scan.

The mappers are pure and unit-tested; the subprocess dance is thin around them.
"""
from __future__ import annotations

import re
from typing import Any

from app.domain.enums import Confidence, Severity
from app.engine.base import EngineFinding
from app.engine.confirm_base import LeadConfirmer, select_family_targets

CMDI_FAMILY = "cmdi"

# commix prints one of these when it reproduces an injectable parameter.
_VULNERABLE_MARKERS = (
    re.compile(r"parameter '[^']+' is vulnerable", re.IGNORECASE),
    re.compile(r"appears to be injectable", re.IGNORECASE),
    re.compile(r"seems to be injectable", re.IGNORECASE),
)
# "Type: results-based command injection" / "Technique: ..." lines.
_TECHNIQUE_LINE = re.compile(
    r"^\s*(?:Type|Technique)\s*:\s*(.+)$", re.MULTILINE | re.IGNORECASE
)


def select_cmdi_targets(findings: list[Any], *, max_targets: int = 5) -> list[dict[str, Any]]:
    return select_family_targets(findings, CMDI_FAMILY, max_targets=max_targets)


def build_command(commix_bin: str, url: str) -> list[str]:
    """Conservative, non-interactive commix invocation.

    ``--batch`` never prompts; ``--disable-coloring`` keeps output parseable;
    the wall-clock timeout is the hard bound.
    """
    return [
        commix_bin,
        "-u", url,
        "--batch",
        "--disable-coloring",
        "--timeout=10",
        "--retries=1",
    ]


def parse_output(stdout: str) -> tuple[bool, list[str]]:
    """Decide vulnerable/not from commix output; return detected techniques."""
    vulnerable = any(p.search(stdout) for p in _VULNERABLE_MARKERS)
    techniques = [t.strip() for t in _TECHNIQUE_LINE.findall(stdout)]
    return vulnerable, techniques


class CommixConfirmer(LeadConfirmer):
    """Re-tests flagged command-injection leads with commix and maps hits."""

    tool = "commix"
    default_timeout_seconds = 300

    def build_command(self, url: str) -> list[str]:
        return build_command(self._bin, url)

    def parse_output(self, stdout: str) -> tuple[bool, list[str]]:
        return parse_output(stdout)

    def make_finding(
        self, target: dict[str, Any], url: str, stdout: str, detail: Any
    ) -> EngineFinding:
        techniques = list(detail)
        return EngineFinding(
            check="commix_confirm",
            confidence=Confidence.verified,
            owasp_id="CWE-78",
            severity=Severity.critical,
            title=(
                f"Command injection confirmed (commix): "
                f"'{target['param']}' on {target['path']}"
            ),
            description=(
                f"commix reproduced OS command injection on the '{target['param']}' "
                f"parameter at {target['path']}, confirming the engine's reflection "
                "lead. This is a verified finding, not a lead."
            ),
            evidence={
                "url": url,
                "path": target["path"],
                "param": target["param"],
                "techniques": techniques,
                "commix_excerpt": stdout[-1500:],
                "source_check": target.get("source_check"),
                "source": "commix",
            },
            operation_id=target.get("operation_id"),
        )
