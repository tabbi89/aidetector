"""tplmap confirmation — upgrades heuristic SSTI leads to verified findings.

The engine's reflection checks only prove ``{{marker}}`` is echoed back; they
never prove the template engine *evaluates* it. This adjunct re-tests
*parameters the engine already flagged as SSTI leads* with tplmap, which detects
and (where possible) exploits server-side template injection by observing
arithmetic evaluation — so a finding here is a confirmation, not a lead.

Deliberately a *side path*, not a check in ``ALL_CHECKS`` — same posture as
``sqlmap_confirm``:

- **tplmap makes its own requests** — outside the engine's 750-request budget
  and cooperative cancellation. Bounded by a per-target wall-clock timeout and a
  cap on how many leads are re-tested (``max_targets``).
- **Opt-in via config** (``TPLMAP_BIN``), like OAST: unset → silent no-op.
  tplmap is a deprecated Python-2 tool and is not packaged in Debian; provision
  its interpreter/binary yourself and point ``TPLMAP_BIN`` at the launcher.
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

SSTI_FAMILY = "ssti"

# tplmap prints this when it locates an injection point, and names the engine.
_VULNERABLE_MARKERS = (
    re.compile(r"identified the following injection point", re.IGNORECASE),
    re.compile(r"Tplmap identified", re.IGNORECASE),
)
_ENGINE_LINE = re.compile(r"^\s*Engine\s*:\s*(.+)$", re.MULTILINE | re.IGNORECASE)


def select_ssti_targets(findings: list[Any], *, max_targets: int = 5) -> list[dict[str, Any]]:
    return select_family_targets(findings, SSTI_FAMILY, max_targets=max_targets)


def build_command(tplmap_bin: str, url: str) -> list[str]:
    """Non-interactive tplmap invocation against a single URL.

    tplmap runs without prompting; the wall-clock timeout is the hard bound.
    """
    return [tplmap_bin, "-u", url]


def parse_output(stdout: str) -> tuple[bool, list[str]]:
    """Decide vulnerable/not from tplmap output; return the detected engine(s)."""
    vulnerable = any(p.search(stdout) for p in _VULNERABLE_MARKERS)
    engines = [e.strip() for e in _ENGINE_LINE.findall(stdout)]
    return vulnerable, engines


class TplmapConfirmer(LeadConfirmer):
    """Re-tests flagged SSTI leads with tplmap and maps hits to findings."""

    tool = "tplmap"
    default_timeout_seconds = 240

    def build_command(self, url: str) -> list[str]:
        return build_command(self._bin, url)

    def parse_output(self, stdout: str) -> tuple[bool, list[str]]:
        return parse_output(stdout)

    def make_finding(
        self, target: dict[str, Any], url: str, stdout: str, detail: Any
    ) -> EngineFinding:
        engines = list(detail)
        return EngineFinding(
            check="tplmap_confirm",
            confidence=Confidence.verified,
            owasp_id="CWE-1336",
            severity=Severity.high,
            title=f"SSTI confirmed (tplmap): '{target['param']}' on {target['path']}",
            description=(
                f"tplmap reproduced server-side template injection on the "
                f"'{target['param']}' parameter at {target['path']} "
                + (f"(engine: {', '.join(engines)}) " if engines else "")
                + "— confirming the engine's reflection lead. This is a "
                "verified finding, not a lead."
            ),
            evidence={
                "url": url,
                "path": target["path"],
                "param": target["param"],
                "engines": engines,
                "tplmap_excerpt": stdout[-1500:],
                "source_check": target.get("source_check"),
                "source": "tplmap",
            },
            operation_id=target.get("operation_id"),
        )
