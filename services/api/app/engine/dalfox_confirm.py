"""dalfox confirmation — upgrades heuristic XSS leads to verified findings.

The engine's ``reflected_injection`` check only proves an XSS marker is echoed
back; it never proves the payload executes in a browser context. This adjunct
re-tests *parameters the engine already flagged as XSS leads* with dalfox, whose
verified ("V") verdict fires a headless browser to confirm the payload actually
triggers — so a finding here is a confirmation, not another reflection lead.

Deliberately a *side path*, not a check in ``ALL_CHECKS`` — same posture as
``sqlmap_confirm``:

- **dalfox makes its own requests** — outside the engine's 750-request budget
  and cooperative cancellation. It is bounded instead by a wall-clock timeout
  per target and a cap on how many leads are re-tested (``max_targets``).
- **Opt-in via config** (``DALFOX_BIN``), like OAST: unset → silent no-op.
- **Degrades gracefully**, like the AI cascade and ZAP: a missing binary,
  timeout or crash on one target skips that target and never fails a scan.

The mappers are pure and unit-tested; the subprocess dance is thin around them.
"""
from __future__ import annotations

import json
from typing import Any

from app.domain.enums import Confidence, Severity
from app.engine.base import EngineFinding
from app.engine.confirm_base import LeadConfirmer, select_family_targets

XSS_FAMILY = "xss"

# dalfox `--format json` emits a JSON array of PoC objects. `type` is the
# strongest signal: "V" = verified (triggered in a headless browser), "R" =
# reflected, "G" = grep/heuristic. We confirm on a verified PoC only; a bare
# reflected PoC is what the engine already reported.
_VERIFIED_TYPES = {"V"}


def select_xss_targets(findings: list[Any], *, max_targets: int = 5) -> list[dict[str, Any]]:
    return select_family_targets(findings, XSS_FAMILY, max_targets=max_targets)


def build_command(dalfox_bin: str, url: str) -> list[str]:
    """Conservative, non-interactive dalfox invocation.

    ``url`` mode scans a single URL. ``--format json`` gives machine output,
    ``--silence`` drops the banner/progress, ``--no-color`` keeps it parseable,
    ``--skip-bav`` skips the noisy basic-analysis probes; the wall-clock timeout
    is the hard bound.
    """
    return [
        dalfox_bin,
        "url", url,
        "--format", "json",
        "--silence",
        "--no-color",
        "--skip-bav",
        "--worker", "5",
        "--timeout", "10",
    ]


def _extract_json_array(stdout: str) -> list[Any] | None:
    """Find and decode the first JSON array in ``stdout``.

    dalfox prints a JSON array (or nothing when clean), but a banner line like
    ``[*] scanning`` can precede it — so we try to ``raw_decode`` an array at
    each ``[`` until one parses, ignoring the noise.
    """
    decoder = json.JSONDecoder()
    idx = stdout.find("[")
    while idx != -1:
        try:
            value, _ = decoder.raw_decode(stdout[idx:])
        except json.JSONDecodeError:
            idx = stdout.find("[", idx + 1)
            continue
        if isinstance(value, list):
            return value
        idx = stdout.find("[", idx + 1)
    return None


def parse_output(stdout: str) -> tuple[bool, list[dict[str, Any]]]:
    """Decide verified/not from dalfox JSON output; return the verified PoCs."""
    data = _extract_json_array(stdout)
    if data is None:
        return False, []
    verified: list[dict[str, Any]] = []
    for poc in data:
        if not isinstance(poc, dict):
            continue
        if str(poc.get("type", "")).upper() in _VERIFIED_TYPES:
            verified.append(
                {
                    "type": poc.get("type"),
                    "method": poc.get("method"),
                    "param": poc.get("param"),
                    "cwe": poc.get("cwe"),
                    "poc": poc.get("data"),
                    "evidence": poc.get("evidence"),
                }
            )
    return bool(verified), verified


class DalfoxConfirmer(LeadConfirmer):
    """Re-tests flagged XSS leads with dalfox and maps verified hits to findings."""

    tool = "dalfox"
    default_timeout_seconds = 180

    def build_command(self, url: str) -> list[str]:
        return build_command(self._bin, url)

    def parse_output(self, stdout: str) -> tuple[bool, list[dict[str, Any]]]:
        return parse_output(stdout)

    def make_finding(
        self, target: dict[str, Any], url: str, stdout: str, detail: Any
    ) -> EngineFinding:
        pocs = list(detail)
        return EngineFinding(
            check="dalfox_confirm",
            confidence=Confidence.verified,
            owasp_id="CWE-79",
            severity=Severity.high,
            title=f"XSS confirmed (dalfox): '{target['param']}' on {target['path']}",
            description=(
                f"dalfox verified cross-site scripting on the '{target['param']}' "
                f"parameter at {target['path']} — the payload triggered in a "
                "headless browser, confirming the engine's reflection lead. "
                "This is a verified finding, not a lead."
            ),
            evidence={
                "url": url,
                "path": target["path"],
                "param": target["param"],
                "pocs": pocs[:10],
                "source_check": target.get("source_check"),
                "source": "dalfox",
            },
            operation_id=target.get("operation_id"),
        )
