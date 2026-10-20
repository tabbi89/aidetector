"""Shared plumbing for lead-confirmation adjuncts (dalfox, commix, tplmap, …).

The engine's reflection checks only prove a marker comes back; they never test
whether the input actually *executes*. A confirmation adjunct re-tests only the
``(path, param)`` pairs the engine already flagged for a given payload family
with a dedicated CLI tool, so a hit here is a confirmation, not another lead.

This module factors out the pieces every confirmer shares — the executor
contract, target selection by family, URL building, and the per-target run loop
(``LeadConfirmer``) — so each tool module (``sqlmap_confirm``,
``dalfox_confirm``, ``commix_confirm``, ``tplmap_confirm``) is just its own
command builder, output parser and finding mapper.
"""
from __future__ import annotations

import logging
import subprocess
import time
from collections.abc import Callable, Mapping
from contextlib import ExitStack
from typing import Any, ClassVar
from urllib.parse import urlencode

from app.engine.base import EngineFinding

# Command executor contract: argv + timeout seconds → (returncode, stdout).
# Injectable so tests never spawn a process.
Execute = Callable[[list[str], int], tuple[int, str]]


def default_execute(argv: list[str], timeout: int) -> tuple[int, str]:
    """Run a command, capturing stdout. Raises on timeout (caller handles)."""
    r = subprocess.run(argv, capture_output=True, text=True, timeout=timeout)  # noqa: S603
    return r.returncode, r.stdout


def _field(f: Any, name: str) -> Any:
    """Read ``name`` from a finding, ORM row or plain dict alike."""
    if isinstance(f, Mapping):
        return f.get(name)
    return getattr(f, name, None)


def select_family_targets(
    findings: list[Any], family: str, *, max_targets: int = 5
) -> list[dict[str, Any]]:
    """Pick unique (path, param) leads of ``family`` from persisted findings.

    Accepts anything with an ``evidence`` field — an ORM ``Finding``, an
    ``EngineFinding``, or the plain finding dict a local run uploads — so both
    lanes select the same leads. Capped so one scan cannot chain dozens of runs.
    """
    seen: set[tuple[str, str]] = set()
    targets: list[dict[str, Any]] = []
    for f in findings:
        ev = _field(f, "evidence") or {}
        # URL-only adapters cannot faithfully replay a body/header/cookie/path
        # injection. Do not turn broader coverage into a different query attack.
        method = ev.get("method", ev.get("request_method", "GET"))
        if ev.get("location", "query") != "query" or method != "GET":
            continue
        if ev.get("family") != family:
            continue
        path = str(ev.get("path") or "")
        param = str(ev.get("param") or "")
        if not path or not param or (path, param) in seen:
            continue
        seen.add((path, param))
        targets.append(
            {
                "path": path,
                "param": param,
                "operation_id": _field(f, "operation_id"),
                "source_check": _field(f, "check") or "",
            }
        )
        if len(targets) >= max_targets:
            break
    return targets


def build_url(base_url: str, path: str, param: str) -> str:
    """A concrete GET URL with the flagged parameter carrying a probe value."""
    return f"{base_url.rstrip('/')}{path}?{param}=1"


class LeadConfirmer:
    """Drives one confirmation tool over the leads the engine already flagged.

    Subclasses supply ``tool``, ``default_timeout_seconds`` and three pure
    hooks — ``build_command``, ``parse_output``, ``make_finding``. This class
    owns the only part that is identical across every tool: walking the targets
    under the adjunct phase's shared deadline and cooperative cancel, running
    the binary, and isolating failures.

    Failure posture, matching the rest of the adjunct phase:

    - a missing binary aborts the pass and returns what was already confirmed
      (no point retrying the same absent tool per target);
    - any other error on one target skips that target and the pass continues;
    - nothing raises, so a confirmation problem can never fail a scan.

    ``execute`` is injectable so tests never spawn a process.
    """

    #: Event-stage / logger name; also how the tool is named in warnings.
    tool: ClassVar[str] = "confirm"
    #: Per-target wall-clock bound used when the caller passes none.
    default_timeout_seconds: ClassVar[int] = 300

    def __init__(
        self,
        binary: str,
        *,
        execute: Execute = default_execute,
        timeout_seconds: int | None = None,
    ) -> None:
        self._bin = binary
        self._execute = execute
        self._timeout = (
            self.default_timeout_seconds if timeout_seconds is None else timeout_seconds
        )
        self._log = logging.getLogger(f"aidetector.{self.tool}")

    # ---- hooks implemented per tool -------------------------------------

    def build_command(self, url: str) -> list[str]:
        """The argv to run against a single URL."""
        raise NotImplementedError

    def parse_output(self, stdout: str) -> tuple[bool, Any]:
        """``(confirmed, detail)`` from the tool's stdout."""
        raise NotImplementedError

    def make_finding(
        self, target: dict[str, Any], url: str, stdout: str, detail: Any
    ) -> EngineFinding:
        """Map one confirmed lead to a finding."""
        raise NotImplementedError

    def target_command(self, target: dict[str, Any], url: str, stack: ExitStack) -> list[str]:
        return self.build_command(url)

    # ---- shared driver ---------------------------------------------------

    def run(
        self,
        base_url: str,
        targets: list[dict[str, Any]],
        *,
        deadline: float | None = None,
        should_stop: Callable[[], bool] | None = None,
    ) -> list[EngineFinding]:
        findings: list[EngineFinding] = []
        for t in targets:
            if deadline is not None and time.monotonic() > deadline:
                break
            if should_stop is not None and should_stop():
                break
            url = build_url(base_url, t["path"], t["param"])
            if "request" in t:
                url = base_url.rstrip("/") + t["path"]
                params = t["request"].get("params")
                if params:
                    url += "?" + urlencode(params)
            try:
                timeout = self._timeout
                if deadline is not None:
                    timeout = min(timeout, int(deadline - time.monotonic()))
                    if timeout <= 0:
                        break
                with ExitStack() as stack:
                    _, stdout = self._execute(self.target_command(t, url, stack), timeout)
            except FileNotFoundError:
                self._log.warning(
                    "%s binary %r not found; skipping confirmation", self.tool, self._bin
                )
                return findings
            except Exception:  # noqa: BLE001 — one bad target never aborts the pass
                self._log.warning("%s target confirmation failed", self.tool)
                continue
            confirmed, detail = self.parse_output(stdout)
            if "case" in t:
                # Exit status/output alone cannot certify a negative scan;
                # unsuccessful confirmations remain inconclusive.
                t["case"]["outcome"] = "finding" if confirmed else "inconclusive"
            if not confirmed:
                continue
            findings.append(self.make_finding(t, url, stdout, detail))
        return findings
