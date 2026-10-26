"""The bounded whitebox agent loop.

Phase 3 slice 3. After the engine tier runs, this loop spends a small, hard-
capped budget to *widen and confirm* what the engine found: it picks sandboxed
tools to run, feeds their findings back through the journal (so grading, not the
agent, decides verified-vs-heuristic), and uses the source index to explain the
result with ``file:line``. It then reflects and either continues or stops.

It is deliberately **bounded, not autonomous** (the design decision behind this
whole phase):

- Three hard caps — ``max_steps``, ``max_tool_calls`` and a wall-clock
  ``deadline`` — any of which ends the loop. A reflector also ends it early when
  a step makes no progress or the action queue drains.
- The agent only ever names a tool from the sandbox allowlist and a target the
  engine already knows; it cannot invent an image, a flag, or a check key.
- It **never relaxes a safety gate.** It issues no writes (mutation stays the
  engine's ``mutate`` opt-in) and adds no destructive verbs; the tools run in
  the sandbox's hardened containers.
- A planner (DeepSeek via the existing seam) is *optional* and only ever
  **reprioritises** the deterministic action queue. If it is absent or fails,
  the loop runs the same actions in a deterministic order — the product's
  standing rule that an AI problem never changes what a scan does.

DB-free and planner-injected, so it stays in ``PURE_MODULES``.
"""
from __future__ import annotations

import logging
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any, Protocol
from urllib.parse import urlsplit, urlunsplit

from app.agent.sandbox import Sandbox, SandboxUnavailable
from app.agent.source import SourceIndex
from app.engine.base import ScanContext
from app.engine.journal import RunJournal

log = logging.getLogger("runpentests.agent.loop")

#: Engine checks whose leads a confirmation tool (sqlmap) can follow up.
_INJECTION_LEADS = frozenset({"reflected_injection", "signature_injection"})


class Planner(Protocol):
    """Just the one capability the loop uses: rank operations by risk.

    Reuses the existing ``plan`` mode (``app.ai.planner.OpusPlanner.plan``); the
    loop never asks the model to choose a tool or a target, only to order the
    ones the engine already surfaced.
    """

    def plan(self, operations_payload: list[dict]) -> tuple[list[dict], list[Any]]: ...


@dataclass(frozen=True)
class AgentLimits:
    """The three hard caps. Defaults are intentionally small — this is a bounded
    confirmation pass, not a second full scan."""

    max_steps: int = 6
    max_tool_calls: int = 4
    wall_clock_seconds: float = 300.0


@dataclass
class _Action:
    """One queued tool invocation: a tool name, a target, a priority and why."""

    tool: str
    target: str
    priority: int = 1
    rationale: str = ""


@dataclass
class AgentOutcome:
    steps: int = 0
    tool_calls: int = 0
    findings_added: int = 0
    tools_unavailable: list[str] = field(default_factory=list)
    stopped_reason: str = ""


def _endpoint_url(base_url: str, route: str) -> str | None:
    """A concrete endpoint URL from a finding's route, query and payload stripped.

    Returns None when the route still carries an unresolved ``{id}`` template or
    is not under the scan's base — a tool needs a real URL, and we never fabricate
    one or point a tool somewhere the engine was not already probing.
    """
    if not route:
        return None
    if route.startswith(("http://", "https://")):
        candidate = route
    else:
        candidate = base_url.rstrip("/") + "/" + route.lstrip("/")
    parts = urlsplit(candidate)
    if not parts.scheme or not parts.netloc:
        return None
    if "{" in parts.path or "}" in parts.path:
        return None
    base_host = urlsplit(base_url).netloc
    if base_host and parts.netloc != base_host:
        return None
    # Drop query (it may carry the engine's rotating payload) and fragment.
    return urlunsplit((parts.scheme, parts.netloc, parts.path, "", ""))


class AgentLoop:
    """Drives the bounded confirmation pass. ``run`` returns what it did."""

    def __init__(
        self,
        ctx: ScanContext,
        journal: RunJournal,
        sandbox: Sandbox,
        *,
        source: SourceIndex | None = None,
        planner: Planner | None = None,
        limits: AgentLimits | None = None,
        recalls: list[dict] | None = None,
        clock: Callable[[], float] = time.monotonic,
    ):
        self._ctx = ctx
        self._journal = journal
        self._sandbox = sandbox
        self._source = source
        self._planner = planner
        self._limits = limits or AgentLimits()
        self._recalls = recalls or []
        self._clock = clock

    # -- planning ------------------------------------------------------------
    def _plan_actions(self) -> list[_Action]:
        """Build the deterministic action queue from the engine's findings.

        - one ``nuclei`` sweep of the base target (broad exposure/CVE leads);
        - one ``ffuf`` discovery pass of the base target (shadow endpoints);
        - a ``sqlmap`` confirmation per distinct injection-lead endpoint.

        Only tools the sandbox actually offers are queued, so a disabled sandbox
        yields an empty plan and the loop stops cleanly.
        """
        if not getattr(self._sandbox, "enabled", True):
            return []
        base = self._ctx.base_url
        actions: list[_Action] = [
            _Action("nuclei", base, priority=2, rationale="broad exposure/CVE sweep"),
            _Action("ffuf", base, priority=1, rationale="shadow-endpoint discovery"),
        ]
        seen: set[str] = set()
        for finding in self._engine_findings():
            if finding.get("check") not in _INJECTION_LEADS:
                continue
            evidence = finding.get("evidence") or {}
            route = str(evidence.get("route") or evidence.get("path") or "")
            url = _endpoint_url(base, route)
            if url is None or url in seen:
                continue
            seen.add(url)
            actions.append(
                _Action("sqlmap", url, priority=3, rationale=f"confirm injection lead on {route}")
            )
        actions = [a for a in actions if a.tool in self._sandbox_tools()]
        self._bump_from_memory(actions)
        actions = self._reprioritise(actions)
        # Highest priority first; stable within a priority.
        return sorted(actions, key=lambda a: -a.priority)

    def _bump_from_memory(self, actions: list[_Action]) -> None:
        """Raise the priority of tools a prior heavy run found productive here.

        Episodic memory steers spending of the small tool budget toward what has
        worked on this target before; it never adds or removes an action, so a
        wrong recall cannot invent or suppress a finding.
        """
        if not self._recalls:
            return
        from app.agent.memory import prior_productive_tools

        productive = prior_productive_tools(self._recalls)
        if not productive:
            return
        for action in actions:
            if action.tool in productive:
                action.priority += 2
                action.rationale += " (seen on this target before)"

    def _reprioritise(self, actions: list[_Action]) -> list[_Action]:
        """Let the planner reorder, advisory only; any failure keeps the order."""
        if self._planner is None or not actions:
            return actions
        payload = [
            {
                "operation_id": str(i),
                "method": "",
                "path": a.target,
                "params": [],
                "auth_scope": None,
            }
            for i, a in enumerate(actions)
        ]
        try:
            plan, _ = self._planner.plan(payload)
        except Exception:  # noqa: BLE001 — AI never changes what the scan does
            return actions
        rank = {"high": 3, "medium": 2, "low": 1}
        for row in plan or []:
            try:
                idx = int(str(row.get("operation_id")))
            except (TypeError, ValueError):
                continue
            if 0 <= idx < len(actions):
                actions[idx].priority = rank.get(str(row.get("priority")), actions[idx].priority)
        return actions

    # -- execution -----------------------------------------------------------
    def run(self) -> AgentOutcome:
        outcome = AgentOutcome()
        deadline = self._clock() + self._limits.wall_clock_seconds
        queue = self._plan_actions()
        if not queue:
            outcome.stopped_reason = (
                "no sandbox actions available"
                if getattr(self._sandbox, "enabled", True)
                # Say what is missing: "nothing available" reads as a fault in
                # the user's config, when it is this machine that cannot do it.
                else "the agent ran no tools: nuclei, ffuf and sqlmap each run in their own "
                "Docker container, and this runner cannot start one (AGENT_SANDBOX_ENABLED "
                "is off or docker is missing) — the source annotation above does not need "
                "the agent, so leave it off here"
            )
            self._journal.event("agent_idle", self._journal.progress, outcome.stopped_reason)
            return outcome

        self._journal.event(
            "agent_start",
            self._journal.progress,
            f"bounded agent: {len(queue)} candidate action(s), "
            f"≤{self._limits.max_tool_calls} tool call(s)",
        )
        unavailable: set[str] = set()
        while queue:
            if outcome.steps >= self._limits.max_steps:
                outcome.stopped_reason = "step cap reached"
                break
            if outcome.tool_calls >= self._limits.max_tool_calls:
                outcome.stopped_reason = "tool-call budget spent"
                break
            if self._clock() >= deadline:
                outcome.stopped_reason = "wall-clock budget spent"
                break
            if self._journal.cancelled():
                outcome.stopped_reason = "cancelled"
                break

            action = queue.pop(0)
            outcome.steps += 1
            if action.tool in unavailable:
                # Reflector: do not keep trying a tool that already proved absent.
                continue
            before = outcome.findings_added
            self._run_action(action, outcome, unavailable)
            # Reflector: a step that produced nothing and drained the queue ends it.
            if not queue and outcome.findings_added == before:
                outcome.stopped_reason = outcome.stopped_reason or "queue drained"

        if not outcome.stopped_reason:
            outcome.stopped_reason = "queue drained"
        outcome.tools_unavailable = sorted(unavailable)
        self._journal.event(
            "agent_done",
            self._journal.progress,
            f"agent ran {outcome.tool_calls} tool call(s) over {outcome.steps} step(s); "
            f"added {outcome.findings_added} finding(s) — {outcome.stopped_reason}",
        )
        return outcome

    def _run_action(self, action: _Action, outcome: AgentOutcome, unavailable: set[str]) -> None:
        outcome.tool_calls += 1
        try:
            result = self._sandbox.run(action.tool, action.target)
        except SandboxUnavailable as exc:
            unavailable.add(action.tool)
            # A tool that did not run must never read as a clean result.
            self._journal.event(
                f"{action.tool}_skipped",
                self._journal.progress,
                f"{action.tool} did not run: {exc}",
            )
            return
        new_findings = [self._as_dict(f) for f in result.findings]
        self._annotate(new_findings)
        for ef in result.findings:
            self._journal.record(ef)
        outcome.findings_added += len(result.findings)
        self._journal.event(
            f"{action.tool}_done",
            self._journal.progress,
            f"{result.summary} ({action.rationale})",
        )

    def _annotate(self, findings: list[dict]) -> None:
        if self._source is None or not findings:
            return
        try:
            self._source.annotate_findings(findings, redactor=self._ctx.redact)
        except Exception:  # noqa: BLE001 — whitebox is enhancement, never required
            log.debug("source annotation failed", exc_info=True)

    # -- helpers -------------------------------------------------------------
    def _engine_findings(self) -> list[dict]:
        """The findings recorded so far, as dicts. The journal fake and the
        HTTP runner journal both expose a ``findings`` list of dicts."""
        got = getattr(self._journal, "findings", None)
        rows: list[dict] = []
        for f in got or []:
            if isinstance(f, dict):
                rows.append(f)
            else:  # an EngineFinding-like object
                rows.append(
                    {"check": getattr(f, "check", None), "evidence": getattr(f, "evidence", {})}
                )
        return rows

    @staticmethod
    def _as_dict(finding: Any) -> dict:
        return {"check": finding.check, "evidence": finding.evidence}

    def _sandbox_tools(self) -> set[str]:
        from app.agent.sandbox import SANDBOX_TOOLS

        return set(SANDBOX_TOOLS)
