"""Test doubles for the collaborators a scan can reach outside itself.

The AI cascade, the planner and the confirmation tools are all injection seams
precisely so tests never spend tokens or spawn processes. These doubles were
previously defined inside individual test modules, which meant one test file had
to import another to reuse them — collecting a whole unrelated module as a side
effect. They live here instead.
"""
from __future__ import annotations

from collections.abc import Callable
from types import SimpleNamespace
from typing import Any

from app.ai.types import Usage


class FakeCascade:
    """Adjudicates every finding with a canned verdict; records what it saw."""

    def __init__(
        self,
        usages: list[Usage] | None = None,
        verdict_for: Callable[[str], str] | None = None,
        remediation_for: Callable[[str], str] | None = None,
    ) -> None:
        self.usages = usages or []
        self.verdict_for = verdict_for or (lambda check: "confirmed")
        # None → the model returns no remediation (the static fix stands).
        self.remediation_for = remediation_for
        self.seen_payload: list[dict] | None = None
        #: How many times the cascade was actually invoked. A re-scan over
        #: unchanged findings should hit the adjudication cache and leave this
        #: alone — that is the property the cache exists for.
        self.calls = 0

    def run(self, findings_payload: list[dict]) -> tuple[list[dict], list[Usage]]:
        self.calls += 1
        self.seen_payload = findings_payload
        verdicts = []
        for f in findings_payload:
            v = {
                "id": f["id"],
                "verdict": self.verdict_for(f["check"]),
                "rationale": f"AI says {self.verdict_for(f['check'])} for {f['check']}",
            }
            if self.remediation_for is not None:
                v["remediation"] = self.remediation_for(f["check"])
            verdicts.append(v)
        return verdicts, self.usages

    def answer(self, findings_payload: list[dict], question: str) -> tuple[str, list[Usage]]:
        self.calls += 1
        self.seen_payload = findings_payload
        return f"canned answer to: {question}", self.usages


class BrokenCascade:
    """Raises on use — the graceful-degradation path."""

    def run(self, findings_payload: list[dict]) -> tuple[list[dict], list[Usage]]:
        raise RuntimeError("planner exploded")

    def answer(self, findings_payload: list[dict], question: str) -> tuple[str, list[Usage]]:
        # The real planner wraps every failure mode in PlannerUnavailable, which
        # the ask route maps to 502; mirror that contract here.
        from app.ai.planner import PlannerUnavailable

        raise PlannerUnavailable("planner exploded")


class FakePlanner:
    """Returns a canned per-operation plan + usages (no network)."""

    def __init__(
        self,
        priority_for: Callable[[str], str],
        usages: list[Usage] | None = None,
    ) -> None:
        self.priority_for = priority_for
        self.usages = usages or []
        self.seen: list[dict] | None = None

    def plan(self, operations_payload: list[dict]) -> tuple[list[dict], list[Usage]]:
        self.seen = operations_payload
        return (
            [
                {
                    "operation_id": o["operation_id"],
                    "priority": self.priority_for(o["path"]),
                    "rationale": f"risk for {o['path']}",
                }
                for o in operations_payload
            ],
            self.usages,
        )


class BrokenPlanner:
    """Raises on use — planning failures must leave the scan in spec order."""

    def plan(self, operations_payload: list[dict]) -> tuple[list[dict], list[Usage]]:
        raise RuntimeError("planner unavailable")


def adjunct_harness(
    base_url: str = "http://t:9000", findings: list[Any] | None = None
) -> tuple[Any, Any, Callable[[str, int, str], None], list[str]]:
    """A DB-free stand-in for the objects an adjunct pass touches.

    The passes only need ``scan.progress/findings/target_base_url``, a
    ``db.commit()`` and an ``emit`` callable, so fakes exercise the exact gates
    without a database. Returns ``(db, scan, emit, events)`` where ``events``
    collects the emitted stage names.
    """
    scan = SimpleNamespace(
        progress=50, findings=findings or [], target_base_url=base_url
    )
    db = SimpleNamespace(commit=lambda: None)
    events: list[str] = []

    def emit(stage: str, pct: int, message: str) -> None:
        events.append(stage)

    return db, scan, emit, events


def lead_finding(family: str, path: str = "/items", param: str = "id") -> Any:
    """A persisted-looking finding carrying the confirmation-tier evidence keys."""
    return SimpleNamespace(
        check="reflected_injection",
        evidence={"family": family, "path": path, "param": param},
        operation_id=None,
    )


class CollectorOob:
    """In-memory OAST client: reads the vulnapp's simulated outbound fetches.

    Implements the OobClient interface so the engine's OOB path is exercised
    end-to-end without a real interactsh server or a network callback.
    """

    active = True
    _host = "oast.test"

    def __init__(self, outbound: list[str]) -> None:
        self._outbound = outbound

    def payload_url(self, token: str) -> str:
        return f"http://{token}.{self._host}/{token}"

    def payload_domain(self, token: str) -> str:
        return f"{token}.{self._host}"

    def poll(self) -> list[Any]:
        from app.engine.oob import Interaction

        seen = []
        for url in self._outbound:
            host = url.split("//", 1)[-1].split("/", 1)[0]
            token = host.split(".", 1)[0]
            seen.append(
                Interaction(protocol="http", token=token, source_ip="127.0.0.1", raw=url)
            )
        return seen


class FakeJournal:
    """A :class:`~app.engine.journal.RunJournal` backed by two lists.

    The run-level invariants — a cancel lands at a stage boundary, discovery
    only runs under ``kali``, triage applies after adjudication — used to be
    exercisable only through a full run against Postgres, so in an environment
    without a database they *skipped* rather than failed. This is what makes
    them unit tests.

    ``cancel_after`` fires a cancel once ``cancelled()`` has been asked that
    many times, which is how a test places a cancel at a chosen stage boundary.
    """

    def __init__(self, cancel_after: int | None = None) -> None:
        self.findings: list[Any] = []
        self.events: list[tuple[str, int, str]] = []
        #: Lifecycle calls in order — "begin", "complete", "cancel", "fail", …
        self.lifecycle: list[str] = []
        self._cancel_after = cancel_after
        self.cancel_checks = 0

    # ---- RunJournal ----------------------------------------------------

    @property
    def progress(self) -> int:
        return self.events[-1][1] if self.events else 0

    def event(self, stage: str, pct: int, message: str) -> None:
        self.events.append((stage, pct, message))

    def record(self, finding: Any) -> None:
        self.findings.append(finding)

    def cancelled(self) -> bool:
        self.cancel_checks += 1
        return self._cancel_after is not None and self.cancel_checks > self._cancel_after

    # ---- lifecycle ------------------------------------------------------

    def begin(self) -> None:
        self.lifecycle.append("begin")

    def complete(self) -> list[Any]:
        self.lifecycle.append("complete")
        return list(self.findings)

    def cancel(self) -> list[Any]:
        self.lifecycle.append("cancel")
        return list(self.findings)

    def fail(self, exc: BaseException | None = None) -> None:
        self.lifecycle.append("fail")

    def note_budget(self) -> None:
        """Called after every stage; not a lifecycle transition."""

    def note_skipped(self, checks: list[str]) -> None:
        self.skipped = list(checks)

    def note_failed(self, checks: list[str]) -> None:
        self.failed = list(checks)

    def apply_triage(self) -> None:
        self.lifecycle.append("triage")

    @property
    def stages(self) -> list[str]:
        return [stage for stage, _, _ in self.events]
