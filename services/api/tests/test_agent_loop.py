"""The bounded agent loop: hard caps, graceful degrade, grading stays the engine's."""
from __future__ import annotations

from app.agent.loop import AgentLimits, AgentLoop, _endpoint_url
from app.agent.sandbox import SandboxProc, SandboxUnavailable, ToolResult
from app.domain.enums import Confidence, Severity
from app.engine.base import EngineFinding, ScanContext


class FakeJournal:
    """List-backed RunJournal double (the same shape tests/fakes.py uses)."""

    def __init__(self, seeded: list[dict] | None = None, cancel_after: int | None = None):
        self.findings: list[dict] = list(seeded or [])
        self.events: list[tuple[str, int, str]] = []
        self._cancel_after = cancel_after
        self._event_count = 0

    @property
    def progress(self) -> int:
        return 0

    def event(self, stage: str, pct: int, message: str) -> None:
        self.events.append((stage, pct, message))

    def record(self, finding: EngineFinding) -> None:
        self.findings.append({"check": finding.check, "evidence": finding.evidence})

    def cancelled(self) -> bool:
        self._event_count += 1
        return self._cancel_after is not None and self._event_count > self._cancel_after


class FakeSandbox:
    """Records calls; returns scripted results or raises for named tools."""

    def __init__(self, results=None, unavailable=()):
        self.enabled = True
        self._results = results or {}
        self._unavailable = set(unavailable)
        self.calls: list[tuple[str, str]] = []

    def run(self, tool: str, target: str) -> ToolResult:
        self.calls.append((tool, target))
        if tool in self._unavailable:
            raise SandboxUnavailable(f"{tool} disabled")
        return self._results.get(tool, ToolResult(tool=tool, findings=[], summary=f"{tool}: 0"))


def _ctx(base="http://target:9000") -> ScanContext:
    from app.engine.base import HttpProbe

    probe = HttpProbe.__new__(HttpProbe)  # not exercised by the loop
    return ScanContext(base_url=base, operations=[], credentials=[], probe=probe)


def _nuclei_result() -> ToolResult:
    f = EngineFinding(
        check="kali_nuclei",
        owasp_id=None,
        severity=Severity.high,
        title="nuclei: x",
        description="",
        evidence={"tool": "nuclei", "location": "http://target:9000/.env"},
        confidence=Confidence.heuristic,
    )
    return ToolResult(tool="nuclei", findings=[f], summary="nuclei: 1 finding")


def test_endpoint_url_strips_query_and_rejects_templates_and_offhost() -> None:
    assert _endpoint_url("http://t:9000", "/widgets/5?x=1#y") == "http://t:9000/widgets/5"
    assert _endpoint_url("http://t:9000", "/widgets/{id}") is None
    assert _endpoint_url("http://t:9000", "http://evil/x") is None
    assert _endpoint_url("http://t:9000", "") is None
    assert _endpoint_url("http://t:9000", "http://t:9000/a") == "http://t:9000/a"


def test_disabled_sandbox_yields_no_actions() -> None:
    from app.agent.sandbox import Sandbox

    sb = Sandbox(runner=lambda *a: SandboxProc(0, ""), enabled=False)
    out = AgentLoop(_ctx(), FakeJournal(), sb).run()
    assert out.tool_calls == 0
    # Names what is missing, not just that nothing ran.
    assert "AGENT_SANDBOX_ENABLED" in out.stopped_reason


def test_runs_tools_and_records_findings() -> None:
    j = FakeJournal()
    sb = FakeSandbox(results={"nuclei": _nuclei_result()})
    out = AgentLoop(_ctx(), j, sb).run()
    assert out.findings_added == 1
    assert any(f["check"] == "kali_nuclei" for f in j.findings)
    assert any(stage == "agent_done" for stage, _, _ in j.events)


def test_tool_call_budget_is_capped() -> None:
    j = FakeJournal()
    sb = FakeSandbox()
    out = AgentLoop(_ctx(), j, sb, limits=AgentLimits(max_tool_calls=1)).run()
    assert out.tool_calls == 1
    assert out.stopped_reason == "tool-call budget spent"


def test_wall_clock_deadline_stops_the_loop() -> None:
    j = FakeJournal()
    sb = FakeSandbox()
    ticks = iter([0.0, 0.0, 1000.0, 1000.0, 1000.0])
    out = AgentLoop(
        _ctx(), j, sb, limits=AgentLimits(wall_clock_seconds=1.0), clock=lambda: next(ticks)
    ).run()
    assert out.stopped_reason == "wall-clock budget spent"


def test_unavailable_tool_is_skipped_not_retried() -> None:
    j = FakeJournal()
    sb = FakeSandbox(unavailable=["nuclei", "ffuf", "sqlmap"])
    AgentLoop(_ctx(), j, sb).run()
    assert any(stage == "nuclei_skipped" for stage, _, _ in j.events)
    # Each tool only attempted once despite the loop having budget.
    assert len(sb.calls) == len({t for t, _ in sb.calls})


def test_injection_lead_queues_sqlmap_on_the_endpoint() -> None:
    seeded = [
        {"check": "reflected_injection", "evidence": {"route": "/search?q=aidx"}},
    ]
    j = FakeJournal(seeded=seeded)
    confirm = ToolResult(
        tool="sqlmap",
        findings=[
            EngineFinding(
                check="sqlmap_confirm",
                owasp_id=None,
                severity=Severity.high,
                title="SQLi",
                description="",
                evidence={"tool": "sqlmap"},
                confidence=Confidence.verified,
            )
        ],
        summary="sqlmap: 1",
    )
    sb = FakeSandbox(results={"sqlmap": confirm})
    out = AgentLoop(_ctx(), j, sb, limits=AgentLimits(max_tool_calls=5)).run()
    assert ("sqlmap", "http://target:9000/search") in sb.calls
    assert out.findings_added >= 1
    assert any(f["check"] == "sqlmap_confirm" for f in j.findings)


def test_cancellation_stops_the_loop() -> None:
    j = FakeJournal(cancel_after=0)
    sb = FakeSandbox()
    out = AgentLoop(_ctx(), j, sb).run()
    assert out.stopped_reason == "cancelled"


def test_planner_failure_is_tolerated() -> None:
    class BadPlanner:
        def plan(self, payload):
            raise RuntimeError("deepseek down")

    j = FakeJournal()
    sb = FakeSandbox(results={"nuclei": _nuclei_result()})
    out = AgentLoop(_ctx(), j, sb, planner=BadPlanner()).run()
    assert out.findings_added == 1  # ran anyway, order unchanged


def test_memory_recall_bumps_productive_tools() -> None:
    # A prior nuclei hit on this target should make nuclei run before ffuf.
    j = FakeJournal()
    order: list[str] = []

    class RecordingSandbox(FakeSandbox):
        def run(self, tool, target):
            order.append(tool)
            return super().run(tool, target)

    sb = RecordingSandbox()
    recalls = [{"check": "kali_nuclei", "title": "exposed env"}]
    AgentLoop(_ctx(), j, sb, recalls=recalls, limits=AgentLimits(max_tool_calls=5)).run()
    assert order and order[0] == "nuclei"
