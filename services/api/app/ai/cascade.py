"""Cascade orchestration — turn HYBRID findings into adjudicated verdicts.

The real cascade drives the planner: DeepSeek directly by default, or the Opus
planner (which may delegate to the DeepSeek executor) under
PLANNER_PROVIDER=anthropic. Tests inject a fake implementing the same `run`
contract.
"""
from __future__ import annotations

from typing import Protocol

from app.ai.planner import OpusPlanner
from app.ai.types import Usage
from app.domain.enums import Confidence
from app.models.finding import Finding


class Cascade(Protocol):
    def run(self, findings_payload: list[dict]) -> tuple[list[dict], list[Usage]]:
        """Return (verdicts, usages). verdicts: [{id, verdict, rationale}]."""
        ...

    def answer(self, findings_payload: list[dict], question: str) -> tuple[str, list[Usage]]:
        """Return (answer, usages). answer: a plain-prose string."""
        ...


def build_plan_payload(operations: list) -> list[dict]:
    """Compact, model-friendly view of the spec's operations for the planner.

    Spec-shape only — method, path, declared params, auth scope. No credentials
    or target data ever leave the process.
    """
    return [
        {
            "operation_id": op.id,
            "method": op.method,
            "path": op.path,
            "auth_scope": op.auth_scope,
            "params": [
                {
                    "name": p.get("name"),
                    "in": p.get("in"),
                    "required": bool(p.get("required")),
                    "schema": p.get("schema") or {},
                }
                for p in op.params
                if p.get("name")
            ],
        }
        for op in operations
    ]


def build_payload(findings: list[Finding]) -> list[dict]:
    """Compact, model-friendly view of findings to adjudicate."""
    return [
        {
            "id": str(f.id),
            "check": f.check,
            "owasp_id": f.owasp_id,
            "severity": f.severity.value,
            # What the engine already established: a "verified" finding is one
            # whose evidence demonstrates the weakness, so the adjudicator is
            # judging the writeup, not the existence of the bug.
            "confidence": (f.confidence or Confidence.heuristic).value,
            "title": f.title,
            "description": f.description,
            "evidence": f.evidence,
            # The generic catalogue fix, so the model improves on it for a
            # confirmed finding rather than restating it.
            "remediation": f.remediation or "",
        }
        for f in findings
    ]


class AICascade:
    """Production cascade over the configured planner provider."""

    def __init__(self, planner: OpusPlanner | None = None) -> None:
        self.planner = planner or OpusPlanner()

    def run(self, findings_payload: list[dict]) -> tuple[list[dict], list[Usage]]:
        return self.planner.adjudicate(findings_payload)

    def plan(self, operations_payload: list[dict]) -> tuple[list[dict], list[Usage]]:
        return self.planner.plan(operations_payload)

    def answer(self, findings_payload: list[dict], question: str) -> tuple[str, list[Usage]]:
        return self.planner.answer(findings_payload, question)

    def generate_payloads(self, families_payload: list[dict]) -> tuple[dict, list[Usage]]:
        return self.planner.generate_payloads(families_payload)
