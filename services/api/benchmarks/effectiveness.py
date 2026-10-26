"""Score a scan of a *real* vulnerable API against a ground-truth manifest.

Every quality number the project reports today comes from paired synthetic
targets (``tests/vulnapp.py`` / ``tests/safeapp.py`` and
``tests/methodology_benchmark.py``). Those catch regressions, but they are
written alongside the checks, so they cannot tell us how the engine does against
an API it was not built against. This harness closes that gap: point it at a
known-vulnerable third-party API (crAPI, VAmPI, …) with a hand-curated list of
the weaknesses that API is documented to have, and it reports, per OWASP
category and per check, how much the engine *found* (recall) and how much of
what it reported lines up with the ground truth (precision).

Two halves, kept apart so the scoring is testable without any target running:

- :func:`score` and :func:`load_manifest` are pure — given a list of findings and
  a manifest, they compute the result. Unit-tested.
- :func:`run_against_api` drives the public HTTP API end to end (the same calls
  the CLI and web make) against a live target, then feeds the findings to
  :func:`score`. Needs a running stack and target; see ``benchmarks/README.md``.

Precision here is measured against the manifest, which is necessarily
incomplete — a real API has weaknesses nobody wrote down. A finding that matches
no manifest entry is reported as *unexpected*, not automatically a false
positive: it is a lead to review, which is exactly how the product frames a
heuristic finding. The header is explicit about this so the number is never read
as a hard false-positive rate.
"""
from __future__ import annotations

import json
from collections.abc import Iterable, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from app.engine.coverage import path_matcher


@dataclass(frozen=True)
class ExpectedVuln:
    """One weakness a target is documented to have, as ground truth."""

    owasp_id: str
    route: str
    method: str | None = None
    #: Optional: the specific check expected to catch it, for a tighter score.
    check: str | None = None
    note: str = ""

    def matches(self, finding: Finding) -> bool:
        if self.owasp_id != finding.owasp_id:
            return False
        if self.method and finding.method and self.method.upper() != finding.method.upper():
            return False
        if self.check and finding.check and self.check != finding.check:
            return False
        return path_matcher(self.route).match(finding.route or "") is not None


@dataclass(frozen=True)
class Finding:
    """A scan finding, normalized to what scoring needs."""

    check: str
    owasp_id: str | None
    route: str
    method: str | None = None
    severity: str = ""
    confidence: str = ""

    @classmethod
    def from_api(cls, row: dict[str, Any]) -> Finding:
        evidence = row.get("evidence") or {}
        return cls(
            check=str(row.get("check", "")),
            owasp_id=row.get("owasp_id"),
            route=str(evidence.get("route") or evidence.get("path") or ""),
            method=evidence.get("request_method") or evidence.get("method"),
            severity=str(row.get("severity", "")),
            confidence=str(row.get("confidence", "")),
        )


@dataclass
class CategoryScore:
    owasp_id: str
    expected: int = 0
    found: int = 0

    @property
    def recall(self) -> float:
        return self.found / self.expected if self.expected else 0.0


@dataclass
class BenchmarkResult:
    target: str
    expected_total: int
    covered: int
    findings_total: int
    matched_findings: int
    missed: list[ExpectedVuln] = field(default_factory=list)
    unexpected: list[Finding] = field(default_factory=list)
    categories: dict[str, CategoryScore] = field(default_factory=dict)

    @property
    def recall(self) -> float:
        return self.covered / self.expected_total if self.expected_total else 0.0

    @property
    def manifest_precision(self) -> float:
        """Share of findings that match a manifest entry. See module docstring:
        the manifest is incomplete, so this is a floor, not a false-positive rate."""
        return self.matched_findings / self.findings_total if self.findings_total else 0.0

    def to_dict(self) -> dict[str, Any]:
        return {
            "target": self.target,
            "scope": "measured against a hand-curated ground-truth manifest; "
            "unexpected findings are leads to review, not confirmed false positives",
            "expected_total": self.expected_total,
            "covered": self.covered,
            "recall": round(self.recall, 4),
            "findings_total": self.findings_total,
            "matched_findings": self.matched_findings,
            "manifest_precision": round(self.manifest_precision, 4),
            "categories": {
                owasp: {
                    "expected": c.expected,
                    "found": c.found,
                    "recall": round(c.recall, 4),
                }
                for owasp, c in sorted(self.categories.items())
            },
            "missed": [
                {"owasp_id": m.owasp_id, "method": m.method, "route": m.route, "note": m.note}
                for m in self.missed
            ],
            "unexpected": [
                {"check": f.check, "owasp_id": f.owasp_id, "route": f.route,
                 "severity": f.severity, "confidence": f.confidence}
                for f in self.unexpected
            ],
        }


def load_manifest(path: str | Path) -> tuple[str, list[ExpectedVuln]]:
    """Load ``{"target": str, "expected": [ExpectedVuln...]}`` from a JSON file."""
    data = json.loads(Path(path).read_text())
    target = str(data.get("target", str(path)))
    expected = [
        ExpectedVuln(
            owasp_id=str(e["owasp_id"]),
            route=str(e["route"]),
            method=e.get("method"),
            check=e.get("check"),
            note=str(e.get("note", "")),
        )
        for e in data.get("expected", [])
    ]
    return target, expected


def score(
    target: str, findings: Sequence[Finding], expected: Sequence[ExpectedVuln]
) -> BenchmarkResult:
    """Recall (did we find each documented weakness) and manifest-precision."""
    categories: dict[str, CategoryScore] = {}
    for e in expected:
        categories.setdefault(e.owasp_id, CategoryScore(e.owasp_id)).expected += 1

    missed: list[ExpectedVuln] = []
    covered = 0
    for e in expected:
        if any(e.matches(f) for f in findings):
            covered += 1
            categories[e.owasp_id].found += 1
        else:
            missed.append(e)

    matched_findings = sum(1 for f in findings if any(e.matches(f) for e in expected))
    unexpected = [f for f in findings if not any(e.matches(f) for e in expected)]

    return BenchmarkResult(
        target=target,
        expected_total=len(expected),
        covered=covered,
        findings_total=len(findings),
        matched_findings=matched_findings,
        missed=missed,
        unexpected=unexpected,
        categories=categories,
    )


def render_table(result: BenchmarkResult) -> str:
    """A compact human-readable summary."""
    lines = [
        f"target: {result.target}",
        f"recall: {result.covered}/{result.expected_total} "
        f"({result.recall:.0%}) documented weaknesses found",
        f"manifest-precision: {result.matched_findings}/{result.findings_total} "
        f"findings matched the manifest ({result.manifest_precision:.0%}); "
        f"{len(result.unexpected)} unexpected (review, not confirmed FPs)",
        "",
        "by OWASP category:",
    ]
    for owasp, c in sorted(result.categories.items()):
        lines.append(f"  {owasp:<12} {c.found}/{c.expected} ({c.recall:.0%})")
    if result.missed:
        lines.append("")
        lines.append("missed (recall gaps to investigate):")
        for m in result.missed:
            lines.append(f"  {m.owasp_id:<12} {m.method or 'ANY':<6} {m.route}  {m.note}")
    return "\n".join(lines)


# --- live driver: the same end-to-end calls the CLI and web make --------------


def run_against_api(
    *,
    api_url: str,
    target_url: str,
    spec_path: str,
    manifest_path: str,
    credentials: Iterable[dict[str, Any]] = (),
    api_key: str | None = None,
    level: str = "deep",
    mutate: bool = True,
    poll_seconds: float = 2.0,
    timeout_seconds: float = 1800.0,
) -> BenchmarkResult:  # pragma: no cover - needs a live stack + target
    """Create a scan, run it against ``target_url``, and score the findings.

    Drives the public HTTP API exactly as a client would, so it exercises the
    real pipeline rather than the in-process engine. Not unit-tested: it needs a
    running API and a reachable vulnerable target (see ``benchmarks/README.md``).
    """
    import time

    import httpx

    target, expected = load_manifest(manifest_path)
    headers = {"X-API-Key": api_key} if api_key else {}
    with httpx.Client(base_url=api_url.rstrip("/"), headers=headers, timeout=60.0) as http:
        scan_id = http.post("/scans", json={"target_base_url": target_url}).json()["id"]
        http.post(f"/scans/{scan_id}/spec", files={"file": Path(spec_path).read_bytes()})
        for cred in credentials:
            http.post(f"/scans/{scan_id}/credentials", json=cred)
        http.post(f"/scans/{scan_id}/run", json={"authorized": True, "level": level,
                                                  "mutate": mutate})
        deadline = time.monotonic() + timeout_seconds
        while time.monotonic() < deadline:
            status = http.get(f"/scans/{scan_id}").json().get("status")
            if status in {"completed", "failed", "cancelled"}:
                break
            time.sleep(poll_seconds)
        rows = http.get(f"/scans/{scan_id}/findings").json()
    findings = [Finding.from_api(r) for r in rows]
    return score(target, findings, expected)


def _main(argv: list[str] | None = None) -> int:  # pragma: no cover - CLI glue
    import argparse

    parser = argparse.ArgumentParser(description="Score a scan of a live vulnerable API.")
    parser.add_argument("--api-url", required=True, help="aidetector API base URL")
    parser.add_argument("--target-url", required=True, help="the vulnerable API's base URL")
    parser.add_argument("--spec", required=True, help="OpenAPI spec file for the target")
    parser.add_argument("--manifest", required=True, help="ground-truth manifest JSON")
    parser.add_argument("--api-key", default=None)
    parser.add_argument("--level", default="deep")
    parser.add_argument("--format", choices=("table", "json"), default="table")
    args = parser.parse_args(argv)

    result = run_against_api(
        api_url=args.api_url,
        target_url=args.target_url,
        spec_path=args.spec,
        manifest_path=args.manifest,
        api_key=args.api_key,
        level=args.level,
    )
    if args.format == "json":
        print(json.dumps(result.to_dict(), indent=2))
    else:
        print(render_table(result))
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(_main())
