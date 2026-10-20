"""A coverage floor only counts when the complete required-DB suite ran."""
from __future__ import annotations

import json
import sys
import xml.etree.ElementTree as ET
from pathlib import Path

LINE_FLOOR = 89.0
BRANCH_FLOOR = 76.0


def check_report(totals: dict, junit: ET.Element) -> list[str]:
    problems = []
    suites = list(junit.iter("testsuite"))
    for field in ("failures", "errors", "skipped"):
        count = sum(int(s.get(field, "0")) for s in suites)
        if count:
            problems.append(f"JUnit reports {count} {field}; baseline requires a complete run")
    if not sum(int(s.get("tests", "0")) for s in suites):
        problems.append("JUnit contains no tests")
    for name, covered, total, floor in (
        ("line", "covered_lines", "num_statements", LINE_FLOOR),
        ("branch", "covered_branches", "num_branches", BRANCH_FLOOR),
    ):
        denominator = totals[total]
        percent = 100 * totals[covered] / denominator if denominator else 0
        if percent < floor:
            problems.append(f"{name} coverage {percent:.2f}% is below {floor:.2f}%")
    return problems


if __name__ == "__main__":
    totals = json.loads(Path("coverage.json").read_text())["totals"]
    junit = ET.parse("test-report.xml").getroot()
    problems = check_report(totals, junit)
    print("\n".join(problems) if problems else "Coverage floors passed; zero failures/errors/skips")
    sys.exit(bool(problems))
