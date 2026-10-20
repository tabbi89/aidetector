"""Summarize pinned mutmut 3.6 metadata without treating tool errors as kills."""
from __future__ import annotations

import json
import sys
from collections import Counter
from pathlib import Path

# Keep raw results too: mutmut counts pytest INTERNAL_ERROR (3) as killed;
# this report deliberately counts it as an error requiring investigation.
STATUS = {0: "survived", 1: "killed", 3: "errored", 5: "no_tests", 33: "no_tests",
          34: "skipped", 36: "timed_out", -24: "timed_out", 24: "timed_out",
          152: "timed_out", 255: "timed_out", None: "not_checked"}


def main() -> int:
    totals: Counter = Counter()
    modules = {}
    for path in sorted(Path("mutants/app/engine").glob("*.py.meta")):
        raw = json.loads(path.read_text())["exit_code_by_key"]
        counts = Counter(STATUS.get(code, "errored") for code in raw.values())
        totals.update(counts)
        modules[path.name.removesuffix(".py.meta")] = {"counts": counts, "raw": raw}
    if len(modules) != 4 or not totals:
        raise SystemExit("Expected results for all four configured policy modules")
    Path("mutation-report.json").write_text(json.dumps({"totals": totals, "modules": modules},
                                                      indent=2) + "\n")
    for status in ("killed", "survived", "timed_out", "errored",
                   "no_tests", "skipped", "not_checked"):
        print(f"{status}: {totals[status]}")
    # No mutation-score gate yet; incomplete runs and tool errors cannot pass as a report.
    return int(bool(totals["errored"] or totals["not_checked"]))


if __name__ == "__main__":
    sys.exit(main())
