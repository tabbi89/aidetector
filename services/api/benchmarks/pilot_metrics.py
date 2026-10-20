"""Print the value-free pilot report for one tenant. Read-only.

Usage:
    python -m benchmarks.pilot_metrics --tenant acme --since 2026-10-01
    python -m benchmarks.pilot_metrics --tenant acme --format csv > acme.csv
"""
from __future__ import annotations

import argparse
from datetime import date

from app.core.db import SessionLocal
from app.scans.pilot_metrics import (
    load_scans,
    render_csv,
    render_json,
    summarize,
)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Value-free pilot metrics for one workspace."
    )
    parser.add_argument(
        "--tenant", required=True, help="workspace slug to report on"
    )
    parser.add_argument(
        "--since",
        type=date.fromisoformat,
        default=None,
        help="only scans created on or after this date (YYYY-MM-DD)",
    )
    parser.add_argument(
        "--format",
        choices=("json", "csv"),
        default="json",
        help="json includes the aggregate; csv is one row per scan",
    )
    args = parser.parse_args(argv)

    with SessionLocal() as db:
        scans = load_scans(db, args.tenant, args.since)
        report = summarize(scans, args.tenant, args.since)

    print(render_csv(report) if args.format == "csv" else render_json(report))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
