"""Daily traffic series for the main routes, scored against each route's baseline.

Days are compared by a route's **share** of that day's collected events, not by
raw counts: a sampled day and a full day, or a quiet and a busy day, then stay
comparable. The baseline is the route's own median share over prior complete
days; the score is the distance from it in robust spread units (median absolute
deviation, with floors so a flat history does not turn noise into anomalies).
"""

from __future__ import annotations

from collections.abc import Mapping
from datetime import date
from statistics import median
from typing import TypedDict

#: Below 0.2 percentage points, a shift in share is treated as noise.
SHARE_FLOOR = 0.002
#: A share within 5% of its baseline is never an anomaly on its own.
RELATIVE_FLOOR = 0.05
ANOMALY_SCORE = 4.0
ANOMALY_CHANGE = 0.3
#: Rolling baseline length in days.
BASELINE_WINDOW = 28


class RouteSeriesPoint(TypedDict):
    day: date
    requests: int
    share: float
    blocked: int
    not_found: int


def _int(value: object) -> int:
    if isinstance(value, bool) or not isinstance(value, int | float | str):
        return 0
    try:
        return int(value)
    except ValueError:
        return 0


def _routes(metrics: Mapping[str, object]) -> Mapping[str, object]:
    routes = metrics.get("routes")
    return routes if isinstance(routes, Mapping) else {}


def summarize_routes(
    days: list[tuple[date, Mapping[str, object]]], *, limit: int = 8, minimum_days: int = 7
) -> dict:
    """The busiest routes over the window, each with a daily series and a state."""
    ordered = sorted(
        (item for item in days if _int(item[1].get("event_count")) > 0), key=lambda item: item[0]
    )
    totals: dict[str, int] = {}
    for _, metrics in ordered:
        for route, row in _routes(metrics).items():
            if isinstance(row, Mapping):
                totals[route] = totals.get(route, 0) + _int(row.get("requests"))
    top = sorted(totals.items(), key=lambda item: (-item[1], item[0]))[:limit]

    routes = []
    for route, total in top:
        series: list[RouteSeriesPoint] = []
        daily_shares: list[float] = []
        for day, metrics in ordered:
            count = _int(metrics.get("event_count"))
            row = _routes(metrics).get(route)
            row = row if isinstance(row, Mapping) else {}
            requests = _int(row.get("requests"))
            share = round(requests / count, 5)
            daily_shares.append(share)
            series.append(
                {
                    "day": day,
                    "requests": requests,
                    "share": share,
                    "blocked": _int(row.get("blocked_requests")),
                    "not_found": _int(row.get("not_found_requests")),
                }
            )
        latest, latest_share = series[-1], daily_shares[-1]
        shares = daily_shares[:-1][-BASELINE_WINDOW:]
        baseline = median(shares) if shares else None
        score: float | None = None
        change: float | None = None
        state = "warming_up"
        if baseline is not None and len(shares) >= minimum_days:
            spread = max(
                1.4826 * median(abs(share - baseline) for share in shares),
                SHARE_FLOOR,
                RELATIVE_FLOOR * baseline,
            )
            score = round((latest_share - baseline) / spread, 2)
            change = round((latest_share - baseline) / baseline, 3) if baseline else None
            anomalous = abs(score) >= ANOMALY_SCORE and (
                change is None or abs(change) >= ANOMALY_CHANGE
            )
            state = "anomaly" if anomalous else "normal"
        routes.append(
            {
                "route": route,
                "total_requests": total,
                "latest_day": latest["day"],
                "latest_requests": latest["requests"],
                "latest_share": latest_share,
                "baseline_share": round(baseline, 5) if baseline is not None else None,
                "change": change,
                "score": score,
                "state": state,
                "series": series,
            }
        )
    return {
        "days": len(ordered),
        "sampled": any(isinstance(metrics.get("sample"), Mapping) for _, metrics in ordered),
        "minimum_baseline_days": minimum_days,
        "routes": routes,
    }
