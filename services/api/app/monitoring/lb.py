"""Leads from a load balancer's hourly CloudWatch metrics.

Each UTC hour is compared with **the same hour** on earlier days, not with the day's
average: a nightly batch that is always refused at 03:00 is normal at 03:00, and an
evening peak is normal in the evening. The baseline is the median share over those
days, and the spread is their median absolute deviation, floored so a perfectly flat
history does not turn one extra error into an anomaly.

These metrics cover the whole load balancer, with no route and no client, so every lead
here is ``heuristic`` and says so: "the app refused far more than usual in hour 14" is
timing. It is what makes a WAF lead in hour 14 worth reading first, but it does not say
which client or route caused it.
"""

from __future__ import annotations

import hashlib
from collections.abc import Mapping, Sequence
from statistics import median
from typing import Any

#: Responses the app must have answered in an hour before its share means anything.
MIN_ANSWERED = 100
#: A surge must clear the baseline by this many spread units...
SPREAD_UNITS = 4.0
#: ...and by these floors, so a flat history does not flag noise.
CLIENT_ERROR_FLOOR = 0.05  # five percentage points of 4XX
SERVER_ERROR_FLOOR = 0.01  # one percentage point of 5XX
#: ...and by this factor of the baseline, so an hour that is always refused 40% of the
#: time is not flagged for reaching 46%.
CLIENT_ERROR_RATIO = 2.0
SERVER_ERROR_RATIO = 3.0
#: Server errors worth a lead with no baseline at all: a share and a count.
SINGLE_DAY_SERVER_RATE = 0.05
SINGLE_DAY_SERVER_COUNT = 50
#: 5XX at this share is high severity: a tenth of answers failing is an incident.
HIGH_SERVER_RATE = 0.10
#: p99 must at least double, and grow by half a second, to count as a latency surge.
LATENCY_RATIO = 2.0
LATENCY_FLOOR_SECONDS = 0.5

REMEDIATION = {
    "lb_client_error_surge": (
        "The app refused far more requests than usual in these hours. Read the WAF leads "
        "and route shares for the same hours first: a walk over identifiers, credential "
        "stuffing and a broken client release all look like this. If none match, compare "
        "the deployment log for these hours."
    ),
    "lb_server_error_surge": (
        "The app returned far more 5XX than usual in these hours. Check the deployment log "
        "and target health for these hours; if injection or exploit leads fall in the same "
        "hours, review whether malformed input reached a handler that fails instead of "
        "rejecting it."
    ),
    "lb_latency_surge": (
        "The slowest responses took far longer than usual in these hours. Check target "
        "health and database load for these hours, and whether a crawler or scanner lead "
        "in the same hours was asking for expensive pages."
    ),
}


def _answered(hour: Mapping[str, Any]) -> int:
    return sum(int(hour.get(k) or 0) for k in ("target_2xx", "target_3xx", "target_4xx",
                                                 "target_5xx"))


def _share(hour: Mapping[str, Any], key: str) -> float | None:
    answered = _answered(hour)
    return int(hour.get(key) or 0) / answered if answered >= MIN_ANSWERED else None


def _hours(origin: object) -> dict[int, Mapping[str, Any]]:
    """Hourly points of a stored day, or nothing for a day whose read failed."""
    if not isinstance(origin, Mapping) or origin.get("error"):
        return {}
    rows = origin.get("hours")
    return {
        int(row["hour"]): row
        for row in (rows if isinstance(rows, list) else [])
        if isinstance(row, Mapping) and isinstance(row.get("hour"), int)
    }


def _spread(values: Sequence[float]) -> float:
    centre = median(values)
    return median(abs(v - centre) for v in values)


def _server_severity(flagged: list[dict]) -> str:
    return "high" if max(f["rate"] for f in flagged) >= HIGH_SERVER_RATE else "medium"


def fingerprint(kind: str, load_balancer: str) -> str:
    # One issue per kind per load balancer; the day's affected hours live in ``hours``.
    return hashlib.sha256("|".join(["lb", kind, load_balancer]).encode()).hexdigest()


def _observation(
    kind: str, load_balancer: str, flagged: list[dict], *, severity: str, basis: str,
    baseline_days: int,
) -> dict:
    return {
        "type": kind,
        "fingerprint": fingerprint(kind, load_balancer),
        "route_family": "*",
        "method": "*",
        "cohort": "load_balancer",
        "hours": [row["hour"] for row in flagged],
        "confidence": "heuristic",
        "severity": severity,
        "basis": basis,
        "current": {"load_balancer": load_balancer, "hours": flagged},
        "baseline_days": baseline_days,
        "baseline_requests": 0,
        "remediation": REMEDIATION[kind],
        "disposition": "candidate",
    }


def _rate_surges(
    today: dict[int, Mapping[str, Any]],
    history: list[dict[int, Mapping[str, Any]]],
    key: str,
    *,
    floor: float,
    ratio: float,
) -> list[dict]:
    flagged = []
    for hour, row in sorted(today.items()):
        rate = _share(row, key)
        if rate is None:
            continue
        prior = [r for day in history if hour in day and (r := _share(day[hour], key)) is not None]
        if len(prior) < len(history) or not prior:
            continue  # the same hour must be judgeable on every baseline day
        usual = median(prior)
        threshold = max(usual + SPREAD_UNITS * _spread(prior), usual + floor, usual * ratio)
        if rate >= threshold:
            flagged.append({
                "hour": hour, "answered": _answered(row), "rate": round(rate, 4),
                "usual": round(usual, 4), "count": int(row.get(key) or 0),
            })
    return flagged


def _latency_surges(
    today: dict[int, Mapping[str, Any]], history: list[dict[int, Mapping[str, Any]]]
) -> list[dict]:
    flagged = []
    for hour, row in sorted(today.items()):
        p99 = row.get("response_p99")
        if not isinstance(p99, int | float) or _answered(row) < MIN_ANSWERED:
            continue
        prior = [
            float(day[hour]["response_p99"]) for day in history
            if hour in day and isinstance(day[hour].get("response_p99"), int | float)
        ]
        if len(prior) < len(history) or not prior:
            continue
        usual = median(prior)
        if p99 >= max(usual * LATENCY_RATIO, usual + LATENCY_FLOOR_SECONDS):
            flagged.append({
                "hour": hour, "answered": _answered(row), "p99": round(float(p99), 4),
                "usual": round(usual, 4),
            })
    return flagged


def assess(
    current_origin: object, history_origins: Sequence[object], minimum_days: int
) -> list[dict]:
    """Load balancer leads for one day.

    With ``minimum_days`` of earlier days, each hour is judged against the same hour on
    them. Before that only server errors are judged, on absolute and conservative
    thresholds: a 4XX share or a p99 has no meaning without knowing what is usual here.
    """
    today = _hours(current_origin)
    if not today:
        return []
    load_balancer = (
        str(current_origin.get("load_balancer") or "load_balancer")
        if isinstance(current_origin, Mapping) else "load_balancer"
    )
    history = [h for h in (_hours(o) for o in history_origins) if h]
    observations: list[dict] = []

    if len(history) < minimum_days:
        flagged = []
        for hour, row in sorted(today.items()):
            rate = _share(row, "target_5xx")
            count = int(row.get("target_5xx") or 0)
            if (
                rate is not None
                and rate >= SINGLE_DAY_SERVER_RATE
                and count >= SINGLE_DAY_SERVER_COUNT
            ):
                flagged.append({"hour": hour, "answered": _answered(row), "rate": round(rate, 4),
                                "usual": None, "count": count})
        if flagged:
            observations.append(_observation(
                "lb_server_error_surge", load_balancer, flagged,
                severity=_server_severity(flagged), basis="single_day",
                baseline_days=len(history),
            ))
        return observations

    server = _rate_surges(today, history, "target_5xx",
                          floor=SERVER_ERROR_FLOOR, ratio=SERVER_ERROR_RATIO)
    if server:
        observations.append(_observation(
            "lb_server_error_surge", load_balancer, server,
            severity=_server_severity(server),
            basis="baseline", baseline_days=len(history),
        ))
    client = _rate_surges(today, history, "target_4xx",
                          floor=CLIENT_ERROR_FLOOR, ratio=CLIENT_ERROR_RATIO)
    if client:
        observations.append(_observation(
            "lb_client_error_surge", load_balancer, client,
            severity="medium", basis="baseline", baseline_days=len(history),
        ))
    latency = _latency_surges(today, history)
    if latency:
        observations.append(_observation(
            "lb_latency_surge", load_balancer, latency,
            severity="low", basis="baseline", baseline_days=len(history),
        ))
    return observations
