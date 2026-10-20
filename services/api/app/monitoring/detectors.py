"""Deterministic passive detectors for daily infrastructure observations."""
from __future__ import annotations

from collections.abc import Iterable, Mapping
from dataclasses import asdict, dataclass, field
from datetime import date
from statistics import median

from app.monitoring.waf import NormalizedWafEvent, short_key


@dataclass(frozen=True)
class RouteMetrics:
    route_family: str
    requests: int
    successful_requests: int
    not_found_requests: int
    blocked_requests: int
    distinct_identifier_count: int
    distinct_query_shape_count: int

    @property
    def success_rate(self) -> float:
        return self.successful_requests / self.requests if self.requests else 0.0

    @property
    def not_found_rate(self) -> float:
        return self.not_found_requests / self.requests if self.requests else 0.0

    def as_dict(self) -> dict[str, object]:
        return {
            **asdict(self),
            "success_rate": round(self.success_rate, 4),
            "not_found_rate": round(self.not_found_rate, 4),
        }

    @classmethod
    def from_dict(cls, value: Mapping[str, object], *, route_family: str) -> RouteMetrics:
        """Rehydrate persisted aggregate metrics; never rehydrates raw events."""
        return cls(
            route_family=route_family,
            requests=_metric_int(value.get("requests", 0)),
            successful_requests=_metric_int(value.get("successful_requests", 0)),
            not_found_requests=_metric_int(value.get("not_found_requests", 0)),
            blocked_requests=_metric_int(value.get("blocked_requests", 0)),
            distinct_identifier_count=_metric_int(value.get("distinct_identifier_count", 0)),
            distinct_query_shape_count=_metric_int(value.get("distinct_query_shape_count", 0)),
        )


@dataclass(frozen=True)
class EnumerationObservation:
    route_family: str
    fingerprint: str
    severity: str
    confidence: str
    reason: str
    current: RouteMetrics
    baseline: RouteMetrics
    baseline_days: int

    def as_dict(self) -> dict[str, object]:
        return {
            "type": "enumeration_anomaly",
            "route_family": self.route_family,
            "fingerprint": self.fingerprint,
            "severity": self.severity,
            "confidence": self.confidence,
            "reason": self.reason,
            "current": self.current.as_dict(),
            "baseline": self.baseline.as_dict(),
            "baseline_days": self.baseline_days,
        }


@dataclass(slots=True)
class _RouteTally:
    requests: int = 0
    successful: int = 0
    not_found: int = 0
    blocked: int = 0
    identifiers: set[int] = field(default_factory=set)
    query_shapes: set[tuple[str, ...]] = field(default_factory=set)


class RouteAccumulator:
    """Folds events into per-route metrics without keeping the events."""

    def __init__(self) -> None:
        self._routes: dict[str, _RouteTally] = {}

    def add(self, event: NormalizedWafEvent) -> None:
        tally = self._routes.get(event.route_family)
        if tally is None:
            tally = self._routes[event.route_family] = _RouteTally()
        status = event.status_code
        tally.requests += 1
        tally.successful += status is not None and 200 <= status < 300
        tally.not_found += status == 404
        tally.blocked += event.action in {"BLOCK", "BLOCKED"}
        tally.identifiers.update(short_key(value) for value in event.identifier_hashes)
        tally.query_shapes.add(tuple(event.query_keys))

    def result(self) -> dict[str, RouteMetrics]:
        return {
            route: RouteMetrics(
                route_family=route,
                requests=tally.requests,
                successful_requests=tally.successful,
                not_found_requests=tally.not_found,
                blocked_requests=tally.blocked,
                distinct_identifier_count=len(tally.identifiers),
                distinct_query_shape_count=len(tally.query_shapes),
            )
            for route, tally in self._routes.items()
        }


def aggregate_route_metrics(events: Iterable[NormalizedWafEvent]) -> dict[str, RouteMetrics]:
    """Aggregate events by route and discard event-level identifiers."""
    accumulator = RouteAccumulator()
    for event in events:
        accumulator.add(event)
    return accumulator.result()


def _median_metric(metrics: list[RouteMetrics], attr: str) -> int:
    return int(median([getattr(item, attr) for item in metrics])) if metrics else 0


def _metric_int(value: object) -> int:
    if isinstance(value, bool) or not isinstance(value, int | float | str):
        return 0
    try:
        return int(value)
    except ValueError:
        return 0


def detect_enumeration(
    current_events: Iterable[NormalizedWafEvent],
    baseline_by_day: Mapping[date, Iterable[NormalizedWafEvent]],
    *,
    minimum_baseline_days: int = 7,
    min_distinct_identifiers: int = 20,
    volume_multiplier: float = 4.0,
) -> list[EnumerationObservation]:
    """Find likely identifier enumeration only after a complete 7-day baseline.

    The detector intentionally reports a heuristic observation.  It combines
    high identifier cardinality and a traffic jump; it does not claim broken
    authorization, which requires an active identity-bound proof.
    """
    day_rows = {day: tuple(rows) for day, rows in baseline_by_day.items()}
    complete_days = sorted(day for day, rows in day_rows.items() if rows)
    if len(complete_days) < minimum_baseline_days:
        return []

    current = aggregate_route_metrics(current_events)
    history = {day: aggregate_route_metrics(day_rows[day]) for day in complete_days}
    return detect_enumeration_metrics(
        current,
        history,
        minimum_baseline_days=minimum_baseline_days,
        min_distinct_identifiers=min_distinct_identifiers,
        volume_multiplier=volume_multiplier,
    )


def detect_enumeration_metrics(
    current: Mapping[str, RouteMetrics],
    baseline_by_day: Mapping[date, Mapping[str, RouteMetrics]],
    *,
    minimum_baseline_days: int = 7,
    min_distinct_identifiers: int = 20,
    volume_multiplier: float = 4.0,
) -> list[EnumerationObservation]:
    """Compare already-persisted daily aggregates without retaining events."""
    complete_days = sorted(baseline_by_day)
    if len(complete_days) < minimum_baseline_days:
        return []

    history = [baseline_by_day[day] for day in complete_days]
    observations: list[EnumerationObservation] = []
    for route, metrics in current.items():
        prior = [daily[route] for daily in history if route in daily]
        if not prior:
            baseline = RouteMetrics(route, 0, 0, 0, 0, 0, 0)
        else:
            baseline = RouteMetrics(
                route_family=route,
                requests=_median_metric(prior, "requests"),
                successful_requests=_median_metric(prior, "successful_requests"),
                not_found_requests=_median_metric(prior, "not_found_requests"),
                blocked_requests=_median_metric(prior, "blocked_requests"),
                distinct_identifier_count=_median_metric(prior, "distinct_identifier_count"),
                distinct_query_shape_count=_median_metric(prior, "distinct_query_shape_count"),
            )
        high_cardinality = metrics.distinct_identifier_count >= max(
            min_distinct_identifiers, baseline.distinct_identifier_count * 3
        )
        high_volume = metrics.requests >= max(
            min_distinct_identifiers, int(max(1, baseline.requests) * volume_multiplier)
        )
        if not (high_cardinality and high_volume):
            continue
        severity = "high" if metrics.success_rate >= 0.5 else "medium"
        observations.append(
            EnumerationObservation(
                route_family=route,
                fingerprint=_fingerprint(route),
                severity=severity,
                confidence="heuristic",
                reason="identifier cardinality and request volume exceeded the seven-day baseline",
                current=metrics,
                baseline=baseline,
                baseline_days=len(complete_days),
            )
        )
    return observations


def _fingerprint(route_family: str) -> str:
    import hashlib

    return hashlib.sha256(f"monitoring|enumeration|{route_family}".encode()).hexdigest()
