"""Pure passive decisions over bounded method/cohort/hour aggregates."""

from __future__ import annotations

import hashlib
from collections.abc import Iterable
from dataclasses import dataclass, field
from statistics import median

from app.monitoring.waf import NormalizedWafEvent, short_key

#: Buckets kept per day. A production day has far more client/route/hour
#: buckets than can be stored; the busiest are kept, which is where enumeration
#: shows, and the rest are counted in ``buckets_truncated``.
MAX_BUCKETS = 1000
ACCOUNT_ROUTE_WORDS = ("login", "register", "recovery", "reset", "signup", "password")

#: Against the baseline: a bucket surges at this many requests and this factor of its median.
SURGE_REQUESTS = 20
SURGE_RATIO = 4
#: ...and enumerates at this many identifiers and factor of its median, walking them in
#: order or missing this often.
ENUM_IDENTIFIERS = 20
ENUM_IDENTIFIER_RATIO = 3
ENUM_SEQUENTIAL = 0.5
ENUM_NOT_FOUND = 10
#: A median response this much larger than usual, and at least this many bytes.
SIZE_RATIO = 4
SIZE_FLOOR_BYTES = 4096
#: One day on its own: absolute and more conservative.
DAY_ENUM_IDENTIFIERS = 50
DAY_ENUM_NOT_FOUND = 20
DAY_ACCOUNT_REQUESTS = 50
HIGH_VOLUME_REQUESTS = 200
HIGH_VOLUME_SHARE = 0.25

REMEDIATION = {
    "enumeration_anomaly": (
        "Review object ownership checks and per-identity rate limits; "
        "verify suspicious reads with an authorized active BOLA test."
    ),
    "account_enumeration_lead": (
        "Use uniform login and recovery responses and rate limits. Compare "
        "response behavior with controlled test accounts before confirming "
        "enumeration."
    ),
    "sensitive_request_metadata": (
        "Move credentials and personal data out of URLs and Referer "
        "headers; redact upstream proxy logs and use an appropriate "
        "Referrer-Policy."
    ),
    "shadow_route": (
        "Reconcile the runtime route with the pinned API contract and "
        "review authentication and exposure before adding it to the "
        "contract."
    ),
    "response_size_drift": (
        "Compare the deployment and declared response schema; inspect a "
        "separately authorized redacted sample before claiming data "
        "exposure."
    ),
    "high_volume_client": (
        "One client made a large share of this hour's requests. Check whether it is an "
        "expected integration or batch job; otherwise rate-limit it per identity or IP."
    ),
}


@dataclass(slots=True)
class _BucketTally:
    method: str
    route: str
    cohort: str
    hour: int
    route_mapping: str
    requests: int = 0
    successes: int = 0
    not_found: int = 0
    identifiers: set[int] = field(default_factory=set)
    successors: set[int] = field(default_factory=set)
    variants: set[tuple[int | None, int]] = field(default_factory=set)
    sizes: list[int] = field(default_factory=list)
    sensitive: set[str] = field(default_factory=set)

    def as_dict(self) -> dict:
        return {
            "method": self.method,
            "route": self.route,
            "cohort": self.cohort,
            "hour": self.hour,
            "requests": self.requests,
            "identifiers": len(self.identifiers),
            "sequentiality": round(
                len(self.identifiers & self.successors) / max(1, len(self.identifiers) - 1), 3
            ),
            "successes": self.successes,
            "not_found": self.not_found,
            "response_variants": len(self.variants),
            "median_bytes": int(median(self.sizes)) if self.sizes else None,
            "sensitive_locations": sorted(self.sensitive),
            "route_mapping": self.route_mapping,
        }


class BucketAccumulator:
    """Folds events into method/route/cohort/hour buckets without keeping them."""

    def __init__(self) -> None:
        self._buckets: dict[str, _BucketTally] = {}
        self.events = 0
        self.unmapped = 0

    def add(self, event: NormalizedWafEvent) -> None:
        self.events += 1
        self.unmapped += event.route_mapping != "declared"
        cohort = event.principal_hash or event.source_ip_hash or "anonymous"
        hour = event.observed_at.hour
        key = f"{event.method}|{event.route_family}|{cohort}|{hour}"
        tally = self._buckets.get(key)
        if tally is None:
            tally = self._buckets[key] = _BucketTally(
                event.method, event.route_family, cohort, hour, event.route_mapping
            )
        status = event.status_code
        tally.requests += 1
        tally.successes += status is not None and 200 <= status < 300
        tally.not_found += status == 404
        tally.identifiers.update(short_key(value) for value in event.identifier_hashes)
        tally.successors.update(short_key(value) for value in event.successor_hashes)
        tally.variants.add((status, (event.response_bytes or 0) // 128))
        if event.response_bytes is not None:
            tally.sizes.append(event.response_bytes)
        tally.sensitive.update(event.sensitive_locations)

    def result(self) -> dict:
        kept = list(self._buckets.items())
        if len(kept) > MAX_BUCKETS:
            kept = sorted(kept, key=lambda item: (-item[1].requests, item[0]))[:MAX_BUCKETS]
        return {
            "version": 2,
            "buckets": {key: tally.as_dict() for key, tally in kept},
            "buckets_truncated": len(self._buckets) - len(kept),
            "event_count": self.events,
            "unmapped_count": self.unmapped,
        }


def aggregate(events: Iterable[NormalizedWafEvent]) -> dict:
    accumulator = BucketAccumulator()
    for event in events:
        accumulator.add(event)
    return accumulator.result()


def fingerprint(kind: str, row: dict) -> str:
    boundary = "|".join([kind, row["method"], row["route"], row["cohort"]])
    return hashlib.sha256(boundary.encode()).hexdigest()


def _is_account_route(route: str) -> bool:
    return any(word in route.split("/") for word in ACCOUNT_ROUTE_WORDS)


def _record(
    observations: dict[str, dict],
    kind: str,
    row: dict,
    *,
    basis: str,
    baseline_days: int,
    baseline_requests: float,
) -> None:
    fp = fingerprint(kind, row)
    # One stable issue per route/cohort, with all affected hours preserved.
    if fp in observations:
        observations[fp]["hours"].append(row["hour"])
        return
    observations[fp] = {
        "type": kind,
        "fingerprint": fp,
        "route_family": row["route"],
        "method": row["method"],
        "cohort": row["cohort"],
        "hours": [row["hour"]],
        "confidence": "heuristic",
        "severity": "medium",
        "basis": basis,
        "current": row,
        "baseline_days": baseline_days,
        "baseline_requests": baseline_requests,
        "remediation": REMEDIATION[kind],
        "disposition": "candidate",
    }


def assess(
    current: dict, history: list[dict], minimum_days: int, *, has_contract: bool
) -> list[dict]:
    if len(history) < minimum_days:
        return []
    observations: dict[str, dict] = {}
    for key, row in current.get("buckets", {}).items():
        prior = [day["buckets"][key] for day in history if key in day.get("buckets", {})]
        kinds = []
        if row["sensitive_locations"]:
            kinds.append("sensitive_request_metadata")
        if has_contract and row["route_mapping"] == "heuristic":
            kinds.append("shadow_route")
        baseline_requests = 0
        if len(prior) >= minimum_days:
            baseline_requests = median(p["requests"] for p in prior)
            baseline_ids = median(p["identifiers"] for p in prior)
            enum_floor = max(ENUM_IDENTIFIERS, ENUM_IDENTIFIER_RATIO * baseline_ids)
            surge = row["requests"] >= max(SURGE_REQUESTS, SURGE_RATIO * baseline_requests)
            if (
                surge
                and row["identifiers"] >= enum_floor
                and (row["sequentiality"] >= ENUM_SEQUENTIAL or row["not_found"] >= ENUM_NOT_FOUND)
            ):
                kinds.append("enumeration_anomaly")
            if surge and _is_account_route(row["route"]) and row["response_variants"] > 1:
                kinds.append("account_enumeration_lead")
            sizes = [p["median_bytes"] for p in prior if p["median_bytes"] is not None]
            if (
                len(sizes) >= minimum_days
                and row["median_bytes"] is not None
                and row["median_bytes"] > max(SIZE_FLOOR_BYTES, SIZE_RATIO * median(sizes))
            ):
                kinds.append("response_size_drift")
        for kind in kinds:
            _record(
                observations,
                kind,
                row,
                basis="baseline",
                baseline_days=len(history),
                baseline_requests=baseline_requests,
            )
    return list(observations.values())[:500]


def assess_day(current: dict, *, has_contract: bool) -> list[dict]:
    """Leads one day supports on its own, before a seven-day baseline exists.

    With nothing to compare against, thresholds are absolute and conservative,
    and each lead says ``basis: single_day``. Kinds and fingerprints match the
    baseline detectors, so triage carries over once the baseline is ready.
    """
    buckets = current.get("buckets", {})
    hour_totals: dict[int, int] = {}
    for row in buckets.values():
        hour_totals[row["hour"]] = hour_totals.get(row["hour"], 0) + row["requests"]
    observations: dict[str, dict] = {}
    for row in buckets.values():
        kinds = []
        if row["sensitive_locations"]:
            kinds.append("sensitive_request_metadata")
        if has_contract and row["route_mapping"] == "heuristic":
            kinds.append("shadow_route")
        if row["identifiers"] >= DAY_ENUM_IDENTIFIERS and (
            row["sequentiality"] >= ENUM_SEQUENTIAL or row["not_found"] >= DAY_ENUM_NOT_FOUND
        ):
            kinds.append("enumeration_anomaly")
        if (
            row["requests"] >= DAY_ACCOUNT_REQUESTS
            and _is_account_route(row["route"])
            and row["response_variants"] > 1
        ):
            kinds.append("account_enumeration_lead")
        hour_total = hour_totals.get(row["hour"], 0)
        if (
            row["cohort"] != "anonymous"
            and row["requests"] >= HIGH_VOLUME_REQUESTS
            and hour_total
            and row["requests"] / hour_total >= HIGH_VOLUME_SHARE
        ):
            kinds.append("high_volume_client")
        for kind in kinds:
            _record(
                observations, kind, row, basis="single_day", baseline_days=0, baseline_requests=0
            )
    return list(observations.values())[:500]
