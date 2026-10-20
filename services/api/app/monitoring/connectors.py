"""Bounded, offline JSON snapshot adapter. No network or raw-log persistence."""

from __future__ import annotations

import json
from datetime import date

from app.monitoring.contracts import RouteBinding
from app.monitoring.waf import NormalizedWafEvent, normalize_waf_event

MAX_SNAPSHOT_BYTES = 2 * 1024 * 1024
MAX_SNAPSHOT_ROWS = 10_000


def normalize_snapshot(
    payload: bytes, *, observation_date: date, salt: bytes, routes: list[RouteBinding] | None = None
) -> list[NormalizedWafEvent]:
    """Require a complete JSON array within one explicit UTC day.

    Reject the entire snapshot on invalid input; partial evidence must never
    look like a complete baseline day. Errors contain no source values.
    """
    if len(payload) > MAX_SNAPSHOT_BYTES:
        raise ValueError("snapshot exceeds byte limit")
    try:
        records = json.loads(payload)
    except (ValueError, UnicodeError, RecursionError):
        raise ValueError("snapshot must be a JSON array") from None
    if not isinstance(records, list) or len(records) > MAX_SNAPSHOT_ROWS:
        raise ValueError("snapshot must be an array of at most 10000 records")
    events: list[NormalizedWafEvent] = []
    seen: set[str] = set()
    for record in records:
        if not isinstance(record, dict):
            raise ValueError("snapshot contains an invalid record")
        try:
            event = normalize_waf_event(record, salt=salt, routes=routes)
        except (ValueError, TypeError, OverflowError, OSError):
            raise ValueError("snapshot contains an invalid record") from None
        if event.observed_at.date() != observation_date:
            raise ValueError("snapshot contains a record outside the selected UTC day")
        # A vendor request ID identifies a duplicate delivery. Without one,
        # identical metadata may describe distinct requests and must be kept.
        if event.request_id_hash:
            if event.request_id_hash in seen:
                continue
            seen.add(event.request_id_hash)
        events.append(event)
    return events
