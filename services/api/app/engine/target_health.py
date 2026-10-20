"""Read a run's own request trace for signs the run never reached the API.

A scan whose every request answered 404 finishes like any other: the checks
complete, a few header findings appear, and nothing says the endpoints were
never there. The same goes for an identity whose key the target rejects —
every authorization check runs and finds nothing, which reads as "clean".
Those runs are misconfigurations, not results, and the person running them
needs to hear that before they trust the report.

This costs no requests: it reads the rows ``HttpProbe`` already recorded. Pure
— no SQLAlchemy, no ``app.models`` — so both lanes run it.
"""
from __future__ import annotations

from collections import Counter
from collections.abc import Iterable, Mapping
from typing import Any
from urllib.parse import urljoin, urlsplit

#: Fewer rows than this say nothing about a whole target.
MIN_ROWS = 3
#: The share of a target's answers that must agree before the run is called off.
#: Not 100%: a catch-all route or one static file should not hide a broken run.
DOMINANT_SHARE = 0.9

_UNATTRIBUTED = "(unattributed)"


def _status(row: Mapping[str, Any]) -> int | None:
    response = row.get("response")
    status = response.get("status") if isinstance(response, Mapping) else None
    return status if isinstance(status, int) else None


def _spec_rows(rows: Iterable[Mapping[str, Any]]) -> list[Mapping[str, Any]]:
    """Main-pass requests to a spec route. Probes of paths the spec never named
    (``/.git``, discovery) answer 404 on a healthy API and must not count."""
    return [
        row
        for row in rows
        if row.get("pass", "engine") == "engine" and row.get("route") not in (None, _UNATTRIBUTED)
    ]


def _url(base_url: str, route: str) -> str:
    """The URL a route is sent to — the same join ``AsyncHttpClientBridge`` does."""
    return urljoin(base_url.rstrip("/") + "/", route.lstrip("/"))


def _doubled_prefix(base_url: str, route: str) -> str | None:
    """``"/api/v1"`` when the target ends with the segments the route starts with."""
    base = [part for part in urlsplit(base_url).path.split("/") if part]
    head = [part for part in route.split("/") if part]
    for size in range(len(base), 0, -1):
        if base[-size:] == head[:size]:
            return "/" + "/".join(base[-size:])
    return None


def _origin(base_url: str) -> str:
    parts = urlsplit(base_url)
    return f"{parts.scheme}://{parts.netloc}"


def _routes_not_found(base_url: str, rows: list[Mapping[str, Any]]) -> str | None:
    # A collection route (no path parameter) has no id to get wrong, so its 404
    # means the route itself is missing. Item routes 404 for a placeholder id on
    # a healthy API; they count only when the spec has nothing else.
    collection = [row for row in rows if "{" not in str(row.get("route"))]
    sample = collection if len(collection) >= MIN_ROWS else rows
    answered = [row for row in sample if _status(row) is not None]
    if len(answered) < MIN_ROWS:
        return None
    missing = [row for row in answered if _status(row) == 404]
    if len(missing) / len(answered) < DOMINANT_SHARE:
        return None
    example = missing[0]
    route = str(example.get("route"))
    if all(row.get("identity") == "anonymous" for row in missing):
        # Some APIs answer 404, not 401, to a caller without a key, so a
        # resource's existence does not leak. Without a key the run cannot tell
        # that from a missing route; it says both and names the cheaper fix.
        return (
            f"{len(missing)} of {len(answered)} requests to the spec's endpoints answered 404, "
            f"all of them without credentials: {example.get('method', 'GET')} {route} was sent "
            f"to {_url(base_url, route)} — either the routes are wrong, or the API hides them "
            "from callers without a key; add an identity to tell which"
        )
    message = (
        f"{len(missing)} of {len(answered)} requests to the spec's endpoints answered 404, "
        f"so this run never reached the API: {example.get('method', 'GET')} {route} "
        f"was sent to {_url(base_url, route)}"
    )
    doubled = _doubled_prefix(base_url, route)
    if doubled:
        return (
            f"{message} — the target already ends with {doubled} and the route repeats it; "
            f"set target: to {_origin(base_url)}"
        )
    return (
        f"{message} — check that target: is the API's base URL (the part the spec's "
        "paths are appended to) and that the spec matches the deployed API"
    )


def _unreachable(rows: list[Mapping[str, Any]]) -> str | None:
    if len(rows) < MIN_ROWS or any(_status(row) is not None for row in rows):
        return None
    errors = Counter(str(row.get("error") or "no response") for row in rows)
    kind, _count = errors.most_common(1)[0]
    return (
        f"none of the {len(rows)} requests got an answer ({kind}) — the target is down or "
        "unreachable from where the scan runs; for a local run on a Docker network, pass "
        "--docker-network so the runner can resolve it"
    )


def _failing(rows: list[Mapping[str, Any]]) -> str | None:
    answered = [row for row in rows if _status(row) is not None]
    if len(answered) < MIN_ROWS:
        return None
    errors = [row for row in answered if (_status(row) or 0) >= 500]
    if len(errors) / len(answered) < DOMINANT_SHARE:
        return None
    return (
        f"{len(errors)} of {len(answered)} requests answered 5xx — the target is failing, so "
        "the checks saw its error pages rather than the API"
    )


def _rejected_identities(rows: list[Mapping[str, Any]], identities: Iterable[str]) -> list[str]:
    notes = []
    for name in identities:
        sent = [row for row in rows if row.get("identity") == name and _status(row) is not None]
        if len(sent) < MIN_ROWS or any(_status(row) != 401 for row in sent):
            continue
        notes.append(
            f"identity '{name}' was rejected: all {len(sent)} requests it sent answered 401, so "
            "every check that uses it saw a login error — its secret is wrong or expired, or "
            "it goes in a different header (set header: on the identity)"
        )
    return notes


#: The run never reached the API: its findings describe an error page or a
#: closed port, not the API. A client reads the stage, never the wording.
UNREACHED = "target_unreached"
#: The run reached the API, but part of it saw only errors.
DEGRADED = "target_health"


def diagnose(
    base_url: str, rows: Iterable[Mapping[str, Any]], identities: Iterable[str]
) -> list[tuple[str, str]]:
    """``(stage, message)`` for what the trace says went wrong with the run itself,
    worst first; ``[]`` when nothing did. Each message names the evidence and the fix."""
    spec = _spec_rows(rows)
    unreachable = _unreachable(spec)
    if unreachable:
        return [(UNREACHED, unreachable)]
    failing = _failing(spec)
    if failing:
        return [(DEGRADED, failing)]
    missing = _routes_not_found(base_url, spec)
    if missing:
        # Whose key was refused cannot be told from a route that is not there.
        return [(UNREACHED, missing)]
    return [(DEGRADED, note) for note in _rejected_identities(spec, identities)]
