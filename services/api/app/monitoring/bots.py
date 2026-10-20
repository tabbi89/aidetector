"""Pure AI and bot traffic aggregates, and the leads they support.

Everything here reads AWS WAF Bot Control labels — a bot's published name,
organization, AWS category and verification — never a value the client chose.
Counts are evidence, not identity: a fingerprint names the kind, the route and
the bot, so a continuing issue keeps one identity however its volume moves.

All observations are ``heuristic``. A label says what AWS believes the client
is; it does not show that a request reached data it should not have.
"""

from __future__ import annotations

import hashlib
from collections import Counter
from collections.abc import Iterable, Mapping
from datetime import date
from statistics import median
from typing import Any

from app.monitoring.waf import NormalizedWafEvent

VERSION = 1
MAX_CRAWLERS = 200
MAX_CRAWLER_ROUTES = 10
AI_CATEGORY = "ai"
UNCATEGORIZED = "uncategorized"
#: Unverified requests under a name verified elsewhere before it reads as impersonation.
SPOOF_REQUESTS = 5
#: Allowed unverified bot requests on one authenticated operation.
PROTECTED_ALLOWED = 5
#: Unverified AI requests in a day: at least this many, and this factor of the median.
AI_SURGE_REQUESTS = 50
AI_SURGE_RATIO = 4

REMEDIATION = {
    "unverified_ai_surge": (
        "Review which unverified AI crawlers drove the increase. Allow or rate-limit the "
        "ones you accept with Bot Control label rules, and challenge or block the rest."
    ),
    "bot_identity_spoof": (
        "Traffic claims a crawler name that Bot Control verified elsewhere. Treat the "
        "unverified requests as an impersonation lead: rate-limit or block the name "
        "unless it carries the bot:verified label."
    ),
    "bot_on_protected_route": (
        "A labelled bot was allowed through the WAF to an operation the API contract "
        "marks as authenticated. Confirm the origin rejects it, and consider a WAF rule "
        "that blocks bot traffic on authenticated paths."
    ),
}


def is_bot(event: NormalizedWafEvent) -> bool:
    return bool(event.bot_category or event.bot_name or event.bot_verification)


def _outcome(event: NormalizedWafEvent) -> str:
    if event.action == "BLOCK":
        return "blocked"
    if event.action in {"CAPTCHA", "CHALLENGE"}:
        return "challenged"
    if event.action == "ALLOW" or (
        event.status_code is not None and 200 <= event.status_code < 300
    ):
        return "allowed"
    return "other"


def _ranked(counts: Counter[str], limit: int) -> list[tuple[str, int]]:
    """Most common first, ties by name, so the result never depends on arrival order."""
    return sorted(counts.items(), key=lambda item: (-item[1], item[0]))[:limit]


class BotAccumulator:
    """Folds one day's events into bot aggregates without keeping the events."""

    def __init__(self) -> None:
        self.requests = 0
        self.bot_requests = 0
        self.ai_requests = 0
        self.verified_ai = 0
        self.by_category: Counter[str] = Counter()
        self.by_hour: dict[int, Counter[str]] = {}
        self.crawlers: dict[tuple[str, str, str, str], dict[str, Counter[str]]] = {}

    def add(self, event: NormalizedWafEvent) -> None:
        self.requests += 1
        if not is_bot(event):
            return
        self.bot_requests += 1
        category = event.bot_category or UNCATEGORIZED
        verification = event.bot_verification or "unknown"
        self.by_category[category] += 1
        self.by_hour.setdefault(event.observed_at.hour, Counter())[category] += 1
        if category == AI_CATEGORY:
            self.ai_requests += 1
            self.verified_ai += verification == "verified"
        key = (event.bot_name or "", event.bot_organization or "", category, verification)
        row = self.crawlers.get(key)
        if row is None:
            row = self.crawlers[key] = {
                "outcomes": Counter(),
                "routes": Counter(),
                "allowed_routes": Counter(),
            }
        outcome = _outcome(event)
        route = f"{event.method} {event.route_family}"
        row["outcomes"][outcome] += 1
        row["routes"][route] += 1
        if outcome == "allowed":
            row["allowed_routes"][route] += 1

    def result(self) -> dict:
        table: list[dict[str, Any]] = [
            {
                "name": name,
                "organization": organization,
                "category": category,
                "verification": verification,
                "requests": sum(row["outcomes"].values()),
                "allowed": row["outcomes"]["allowed"],
                "blocked": row["outcomes"]["blocked"],
                "challenged": row["outcomes"]["challenged"],
                "routes": [
                    {"route": route, "requests": count, "allowed": row["allowed_routes"][route]}
                    for route, count in _ranked(row["routes"], MAX_CRAWLER_ROUTES)
                ],
            }
            for (name, organization, category, verification), row in self.crawlers.items()
        ]
        table.sort(
            key=lambda row: (
                -row["requests"],
                row["name"],
                row["organization"],
                row["category"],
                row["verification"],
            )
        )
        return {
            "version": VERSION,
            "requests": self.requests,
            "bot_requests": self.bot_requests,
            "ai_requests": self.ai_requests,
            "verified_ai": self.verified_ai,
            "unverified_ai": self.ai_requests - self.verified_ai,
            "by_category": dict(_ranked(self.by_category, len(self.by_category))),
            "by_hour_category": {
                str(hour): dict(sorted(counts.items()))
                for hour, counts in sorted(self.by_hour.items())
            },
            "crawlers": table[:MAX_CRAWLERS],
            "crawlers_truncated": max(0, len(table) - MAX_CRAWLERS),
        }


def aggregate(events: Iterable[NormalizedWafEvent]) -> dict:
    """One day's bot traffic: totals, category mix and the crawler table."""
    accumulator = BotAccumulator()
    for event in events:
        accumulator.add(event)
    return accumulator.result()


def protected_routes(context: Mapping[str, object]) -> set[str]:
    """``METHOD path`` of contract operations that declare a security requirement."""
    routes = context.get("routes")
    advisories = context.get("advisories")
    declared = {
        f"{str(r['method']).upper()} {r['path']}"
        for r in (routes if isinstance(routes, list) else [])
        if isinstance(r, Mapping) and "method" in r and "path" in r
    }
    public = {
        f"{str(a['method']).upper()} {a['path']}"
        for a in (advisories if isinstance(advisories, list) else [])
        if isinstance(a, Mapping)
        and a.get("type") == "declared_public_operation"
        and "method" in a
        and "path" in a
    }
    return declared - public


def fingerprint(kind: str, route: str, bot: str) -> str:
    return hashlib.sha256("|".join(["bots", kind, route, bot]).encode()).hexdigest()


def _observation(kind: str, route: str, bot: str, severity: str, current: dict, **extra) -> dict:
    method, _, path = route.partition(" ")
    return {
        "type": kind,
        "fingerprint": fingerprint(kind, route, bot),
        "route_family": path or "*",
        "method": method or "*",
        "cohort": f"bot:{bot}" if bot else "bots",
        "hours": [],
        "confidence": "heuristic",
        "severity": severity,
        "current": current,
        "remediation": REMEDIATION[kind],
        "disposition": "candidate",
        **extra,
    }


def _crawler_rows(current: Mapping[str, object]) -> list[dict]:
    crawlers = current.get("crawlers")
    return [row for row in crawlers if isinstance(row, dict)] if isinstance(crawlers, list) else []


def _crawler_leads(
    rows: list[dict],
    verified_names: set[str],
    *,
    protected: set[str],
    basis: str,
    baseline_days: int,
) -> list[dict]:
    observations: list[dict] = []
    for row in rows:
        name = str(row.get("name") or "")
        if name and row.get("verification") == "unverified" and name in verified_names:
            if int(row.get("requests", 0)) >= SPOOF_REQUESTS:
                observations.append(
                    _observation(
                        "bot_identity_spoof",
                        "* *",
                        name,
                        "medium",
                        {"requests": row.get("requests"), "organization": row.get("organization")},
                        basis=basis,
                        baseline_days=baseline_days,
                    )
                )
        if row.get("verification") == "verified":
            continue
        for route in row.get("routes") or []:
            if (
                isinstance(route, dict)
                and route.get("route") in protected
                and int(route.get("allowed", 0)) >= PROTECTED_ALLOWED
            ):
                observations.append(
                    _observation(
                        "bot_on_protected_route",
                        str(route["route"]),
                        name or str(row.get("category") or UNCATEGORIZED),
                        "low",
                        {
                            "allowed": route.get("allowed"),
                            "category": row.get("category"),
                            "verification": row.get("verification"),
                        },
                        basis=basis,
                        baseline_days=baseline_days,
                    )
                )
    return observations


def _unique(observations: list[dict]) -> list[dict]:
    return list({observation["fingerprint"]: observation for observation in observations}.values())[
        :100
    ]


def assess(
    current: Mapping[str, object] | None,
    history: list[Mapping[str, object]],
    minimum_days: int,
    *,
    protected: set[str],
) -> list[dict]:
    """Bot leads for one day against the prior comparable days."""
    if not current or len(history) < minimum_days:
        return []
    prior = [day for day in history if day]
    observations: list[dict] = []

    unverified = int(current.get("unverified_ai", 0) or 0)  # type: ignore[call-overload]
    baseline = median(int(day.get("unverified_ai", 0) or 0) for day in prior) if prior else 0  # type: ignore[call-overload]
    if unverified >= max(AI_SURGE_REQUESTS, AI_SURGE_RATIO * baseline):
        observations.append(
            _observation(
                "unverified_ai_surge",
                "* *",
                "",
                "medium",
                {"unverified_ai": unverified, "ai_requests": current.get("ai_requests")},
                basis="baseline",
                baseline_days=len(history),
                baseline_requests=baseline,
            )
        )
    verified_before: set[str] = set()
    for day in prior:
        for row in _crawler_rows(day):
            if row.get("name") and row.get("verification") == "verified":
                verified_before.add(str(row["name"]))
    observations += _crawler_leads(
        _crawler_rows(current),
        verified_before,
        protected=protected,
        basis="baseline",
        baseline_days=len(history),
    )
    return _unique(observations)


def assess_day(current: Mapping[str, object] | None, *, protected: set[str]) -> list[dict]:
    """Crawler leads one day supports on its own, before a baseline exists.

    A name Bot Control verified today but that also arrived unverified today is
    an impersonation lead without needing history.
    """
    if not current:
        return []
    rows = _crawler_rows(current)
    verified_today = {
        str(row["name"])
        for row in rows
        if row.get("name") and row.get("verification") == "verified"
    }
    return _unique(
        _crawler_leads(
            rows, verified_today, protected=protected, basis="single_day", baseline_days=0
        )
    )


def summarize(
    days: list[tuple[date, Mapping[str, object]]], *, limit: int = 50, routes: int = 0
) -> dict:
    """Combine daily aggregates into the analysis view for a window of days.

    ``routes`` adds each crawler's busiest routes over the window, merged from the
    daily per-crawler route lists (each already capped at ``MAX_CRAWLER_ROUTES``).
    """
    totals = Counter[str]()
    by_category: Counter[str] = Counter()
    crawlers: dict[tuple[str, str, str, str], Counter[str]] = {}
    crawler_routes: dict[tuple[str, str, str, str], dict[str, Counter[str]]] = {}
    series = []
    for day, bots in sorted(days, key=lambda item: item[0]):
        for field in ("requests", "bot_requests", "ai_requests", "verified_ai", "unverified_ai"):
            totals[field] += int(bots.get(field, 0) or 0)  # type: ignore[call-overload]
        categories = bots.get("by_category")
        daily = dict(categories) if isinstance(categories, Mapping) else {}
        by_category.update({str(k): int(v) for k, v in daily.items()})
        series.append({"day": day.isoformat(), "by_category": daily})
        for row in _crawler_rows(bots):
            key = (
                str(row.get("name") or ""),
                str(row.get("organization") or ""),
                str(row.get("category") or UNCATEGORIZED),
                str(row.get("verification") or "unknown"),
            )
            merged = crawlers.setdefault(key, Counter())
            for field in ("requests", "allowed", "blocked", "challenged"):
                merged[field] += int(row.get(field, 0) or 0)
            if routes:
                by_route = crawler_routes.setdefault(
                    key, {"requests": Counter(), "allowed": Counter()}
                )
                for route in row.get("routes") or []:
                    if isinstance(route, Mapping) and route.get("route"):
                        name = str(route["route"])
                        by_route["requests"][name] += int(route.get("requests") or 0)
                        by_route["allowed"][name] += int(route.get("allowed") or 0)
    ai = totals["ai_requests"]
    table: list[dict[str, Any]] = [
        {
            "name": name,
            "organization": organization,
            "category": category,
            "verification": verification,
            **{f: counts[f] for f in ("requests", "allowed", "blocked", "challenged")},
            **({"routes": [
                {
                    "route": route,
                    "requests": count,
                    "allowed": crawler_routes[key]["allowed"][route],
                }
                for route, count in _ranked(crawler_routes[key]["requests"], routes)
            ]} if routes and key in crawler_routes else {}),
        }
        for key, counts in crawlers.items()
        for (name, organization, category, verification) in [key]
    ]
    table.sort(key=lambda row: (-row["requests"], row["name"]))
    return {
        "days": len(series),
        "requests": totals["requests"],
        "bot_requests": totals["bot_requests"],
        "ai_requests": ai,
        "verified_ai": totals["verified_ai"],
        "unverified_ai": totals["unverified_ai"],
        "verified_ai_pct": round(100 * totals["verified_ai"] / ai, 1) if ai else None,
        "unverified_ai_pct": round(100 * totals["unverified_ai"] / ai, 1) if ai else None,
        "by_category": dict(by_category.most_common()),
        "crawlers": table[:limit],
        "crawler_count": len(table),
        "series": series,
    }
