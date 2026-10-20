"""Per-TLS-client (JA4) breadth, and the leads one fingerprint supports on its own.

A JA4 fingerprint describes the TLS ClientHello a client's software sends, so it
follows one tool across the addresses it rotates through, which per-IP buckets
cannot. It is not a person: every user of one browser build shares it. So leads
rest on breadth *per request and per address*. A person revisits the same pages
and objects; a scanner or an enumerator mostly asks for something new.

Two kinds of traffic never count toward a lead: requests the operator's own
allow rules let through (an allowlisted webhook sender) and Bot Control
verified bots (a search engine is supposed to crawl widely). Both are still
counted, so the table shows them.

AWS WAF logs carry no origin status code, so nothing here reads one. Every
observation is ``heuristic``: breadth shows intent to explore, not that a
request reached data it should not have.
"""

from __future__ import annotations

import hashlib
from collections import Counter
from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import Any

from app.monitoring.waf import NormalizedWafEvent, short_key

VERSION = 1
MAX_CLIENTS = 200
MAX_ROUTES = 500
#: Distinct sets stop growing here; a count at the cap reads as "at least".
MAX_DISTINCT = 20_000

#: Endpoint probing: many distinct paths, mostly asked for once, per address.
PROBE_PATHS = 100
PROBE_RATIO = 0.3
#: Identifier enumeration on one route: many ids, consecutive, per address.
ENUM_IDS = 50
ENUM_SEQUENTIAL = 0.5
#: Both breadth leads need this much per source address, so a browser build
#: shared by many users does not add up to one "client".
PER_ADDRESS = 25
#: Request manipulation: payload-rule matches from one fingerprint.
ATTACK_MATCHES = 3
#: Distinct payload-matched paths kept per fingerprint, and shown on the observation.
MAX_ATTACK_PATHS = 200
SHOWN_ATTACK_PATHS = 5

REMEDIATION = {
    "ja4_endpoint_probing": (
        "One TLS client fingerprint requested many distinct paths, most of them once. "
        "Check the paths it reached in the WAF logs; unless it is a known crawler or "
        "integration, rate-limit or block the JA4 fingerprint with a WAF rule instead of "
        "chasing its addresses."
    ),
    "ja4_identifier_enumeration": (
        "One TLS client fingerprint walked consecutive identifiers on this route. Review the "
        "handler's ownership check for the named parameter, rate-limit the fingerprint, and "
        "confirm with an authorized active BOLA test."
    ),
    "ja4_request_manipulation": (
        "Requests from one TLS client fingerprint matched AWS managed rules for injection, "
        "traversal or exploit payloads. Where a matching rule only counts, the payload "
        "reached the origin: switch it to block and review that route's input handling."
    ),
}


def _add(values: set[int], key: str) -> None:
    if len(values) < MAX_DISTINCT:
        values.add(short_key(key))


@dataclass(slots=True)
class _Identifiers:
    ids: set[int] = field(default_factory=set)
    successors: set[int] = field(default_factory=set)
    names: Counter[str] = field(default_factory=Counter)

    def summary(self, route: str) -> dict:
        return {
            "route": route,
            "distinct": len(self.ids),
            "sequentiality": round(
                len(self.ids & self.successors) / max(1, len(self.ids) - 1), 3
            ),
            "parameters": [name for name, _ in _ranked(self.names, 4)],
        }


@dataclass(slots=True)
class _ClientTally:
    requests: int = 0
    trusted: int = 0
    verified_bot: int = 0
    blocked: int = 0
    challenged: int = 0
    eligible: int = 0
    addresses: set[int] = field(default_factory=set)
    paths: set[int] = field(default_factory=set)
    hours: set[int] = field(default_factory=set)
    routes: Counter[str] = field(default_factory=Counter)
    identifiers: dict[str, _Identifiers] = field(default_factory=dict)
    attacks: Counter[str] = field(default_factory=Counter)
    attack_requests: int = 0
    attack_allowed: int = 0
    attack_routes: Counter[str] = field(default_factory=Counter)
    attack_paths: Counter[str] = field(default_factory=Counter)
    bots: Counter[str] = field(default_factory=Counter)


def _ranked(counts: Counter[str], limit: int) -> list[tuple[str, int]]:
    """Most common first, ties by name, so the result never depends on arrival order."""
    return sorted(counts.items(), key=lambda item: (-item[1], item[0]))[:limit]


class ClientAccumulator:
    """Folds one day's events into per-JA4 tallies without keeping the events."""

    def __init__(self) -> None:
        self._clients: dict[str, _ClientTally] = {}
        self.without_fingerprint = 0

    def add(self, event: NormalizedWafEvent) -> None:
        if event.ja4 is None:
            self.without_fingerprint += 1
            return
        tally = self._clients.get(event.ja4)
        if tally is None:
            tally = self._clients[event.ja4] = _ClientTally()
        tally.requests += 1
        tally.blocked += event.action == "BLOCK"
        tally.challenged += event.action in {"CAPTCHA", "CHALLENGE"}
        if event.bot_name:
            tally.bots[event.bot_name] += 1
        route = f"{event.method} {event.route_family}"
        if event.attack_labels:
            # Payload matches count whoever sent them: an allowlisted sender is not
            # supposed to carry SQL injection either.
            tally.attack_requests += 1
            tally.attack_allowed += event.action == "ALLOW"
            tally.attacks.update(event.attack_labels)
            if len(tally.attack_routes) < MAX_ROUTES or route in tally.attack_routes:
                tally.attack_routes[route] += 1
            # The one path kept verbatim: the normalizer hands it over only because a
            # managed attack rule matched, so it is the attacker's string, not a client's.
            path = event.attack_path
            if path and (len(tally.attack_paths) < MAX_ATTACK_PATHS or path in tally.attack_paths):
                tally.attack_paths[path] += 1
        if event.allow_rule:
            tally.trusted += 1
            return
        if event.bot_verification == "verified":
            tally.verified_bot += 1
            return
        tally.eligible += 1
        tally.hours.add(event.observed_at.hour)
        if event.source_ip_hash:
            _add(tally.addresses, event.source_ip_hash)
        if event.path_shape_hash:
            _add(tally.paths, event.path_shape_hash)
        if len(tally.routes) < MAX_ROUTES or route in tally.routes:
            tally.routes[route] += 1
        if event.identifier_hashes:
            ids = tally.identifiers.get(route)
            if ids is None:
                if len(tally.identifiers) >= MAX_ROUTES:
                    return
                ids = tally.identifiers[route] = _Identifiers()
            for value in event.identifier_hashes:
                _add(ids.ids, value)
            for value in event.successor_hashes:
                _add(ids.successors, value)
            ids.names.update(event.identifier_keys)

    def result(self) -> dict:
        rows = [_row(ja4, tally) for ja4, tally in self._clients.items()]
        flagged = [row for row in rows if flags(row)]
        rest = sorted(
            (row for row in rows if not flags(row)), key=lambda row: (-row["requests"], row["ja4"])
        )
        kept = sorted(flagged, key=lambda row: (-row["requests"], row["ja4"]))[:MAX_CLIENTS]
        kept += rest[: MAX_CLIENTS - len(kept)]
        kept.sort(key=lambda row: (-row["requests"], row["ja4"]))
        return {
            "version": VERSION,
            "clients": kept,
            "clients_total": len(rows),
            "clients_truncated": len(rows) - len(kept),
            "without_fingerprint": self.without_fingerprint,
        }


def _row(ja4: str, tally: _ClientTally) -> dict[str, Any]:
    identifiers = [ids.summary(route) for route, ids in tally.identifiers.items()]
    # The route whose identifiers look most like a walk, then the widest.
    identifiers.sort(
        key=lambda row: (
            -(row["distinct"] >= ENUM_IDS and row["sequentiality"] >= ENUM_SEQUENTIAL),
            -row["distinct"],
            row["route"],
        )
    )
    return {
        "ja4": ja4,
        "requests": tally.requests,
        "eligible": tally.eligible,
        "trusted": tally.trusted,
        "verified_bot": tally.verified_bot,
        "blocked": tally.blocked,
        "challenged": tally.challenged,
        "addresses": len(tally.addresses),
        "paths": len(tally.paths),
        "routes": len(tally.routes),
        "hours": len(tally.hours),
        "top_routes": [
            {"route": route, "requests": count} for route, count in _ranked(tally.routes, 5)
        ],
        "identifiers": identifiers[0] if identifiers else None,
        "attack_requests": tally.attack_requests,
        "attack_allowed": tally.attack_allowed,
        "attack_labels": dict(_ranked(tally.attacks, 8)),
        "attack_route": _ranked(tally.attack_routes, 1)[0][0] if tally.attack_routes else None,
        "attack_paths": [
            {"path": path, "requests": count}
            for path, count in _ranked(tally.attack_paths, SHOWN_ATTACK_PATHS)
        ],
        "attack_paths_total": len(tally.attack_paths),
        "bot": _ranked(tally.bots, 1)[0][0] if tally.bots else None,
    }


def _per_address(count: int, row: Mapping[str, Any]) -> float:
    return count / max(1, int(row.get("addresses") or 0))


def flags(row: Mapping[str, Any]) -> list[str]:
    """The lead kinds one stored client row meets."""
    found = []
    eligible = int(row.get("eligible") or 0)
    paths = int(row.get("paths") or 0)
    if (
        paths >= PROBE_PATHS
        and paths / max(1, eligible) >= PROBE_RATIO
        and _per_address(paths, row) >= PER_ADDRESS
    ):
        found.append("ja4_endpoint_probing")
    ids = row.get("identifiers")
    if (
        isinstance(ids, Mapping)
        and int(ids.get("distinct") or 0) >= ENUM_IDS
        and float(ids.get("sequentiality") or 0) >= ENUM_SEQUENTIAL
        and _per_address(int(ids.get("distinct") or 0), row) >= PER_ADDRESS
    ):
        found.append("ja4_identifier_enumeration")
    if int(row.get("attack_requests") or 0) >= ATTACK_MATCHES:
        found.append("ja4_request_manipulation")
    return found


def fingerprint(kind: str, ja4: str, route: str) -> str:
    return hashlib.sha256("|".join(["clients", kind, ja4, route]).encode()).hexdigest()


def assess_day(current: Mapping[str, object] | None) -> list[dict]:
    """JA4 leads from one day's rows; absolute thresholds, so no baseline is needed."""
    rows = current.get("clients") if isinstance(current, Mapping) else None
    observations: list[dict] = []
    for row in rows if isinstance(rows, list) else []:
        if not isinstance(row, Mapping) or not isinstance(row.get("ja4"), str):
            continue
        ja4 = str(row["ja4"])
        for kind in flags(row):
            evidence: dict[str, Any] = {
                key: row.get(key)
                for key in ("ja4", "requests", "eligible", "addresses", "paths", "routes", "hours")
            }
            route, severity = "* *", "medium"
            if kind == "ja4_endpoint_probing":
                evidence["top_routes"] = row.get("top_routes")
                evidence["blocked"] = row.get("blocked")
            elif kind == "ja4_identifier_enumeration":
                ids = row["identifiers"]
                route = str(ids["route"])
                evidence["identifiers"] = ids
            else:
                route = str(row.get("attack_route") or "* *")
                evidence["attack_labels"] = row.get("attack_labels")
                evidence["attack_requests"] = row.get("attack_requests")
                evidence["attack_allowed"] = row.get("attack_allowed")
                evidence["attack_paths"] = row.get("attack_paths")
                evidence["attack_paths_total"] = row.get("attack_paths_total")
                # Blocked at the edge is an attempt; allowed means it reached the origin.
                severity = "medium" if int(row.get("attack_allowed") or 0) else "low"
            method, _, path = route.partition(" ")
            observations.append(
                {
                    "type": kind,
                    "fingerprint": fingerprint(kind, ja4, route),
                    "route_family": path or "*",
                    "method": method or "*",
                    "cohort": f"ja4:{ja4}",
                    "hours": [],
                    "confidence": "heuristic",
                    "severity": severity,
                    "basis": "single_day",
                    "current": evidence,
                    "baseline_days": 0,
                    "baseline_requests": 0,
                    "remediation": REMEDIATION[kind],
                    "disposition": "candidate",
                }
            )
    return observations[:100]


def with_flags(current: Mapping[str, object] | None, *, limit: int) -> list[dict]:
    """Stored rows for the API, flagged ones first, each with the leads it meets."""
    rows = current.get("clients") if isinstance(current, Mapping) else None
    table = [
        {**row, "flags": flags(row)}
        for row in (rows if isinstance(rows, list) else [])
        if isinstance(row, Mapping) and isinstance(row.get("ja4"), str)
    ]
    table.sort(key=lambda row: (-len(row["flags"]), -int(row.get("requests") or 0), row["ja4"]))
    return table[:limit]
