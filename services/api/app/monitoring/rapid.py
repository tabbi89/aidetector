"""Short-window, value-free passive detections over complete telemetry windows.

The caller supplies the entire previous hour on each run. Nothing here initiates
target traffic or retains a raw request, account name, object ID, or IP address.
"""

from __future__ import annotations

import hashlib
import hmac
import ipaddress
from collections import defaultdict
from collections.abc import Sequence
from datetime import datetime, timedelta
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator

from app.monitoring.waf import NormalizedWafEvent

HexDigest = str


class ApplicationSignal(BaseModel):
    """Outcome logged by the protected application, after its decision completes."""

    model_config = ConfigDict(extra="forbid")
    event: Literal["auth_failed", "auth_succeeded", "authz_denied", "foreign_object_access"]
    occurred_at: datetime
    request_id: str = Field(min_length=1, max_length=120)
    client_ip: str
    route: str = Field(min_length=1, max_length=300, pattern=r"^/[A-Za-z0-9_{}./-]*$")
    principal_hash: HexDigest | None = None
    account_hash: HexDigest | None = None
    resource_id_hash: HexDigest | None = None
    owner_hash: HexDigest | None = None
    reason: Literal["owner_mismatch", "invalid_credentials", "other"] | None = None
    response_status: int = Field(ge=100, le=599)

    @field_validator("client_ip")
    @classmethod
    def valid_ip(cls, value: str) -> str:
        return str(ipaddress.ip_address(value))

    @field_validator("occurred_at")
    @classmethod
    def aware_time(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("occurred_at must include a timezone")
        return value

    @field_validator("principal_hash", "account_hash", "resource_id_hash", "owner_hash")
    @classmethod
    def valid_digest(cls, value: str | None) -> str | None:
        if value is not None and (
            len(value) != 64 or any(char not in "0123456789abcdef" for char in value)
        ):
            raise ValueError("expected a lowercase 64-character keyed digest")
        return value


def _identity(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()


def _observation(
    kind: str, subject: str, route: str, *, severity: str = "medium",
    confidence: str = "heuristic", **counts: object,
) -> dict:
    return {
        "type": kind,
        "fingerprint": _identity("rapid|" + "|".join((kind, subject, route))),
        "route_family": route,
        "severity": severity,
        "confidence": confidence,
        "basis": "complete_rolling_window",
        "current": counts,
        "disposition": "candidate",
    }


def _eligible(event: NormalizedWafEvent) -> bool:
    return not event.allow_rule and event.bot_verification != "verified"


def _recent(at: datetime, end: datetime, minutes: int) -> bool:
    return end - timedelta(minutes=minutes) <= at <= end


def _ip_digest(ip: str, salt: bytes) -> str:
    return hmac.new(salt, ip.encode(), hashlib.sha256).hexdigest()


def assess_waf(
    events: Sequence[NormalizedWafEvent], *, end: datetime,
    explicit_contract: bool, known_routes: frozenset[str] | None = None,
) -> list[dict]:
    """Detect contract-backed discovery, payload matches and quiet broad crawling.

    Slow reconnaissance counts only *unknown* routes: outside the uploaded contract
    when there is one, otherwise outside the route families the daily baseline has
    already seen. With neither (``known_routes is None``) it does not run -- breadth
    over ordinary routes is a user clicking around, not a crawl.
    """

    def unknown(event: NormalizedWafEvent) -> bool:
        if explicit_contract:
            return event.route_mapping != "declared"
        return known_routes is not None and event.route_family not in known_routes

    discovery: dict[str, list[NormalizedWafEvent]] = defaultdict(list)
    injection: dict[tuple[str, str], list[NormalizedWafEvent]] = defaultdict(list)
    slow_ip: dict[str, list[NormalizedWafEvent]] = defaultdict(list)
    slow_ja4: dict[str, list[NormalizedWafEvent]] = defaultdict(list)
    for event in events:
        ip = event.source_ip_hash
        if ip and event.attack_labels and _recent(event.observed_at, end, 5):
            injection[(ip, event.route_family)].append(event)
        if not ip or not _eligible(event):
            continue
        if _recent(event.observed_at, end, 60):
            if not unknown(event):
                continue
            if explicit_contract:
                discovery[ip].append(event)
            slow_ip[ip].append(event)
            if event.ja4:
                slow_ja4[event.ja4].append(event)

    observations: list[dict] = []
    # Only a user-supplied contract can say a path is unknown; a HAR/Postman
    # derived one lists what was seen, not what exists.
    if explicit_contract:
        for ip, rows in discovery.items():
            recent = [r for r in rows if _recent(r.observed_at, end, 5)]
            short = {r.path_shape_hash for r in recent if r.path_shape_hash}
            hour = {r.path_shape_hash for r in rows if r.path_shape_hash}
            if len(short) < 3 and len(hour) < 10:
                continue
            # WAF ALLOW carries no origin status; only a logged 404 or a payload
            # label corroborates that the paths were guesses.
            corroborated = any(r.status_code == 404 or r.attack_labels for r in rows)
            observations.append(_observation(
                "path_discovery", ip, "*", severity="high" if corroborated else "medium",
                hits=len(rows), unknown_shapes_5m=len(short), unknown_shapes_60m=len(hour),
                not_found=sum(r.status_code == 404 for r in rows),
            ))
    for (ip, route), rows in injection.items():
        if len(rows) >= 3:
            labels = sorted({label for row in rows for label in row.attack_labels})[:8]
            observations.append(_observation(
                "injection_attempts", ip, route, hits=len(rows), labels=labels,
                waf_allowed=sum(row.action == "ALLOW" for row in rows),
            ))
    crawlers: set[str] = set()
    for ip, rows in slow_ip.items():
        shapes = {r.path_shape_hash for r in rows if r.path_shape_hash}
        buckets = {int(r.observed_at.timestamp()) // 300 for r in rows}
        if len(rows) >= 12 and len(shapes) >= 8 and len(buckets) >= 3:
            crawlers.add(ip)
            observations.append(_observation(
                "slow_recon_ip", ip, "*", hits=len(rows), unknown_shapes=len(shapes),
                five_minute_buckets=len(buckets),
            ))
    # A JA4 is shared by legitimate browsers, so it only corroborates: one address
    # must already be a crawler on its own, and another must show breadth too.
    for ja4, rows in slow_ja4.items():
        per_ip: dict[str, list[NormalizedWafEvent]] = defaultdict(list)
        for row in rows:
            if row.source_ip_hash:
                per_ip[row.source_ip_hash].append(row)
        contributing = [
            ip for ip, ip_rows in per_ip.items()
            if len(ip_rows) >= 6
            and len({r.path_shape_hash for r in ip_rows if r.path_shape_hash}) >= 4
        ]
        if len(contributing) >= 2 and crawlers.intersection(contributing):
            observations.append(_observation(
                "slow_recon_ja4", ja4, "*", severity="low",
                contributing_addresses=len(contributing), hits=len(rows),
            ))
    return observations


def assess_application(
    events: Sequence[ApplicationSignal], *, end: datetime, salt: bytes,
) -> list[dict]:
    """Score application decisions. WAF status and URLs cannot prove these outcomes."""
    denied: dict[tuple[str, str], list[ApplicationSignal]] = defaultdict(list)
    auth_by_ip: dict[str, list[ApplicationSignal]] = defaultdict(list)
    auth_by_account: dict[str, list[ApplicationSignal]] = defaultdict(list)
    success_by_account: dict[str, list[ApplicationSignal]] = defaultdict(list)
    foreign: dict[tuple[str, str], list[ApplicationSignal]] = defaultdict(list)
    observations: list[dict] = []
    for event in events:
        ip = _ip_digest(event.client_ip, salt)
        if (event.event == "authz_denied" and event.reason == "owner_mismatch"
                and event.principal_hash and event.resource_id_hash
                and _recent(event.occurred_at, end, 15)):
            denied[(event.principal_hash, event.route)].append(event)
        if (event.event == "foreign_object_access" and event.principal_hash
                and event.owner_hash and event.owner_hash != event.principal_hash
                and 200 <= event.response_status < 300):
            foreign[(event.principal_hash, event.route)].append(event)
        if not event.account_hash or not _recent(event.occurred_at, end, 15):
            continue
        if event.event == "auth_failed":
            auth_by_account[event.account_hash].append(event)
            if _recent(event.occurred_at, end, 5):
                auth_by_ip[ip].append(event)
        elif event.event == "auth_succeeded":
            success_by_account[event.account_hash].append(event)

    # One served foreign object is already an authorization failure.
    for (principal, route), rows in foreign.items():
        observations.append(_observation(
            "foreign_object_access", principal, route, severity="high",
            confidence="verified", accesses=len(rows),
            objects=len({r.resource_id_hash for r in rows if r.resource_id_hash}),
        ))
    for (principal, route), rows in denied.items():
        ids = {r.resource_id_hash for r in rows}
        if len(rows) >= 10 and len(ids) >= 5:
            observations.append(_observation(
                "resource_id_enumeration", principal, route,
                denials=len(rows), distinct_ids=len(ids),
            ))
    targeted_accounts: set[str] = set()
    for ip, rows in auth_by_ip.items():
        accounts = {r.account_hash for r in rows if r.account_hash}
        if len(rows) >= 10 and len(accounts) >= 5:
            targeted_accounts.update(accounts)
            observations.append(_observation(
                "credential_stuffing", ip, "*", failures=len(rows), accounts=len(accounts),
            ))
    for account, rows in auth_by_account.items():
        addresses = {_ip_digest(r.client_ip, salt) for r in rows}
        if len(rows) >= 5 and len(addresses) >= 3:
            targeted_accounts.add(account)
            observations.append(_observation(
                "distributed_brute_force", account, "*", failures=len(rows),
                addresses=len(addresses),
            ))
    for account in targeted_accounts:
        failures = auth_by_account[account]
        if any(
            success.occurred_at > failure.occurred_at
            for success in success_by_account.get(account, []) for failure in failures
        ):
            observations.append(_observation(
                "auth_success_after_attack", account, "*", severity="high",
                failures=len(failures),
            ))
    return observations


def deduplicate_app(events: Sequence[ApplicationSignal]) -> list[ApplicationSignal]:
    seen: set[tuple[str, str]] = set()
    kept = []
    for event in events:
        key = (event.request_id, event.event)
        if key not in seen:
            seen.add(key)
            kept.append(event)
    return kept
