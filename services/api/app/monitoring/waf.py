"""Normalize WAF/access-log records without retaining request values.

Adapters may pass vendor-shaped dictionaries here (AWS WAF, a reverse proxy,
or an MCP read adapter).  The normalizer is the retention boundary: query
values, cookies, authorization material, and raw paths are never returned.
"""
from __future__ import annotations

import hashlib
import hmac
import re
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import UTC, datetime
from urllib.parse import parse_qsl, unquote, urlsplit

from app.monitoring.contracts import RouteBinding

_UUID = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$",
    re.IGNORECASE,
)
_INTEGER = re.compile(r"^[0-9]+$")
_HEX_ID = re.compile(r"^[0-9a-f]{24,}$", re.IGNORECASE)
_STATIC = frozenset(
    "api v1 v2 v3 users orders items widgets projects invoices accounts login logout "
    "register signup password reset recovery search health admin me profile payments".split()
)
_WORD = re.compile(r"^[a-z][a-z0-9_.-]{0,23}$")
MAX_ROUTE_DEPTH = 3
#: Longest attack path sample retained; a payload past this is already identifiable.
MAX_ATTACK_PATH = 200
_QUERY_NAMES = frozenset(
    "email token password api_key access_token refresh_token session_id ssn phone page "
    "limit offset sort q query search id".split()
)


_BOT_CONTROL = "awswaf:managed:aws:bot-control:"
_LABEL_VALUE = re.compile(r"^[a-z0-9_.-]{1,80}$")
_SIGNAL_VALUE = re.compile(r"^[a-z0-9_.:-]{1,80}$")
_BOT_FIELDS = (
    ("bot_name", "bot:name:"),
    ("bot_organization", "bot:organization:"),
    ("bot_category", "bot:category:"),
    ("wba_status", "bot:web_bot_auth:"),
)
# Strongest claim first: a request carrying both labels is reported as verified.
_VERIFICATION = (
    ("bot:verified", "verified"),
    ("bot:user_triggered:verified", "user_triggered"),
    ("bot:developer_platform:verified", "developer_platform"),
    ("bot:unverified", "unverified"),
)
# JA4 TLS client fingerprint: protocol, version, SNI, cipher/extension counts,
# ALPN, then two truncated SHA-256 hashes. It names client software, not a user.
_JA4 = re.compile(r"^[tqd][0-9a-z]{2}[di][0-9]{4}[0-9a-z]{2}_[0-9a-f]{12}_[0-9a-f]{12}$")
_MANAGED = "awswaf:managed:aws:"
# Managed rule groups whose matches mean a request carried an attack payload.
# IP reputation and Bot Control say who the client is, not what it sent.
_PAYLOAD_GROUPS = frozenset(
    "core-rule-set sql-database known-bad-inputs linux-os unix-os windows-os php-app "
    "wordpress-app admin-protection".split()
)
# Core rule set matches that flag an unusual client or a large body, not a payload.
_NOT_PAYLOAD = ("sizerestrictions_", "nouseragent", "useragent_badbots", "badbots")
_RULE_NAME = re.compile(r"^[A-Za-z0-9_.-]{1,80}$")
# Query parameters named like object references; the value must look like an id too.
_ID_PARAMS = frozenset(
    "acct account appt company customer invoice job msg message order tech ticket user".split()
)
MAX_QUERY_PAIRS = 50


@dataclass(frozen=True, slots=True)
class NormalizedWafEvent:
    """Value-free event retained long enough for daily aggregation.

    ``attack_path`` is the single exception and is populated only alongside
    ``attack_labels`` -- see its note below.

    ``identifier_hashes`` are HMACs, not raw identifiers.  Callers should
    aggregate these in memory and persist only the resulting counts.

    The ``bot_*`` fields are AWS WAF Bot Control vocabulary (a bot's published
    name, organization and AWS category), not values supplied by a client, so
    they may be kept in aggregates.
    """

    observed_at: datetime
    method: str
    route_family: str
    status_code: int | None
    action: str
    principal_hash: str | None
    source_ip_hash: str | None
    identifier_hashes: tuple[str, ...]
    query_keys: tuple[str, ...]
    request_id_hash: str | None
    response_bytes: int | None
    successor_hashes: tuple[str, ...] = ()
    route_mapping: str = "heuristic"
    sensitive_locations: tuple[str, ...] = ()
    correlation_hash: str | None = None
    bot_name: str | None = None
    bot_organization: str | None = None
    bot_category: str | None = None
    bot_verification: str | None = None
    wba_status: str | None = None
    bot_signals: tuple[str, ...] = ()
    #: JA4 TLS fingerprint as AWS WAF logged it, kept because a WAF rule can match it.
    ja4: str | None = None
    #: HMAC of the path with identifiers templated, to count distinct paths; never stored.
    path_shape_hash: str | None = None
    #: ``group:rule`` of AWS managed rules that matched an attack payload.
    attack_labels: tuple[str, ...] = ()
    #: Let through by one of the operator's own allow rules (an allowlisted integration).
    allow_rule: bool = False
    #: Names of query parameters that carried an identifier (names only, never values).
    identifier_keys: tuple[str, ...] = ()
    #: The request path as sent, kept **only** when ``attack_labels`` matched. A
    #: payload-matched path is attacker-supplied, so it is evidence rather than a
    #: client's data -- the same reason the scan request trace keeps the body it sent.
    #: Percent-encoding is preserved (it is half of a traversal payload) and the query
    #: string is dropped, because that is where a real client's values live.
    attack_path: str | None = None


def attack_labels(record: Mapping[str, object]) -> tuple[str, ...]:
    """Managed-rule payload matches as ``group:rule``; AWS vocabulary, never request data."""
    found: set[str] = set()
    labels = record.get("labels")
    for label in labels[:200] if isinstance(labels, list) else []:
        name = label.get("name") if isinstance(label, Mapping) else None
        if not isinstance(name, str) or not name.startswith(_MANAGED):
            continue
        group, _, rule = name[len(_MANAGED):].partition(":")
        if (
            group in _PAYLOAD_GROUPS
            and _RULE_NAME.fullmatch(rule)
            and not rule.lower().startswith(_NOT_PAYLOAD)
        ):
            found.add(f"{group}:{rule}")
    return tuple(sorted(found)[:8])


def _allow_rule(record: Mapping[str, object], action: str) -> bool:
    rule = _text(record.get("terminatingRuleId"))
    return (
        action == "ALLOW"
        and rule is not None
        and rule != "Default_Action"
        and record.get("terminatingRuleType") != "MANAGED_RULE_GROUP"
    )


def _is_identifier(value: str) -> bool:
    return bool(_INTEGER.fullmatch(value) or _UUID.fullmatch(value) or _HEX_ID.fullmatch(value))


def _query_identifiers(
    pairs: list[tuple[str, str]], salt: bytes
) -> tuple[tuple[str, ...], tuple[str, ...], tuple[str, ...]]:
    """(identifier hashes, successor hashes, parameter names) for id-shaped query values.

    The parameter name is part of the HMAC input, so ``jid=7`` and ``tech_id=7``
    stay different objects and a successor only joins within one parameter.
    """
    hashes: set[str] = set()
    successors: set[str] = set()
    names: set[str] = set()
    for key, value in pairs[:MAX_QUERY_PAIRS]:
        name = key.lower()[:80]
        if not (name.endswith("id") or name in _ID_PARAMS) or not _is_identifier(value):
            continue
        names.add(name)
        hashes.add(hmac.new(salt, f"{name}={value}".encode(), hashlib.sha256).hexdigest())
        if _INTEGER.fullmatch(value) and len(value) < 19:
            successor = f"{name}={int(value) + 1}".encode()
            successors.add(hmac.new(salt, successor, hashlib.sha256).hexdigest())
    return tuple(sorted(hashes)), tuple(sorted(successors)), tuple(sorted(names)[:8])


def _shape_key(raw_path: str, salt: bytes) -> str | None:
    path = unquote(urlsplit(raw_path).path or "/")
    shape = "/".join("{id}" if _is_identifier(part) else part for part in path.split("/"))
    return _hmac(shape[:2048], salt)


def bot_labels(record: Mapping[str, object]) -> dict[str, object]:
    """Read Bot Control labels; anything outside that namespace is ignored."""
    found: dict[str, object] = {}
    names: set[str] = set()
    signals: set[str] = set()
    labels = record.get("labels")
    for label in labels[:200] if isinstance(labels, list) else []:
        name = label.get("name") if isinstance(label, Mapping) else None
        if not isinstance(name, str) or not name.startswith(_BOT_CONTROL):
            continue
        rest = name[len(_BOT_CONTROL):].lower()
        names.add(rest)
        for field, prefix in _BOT_FIELDS:
            value = rest[len(prefix):] if rest.startswith(prefix) else ""
            if field not in found and _LABEL_VALUE.fullmatch(value):
                found[field] = value
        for prefix in ("signal:", "targeted:signal:"):
            value = rest[len(prefix):] if rest.startswith(prefix) else ""
            if _SIGNAL_VALUE.fullmatch(value):
                signals.add(value)
    found["bot_verification"] = next(
        (status for label, status in _VERIFICATION if label in names), None
    )
    found["bot_signals"] = tuple(sorted(signals)[:16])
    return found


def _first(record: Mapping[str, object], *keys: str) -> object | None:
    for key in keys:
        value = record.get(key)
        if value is not None:
            return value
    return None


def _text(value: object | None) -> str | None:
    if value is None:
        return None
    text = str(value).strip()
    return text or None


def _hmac(value: str | None, salt: bytes) -> str | None:
    if not value:
        return None
    return hmac.new(salt, value.encode("utf-8", "replace"), hashlib.sha256).hexdigest()


def short_key(value: str) -> int:
    """A 64-bit set key from an HMAC hex digest, so day-long sets stay compact."""
    return int(value[:16], 16)


def _timestamp(value: object | None) -> datetime:
    if isinstance(value, datetime):
        return value if value.tzinfo else value.replace(tzinfo=UTC)
    if isinstance(value, int) and not isinstance(value, bool):
        return datetime.fromtimestamp(value / 1000, tz=UTC)
    raw = _text(value)
    if raw:
        try:
            parsed = datetime.fromisoformat(raw.replace("Z", "+00:00"))
            return parsed.astimezone(UTC) if parsed.tzinfo else parsed.replace(tzinfo=UTC)
        except ValueError:
            pass
    raise ValueError("WAF event has no valid timestamp")


def _attack_path(raw_path: str) -> str | None:
    """The path of a payload-matched request, safe to store as evidence.

    Only the caller's decision that a managed attack rule fired makes this safe, so
    it is never called otherwise. The path is kept as sent -- ``%2e%2e%2f`` returned
    verbatim is the evidence -- minus the query string and any control character.
    """
    path = urlsplit(raw_path).path or "/"
    cleaned = "".join(ch for ch in path if ch.isprintable())
    if not cleaned:
        return None
    if len(cleaned) > MAX_ATTACK_PATH:
        return cleaned[:MAX_ATTACK_PATH] + "..."
    return cleaned


def _path_parts(
    raw_path: str, method: str, routes: list[RouteBinding]
) -> tuple[str, tuple[str, ...], str]:
    parsed = urlsplit(raw_path)
    path = unquote(parsed.path or "/")
    families: list[str] = []
    identifiers: list[str] = []
    for route_binding in routes:
        expected = route_binding.path.strip("/").split("/")
        parts = path.strip("/").split("/")
        if route_binding.method == method and len(expected) == len(parts) and all(
            left == right or (right.startswith("{") and right.endswith("}"))
            for left, right in zip(parts, expected, strict=True)
        ):
            ids = tuple(left for left, right in zip(parts, expected, strict=True)
                        if right.startswith("{"))
            return route_binding.path, ids, "declared"
    for part in path.split("/"):
        if not part:
            continue
        if _INTEGER.fullmatch(part) or _UUID.fullmatch(part) or _HEX_ID.fullmatch(part):
            families.append("{id}")
            identifiers.append(part)
        else:
            families.append(part[:80])
    if all(part in _STATIC or part == "{id}" for part in families):
        return "/" + "/".join(families), tuple(identifiers), "heuristic"
    # Outside the API vocabulary: keep enough shape to read the traffic, but
    # never a segment that could carry a value (a name, email, slug or hash).
    shape = [
        part
        if part == "{id}" or part in _STATIC or (index == 0 and _plain_word(part))
        else "{value}"
        for index, part in enumerate(families[:MAX_ROUTE_DEPTH])
    ]
    if len(families) > MAX_ROUTE_DEPTH:
        shape.append("{more}")
    return "/" + "/".join(shape), tuple(identifiers), "unknown"


def _plain_word(part: str) -> bool:
    return (
        bool(_WORD.fullmatch(part))
        and sum(ch.isdigit() for ch in part) <= 2
        and part.count("-") < 3
    )


def _query_keys(raw_path: str, record: Mapping[str, object]) -> tuple[str, ...]:
    parsed = urlsplit(raw_path)
    keys = {key[:80] for key, _ in parse_qsl(parsed.query, keep_blank_values=True)}
    supplied = _first(record, "query_keys", "queryKeys", "query_parameters")
    if isinstance(supplied, Mapping):
        keys.update(str(key)[:80] for key in supplied)
    elif isinstance(supplied, list | tuple | set):
        keys.update(str(key)[:80] for key in supplied)
    return tuple(sorted(key for key in keys if key))


def _status(value: object | None) -> int | None:
    status = _integer(value)
    return status if status is not None and 100 <= status <= 599 else None


def _integer(value: object | None) -> int | None:
    if not isinstance(value, int | str) or isinstance(value, bool):
        return None
    try:
        parsed = int(value)
    except (TypeError, ValueError):
        return None
    return parsed if parsed is not None and parsed >= 0 else None


def normalize_waf_event(
    record: Mapping[str, object], *, salt: bytes,
    routes: list[RouteBinding] | None = None,
) -> NormalizedWafEvent:
    """Convert one vendor record to a safe, vendor-neutral event.

    ``salt`` must be stable for the monitoring tenant and rotated deliberately;
    it is used only to make principals, source IPs, request IDs, and path IDs
    joinable inside the detector without exposing their values.
    """
    request = record.get("httpRequest")
    pairs: list[tuple[str, str]] = []
    if isinstance(request, Mapping):
        record = {**request, **record}
        args = request.get("args")
        if isinstance(args, str):
            pairs = parse_qsl(args, keep_blank_values=True)
            record = {**record, "query_keys": [key for key, _ in pairs]}
    raw_path = _text(_first(record, "path", "uri", "httpRequest.uri"))
    if not raw_path:
        raise ValueError("WAF event has no request path")
    pairs += parse_qsl(urlsplit(raw_path).query, keep_blank_values=True)
    method = (_text(_first(record, "method", "httpMethod")) or "UNKNOWN").upper()
    route_family, identifiers, mapping = _path_parts(raw_path, method, routes or [])
    query_keys = _query_keys(raw_path, record)
    sensitive = tuple(sorted("query:" + key for key in query_keys if key in {
        "email", "token", "password", "api_key", "access_token", "refresh_token",
        "session_id", "ssn", "phone",
    }))
    correlation = _text(_first(record, "correlation_id", "correlationId"))
    query_ids, query_successors, identifier_keys = _query_identifiers(pairs, salt)
    action = (
        _text(_first(record, "action", "waf_action", "terminatingRuleAction")) or "UNKNOWN"
    ).upper()[:24]
    ja4 = _text(record.get("ja4Fingerprint"))
    matched = attack_labels(record)
    return NormalizedWafEvent(
        observed_at=_timestamp(_first(record, "observed_at", "timestamp", "time")),
        method=method[:12],
        route_family=route_family,
        status_code=_status(_first(record, "status", "status_code", "statusCode")),
        action=action,
        principal_hash=_hmac(
            _text(_first(record, "principal", "principal_id", "user", "client_id")), salt
        ),
        source_ip_hash=_hmac(_text(_first(record, "source_ip", "clientIp")), salt),
        identifier_hashes=tuple(
            filter(None, (_hmac(identifier, salt) for identifier in identifiers))
        ) + query_ids,
        query_keys=query_keys,
        request_id_hash=_hmac(
            _text(_first(record, "request_id", "requestId", "trace_id")), salt
        ),
        response_bytes=_integer(_first(record, "response_bytes", "bytes", "body_bytes")),
        successor_hashes=tuple(
            filter(None, (_hmac(str(int(value) + 1), salt) for value in identifiers
                          if _INTEGER.fullmatch(value)))
        ) + query_successors,
        route_mapping=mapping,
        sensitive_locations=sensitive,
        correlation_hash=_hmac(correlation, salt),
        ja4=ja4 if ja4 and _JA4.fullmatch(ja4) else None,
        path_shape_hash=_shape_key(raw_path, salt),
        attack_labels=matched,
        allow_rule=_allow_rule(record, action),
        identifier_keys=identifier_keys,
        attack_path=_attack_path(raw_path) if matched else None,
        **bot_labels(record),  # type: ignore[arg-type]
    )
