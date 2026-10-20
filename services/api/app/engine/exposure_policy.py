"""Scoring rules for what a response body gives away. Pure — no I/O.

Two questions about one JSON response, both answerable from field *names* alone:

1. Does it carry a field whose name means credential material, a government
   identifier, payment data or internal state? That is over-exposure regardless
   of what the spec says — a `password_hash` in an API response is a finding
   even when the schema declares it.
2. Does it carry fields the operation's declared response schema does not? That
   is spec drift: either the API returns more than it documents (nobody reviewed
   the extra fields) or the spec is stale (the scanner, and every client
   generator, is working from a lie).

**Values are never read and never reported.** Only field names, their JSON
paths, and counts leave this module. A rule that had to inspect values would be
a rule that could put a customer's data in a findings table.

The counterpart of ``header_policy.py``: the same shape, the same reason —
scoring lives in a pure function so it can be reasoned about and unit-tested
without a target, and ``apps/web/lib/coverage.ts`` mirrors it for users.
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any

from app.domain.enums import Severity
from app.domain.sensitive import ALLOWED, CATEGORY_PATTERNS, _hit
from app.domain.sensitive import normalise as _normalise

# Bounds on how far into a response we look. A response is attacker-influenced
# data; walking it unbounded is a memory risk, not a thoroughness win.
MAX_DEPTH = 5
MAX_FIELDS = 400
#: Array elements inspected per array. Homogeneous lists add no new field names.
MAX_ARRAY_ITEMS = 3


@dataclass(frozen=True)
class SensitiveRule:
    """One family of field names that should not be in an API response."""

    #: Machine key, also the grouping key for findings.
    key: str
    #: Human label used in the finding title.
    label: str
    severity: Severity
    #: Matched against the *normalised* field name (lowercased, separators
    #: stripped), so `password_hash`, `passwordHash` and `PasswordHash` are one.
    pattern: re.Pattern[str]
    #: Why it matters — becomes part of the finding description.
    why: str


def _rule(key: str, label: str, severity: Severity, why: str) -> SensitiveRule:
    """One rule, taking its pattern from the shared vocabulary.

    The *names* live in ``app/domain/sensitive`` because redaction needs the same
    list; the severity and the rationale live here because only reporting needs
    them.
    """
    return SensitiveRule(key, label, severity, CATEGORY_PATTERNS[key], why)


#: Ordered most-severe first: a name matching several rules is reported once,
#: under the first that claims it.
SENSITIVE_RULES: tuple[SensitiveRule, ...] = (
    _rule(
        "credential",
        "credential material",
        Severity.high,
        "Credential material must never leave the server, hashed or not: a hash "
        "is offline-crackable and a salt makes that cheaper.",
    ),
    _rule(
        "token",
        "session or bearer token",
        Severity.high,
        "A token in a response body is a credential a client can leak through "
        "logs, caches, referrers and analytics.",
    ),
    _rule(
        "payment",
        "payment data",
        Severity.high,
        "Payment data in a response widens PCI scope to every client that "
        "receives it.",
    ),
    _rule(
        "government_id",
        "government identifier",
        Severity.high,
        "Government identifiers are the highest-value PII an API can leak and "
        "cannot be rotated after a breach.",
    ),
    _rule(
        "internal",
        "internal state",
        Severity.medium,
        "Internal state hands an attacker your topology, framework and query "
        "shapes — the reconnaissance step of most real attacks.",
    ),
)

#: Field names that look sensitive to the rules above but routinely are not.
#: Checked before the rules, so they cannot be reported.
_ALLOWED = ALLOWED


#: Re-exported so callers keep importing the exposure vocabulary from one place.
normalise = _normalise


@dataclass(frozen=True)
class ExposedField:
    """One field name found in a response, with where it sat."""

    #: The name as the target spelled it.
    name: str
    #: Dotted path within the body, e.g. ``items[].owner.email``.
    location: str


def field_names(payload: Any) -> list[ExposedField]:
    """Every field name in a decoded JSON body, with its path. Bounded.

    Arrays collapse to ``[]`` in the path and only the first few elements are
    walked: a list of 500 identical objects contributes the same names as one.
    """
    return _walk_fields(payload)[0]


def field_names_truncated(payload: Any) -> tuple[list[ExposedField], bool]:
    """``field_names`` plus whether a bound cut the walk short.

    The truncation flag lets a caller tell "there are no more sensitive fields"
    from "there may be, but we stopped looking" — a silent cap otherwise reads
    like a clean response.
    """
    return _walk_fields(payload)


def _walk_fields(payload: Any) -> tuple[list[ExposedField], bool]:
    found: list[ExposedField] = []
    seen: set[str] = set()
    truncated = False

    def walk(node: Any, path: str, depth: int) -> None:
        nonlocal truncated
        if depth > MAX_DEPTH:
            truncated = True
            return
        if len(found) >= MAX_FIELDS:
            truncated = True
            return
        if isinstance(node, dict):
            for key, value in node.items():
                if len(found) >= MAX_FIELDS:
                    truncated = True
                    return
                if not isinstance(key, str):
                    continue
                where = f"{path}.{key}" if path else key
                if where not in seen:
                    seen.add(where)
                    found.append(ExposedField(key, where))
                walk(value, where, depth + 1)
        elif isinstance(node, list):
            if len(node) > MAX_ARRAY_ITEMS:
                truncated = True
            for item in node[:MAX_ARRAY_ITEMS]:
                walk(item, f"{path}[]", depth + 1)

    walk(payload, "", 0)
    return found, truncated


@dataclass(frozen=True)
class ExposureIssue:
    """One problem with one response body."""

    #: Rule key, or ``"undeclared"`` for a spec-drift issue.
    key: str
    label: str
    severity: Severity
    why: str
    #: The offending field names, as the target spelled them. Never values.
    fields: tuple[str, ...]


def sensitive_issues(fields: list[ExposedField]) -> list[ExposureIssue]:
    """Fields whose *names* mean they should not be in an API response."""
    by_rule: dict[str, list[str]] = {}
    for f in fields:
        name = normalise(f.name)
        if not name or name in _ALLOWED:
            continue
        for rule in SENSITIVE_RULES:
            # Several spellings: an anchored rule like ``^_`` needs the raw
            # name, which normalising has stripped the separator from. See
            # ``domain/sensitive.forms``.
            if _hit(rule.pattern, f.name):
                names = by_rule.setdefault(rule.key, [])
                if f.name not in names:
                    names.append(f.name)
                break
    issues: list[ExposureIssue] = []
    for rule in SENSITIVE_RULES:
        matched = by_rule.get(rule.key)
        if matched:
            issues.append(
                ExposureIssue(
                    key=rule.key,
                    label=rule.label,
                    severity=rule.severity,
                    why=rule.why,
                    fields=tuple(sorted(matched)),
                )
            )
    return issues


def _parent_of(location: str) -> str | None:
    """The path one level up from a field location (``owner`` for ``owner.email``)."""
    idx = location.rfind(".")
    return location[:idx] if idx != -1 else None


def undeclared_issue(
    fields: list[ExposedField], declared: set[str] | None
) -> ExposureIssue | None:
    """Fields the declared response schema does not mention.

    ``None`` for ``declared`` means the operation documents no response schema —
    absence of a contract is not evidence of drift, so nothing is reported.

    ``declared`` may carry either top-level names (``declared_response_fields``)
    or full nested paths (``declared_response_field_paths``). A field is drift
    when its path is not declared *and* it can be judged: a top-level field
    always can, and a nested field can when the schema actually spells out its
    parent's children. An opaque object declared as just ``owner`` with no
    ``owner.*`` leaves everything beneath it alone — its contents were never
    specified, so they are not evidence of drift.
    """
    if not declared:
        return None
    # Normalise both sides like the sensitive-name half: passwordHash vs a
    # declared password_hash is one field, not a sensitive hit *and* a drift.
    declared_norm = {normalise(d) for d in declared}
    # Parents whose *children* the schema describes. Only these make a nested
    # field judgeable.
    described = {
        normalise(parent)
        for d in declared
        if (parent := _parent_of(d)) is not None
    }

    def judged(field: ExposedField) -> bool:
        location = field.location
        if normalise(location) in declared_norm:
            return False
        parent = _parent_of(location)
        return parent is None or normalise(parent) in described

    extra = sorted({f.location for f in fields if judged(f)})
    if not extra:
        return None
    return ExposureIssue(
        key="undeclared",
        label="fields absent from the declared response schema",
        severity=Severity.low,
        why=(
            "The response returns more than the spec documents. Either the API "
            "exposes fields nobody reviewed, or the schema is stale — and every "
            "client generator, scanner and reviewer is working from it."
        ),
        fields=tuple(extra),
    )
