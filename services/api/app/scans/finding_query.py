"""The findings list as one query: filters, text search and a stable order.

The list used to arrive whole and be filtered in the browser; at scale a page of
the wrong rows is worse than useless, so the filters and ordering are part of the
query and a page is a true slice.
"""
from __future__ import annotations

import uuid
from dataclasses import dataclass
from typing import Any, Literal

from sqlalchemy import ColumnElement, Select, case, func, or_, select

from app.domain.enums import CONFIDENCE_RANK, SEVERITY_RANK, Confidence, Severity, Verdict
from app.models.finding import Finding
from app.models.scan import Operation

FindingSort = Literal["severity", "endpoint", "check", "newest"]


@dataclass(frozen=True)
class FindingFilter:
    """What the reviewer narrowed the list to; ``None`` leaves a field open."""

    severity: Severity | None = None
    check: str | None = None
    operation_id: uuid.UUID | None = None
    verdict: Verdict | None = None
    confidence: Confidence | None = None
    #: True keeps premium checks only, False drops them.
    premium: bool | None = None
    q: str | None = None
    #: An endpoint label as the UI renders it (``GET /users/{id}``).
    endpoint: str | None = None
    include_dismissed: bool = True


def endpoint_label() -> Any:
    """The endpoint label exactly as FindingsSection's ``endpointOf`` renders
    it: the operation's method and path, else the method and route (or path)
    the evidence recorded — adjunct findings carry no operation. Needs the
    outer join to ``Operation``."""
    # ``nullif`` because the web treats an empty evidence string as missing
    # (``evidenceText``), where ``coalesce`` alone would stop at it.
    def evidence(key: str):
        return func.nullif(Finding.evidence[key].astext, "")

    method = func.upper(func.coalesce(Operation.method, evidence("method")))
    route = func.coalesce(Operation.path, evidence("route"), evidence("path"))
    return method.op("||")(" ").op("||")(route)


def findings_query(
    scan_id: uuid.UUID, filters: FindingFilter, sort: FindingSort = "severity"
) -> Select[tuple[Finding]]:
    """One scan's findings, filtered and ordered; the caller adds limit/offset."""
    stmt = _filtered(select(Finding).where(Finding.scan_id == scan_id), filters)
    return _ordered(stmt, sort, joined_operation=_needs_operation(filters))


def _needs_operation(filters: FindingFilter) -> bool:
    return bool((filters.q or "").strip() or filters.endpoint)


def _filtered(stmt: Select[tuple[Finding]], f: FindingFilter) -> Select[tuple[Finding]]:
    equal_to = {
        Finding.severity: f.severity,
        Finding.check: f.check,
        Finding.operation_id: f.operation_id,
        Finding.verdict: f.verdict,
        Finding.confidence: f.confidence,
    }
    for column, value in equal_to.items():
        if value is not None:
            stmt = stmt.where(column == value)
    if f.premium is not None:
        from app.engine.checks import premium_check_keys

        keys = premium_check_keys()
        stmt = stmt.where(Finding.check.in_(keys) if f.premium else Finding.check.not_in(keys))
    if not f.include_dismissed:
        stmt = stmt.where(Finding.verdict != Verdict.dismissed)

    if not _needs_operation(f):
        return stmt
    stmt = stmt.outerjoin(Operation, Finding.operation_id == Operation.id)
    label = endpoint_label()
    if f.endpoint:
        stmt = stmt.where(label == f.endpoint)
    needle = (f.q or "").strip()
    if needle:
        pattern = f"%{needle}%"
        # The endpoint label the UI shows (method + path) is part of the text a
        # reviewer searches for; matching only the finding's own columns made a
        # visible match disappear as soon as the server took over the query.
        stmt = stmt.where(
            or_(
                Finding.title.ilike(pattern),
                Finding.description.ilike(pattern),
                Finding.check.ilike(pattern),
                Finding.owasp_id.ilike(pattern),
                Finding.remediation.ilike(pattern),
                Finding.fingerprint.ilike(pattern),
                Operation.path.ilike(pattern),
                Operation.method.ilike(pattern),
                Finding.evidence["route"].astext.ilike(pattern),
                Finding.evidence["path"].astext.ilike(pattern),
                Finding.evidence["method"].astext.ilike(pattern),
                label.ilike(pattern),
            )
        )
    return stmt


def _ordered(
    stmt: Select[tuple[Finding]], sort: FindingSort, *, joined_operation: bool
) -> Select[tuple[Finding]]:
    severity = case(SEVERITY_RANK, value=Finding.severity, else_=0).desc()
    confidence = case(CONFIDENCE_RANK, value=Finding.confidence, else_=0).desc()
    if sort == "endpoint" and not joined_operation:
        stmt = stmt.outerjoin(Operation, Finding.operation_id == Operation.id)
    orders: dict[str, tuple[ColumnElement[Any], ...]] = {
        "newest": (Finding.created_at.desc(), severity, confidence),
        "check": (Finding.check.asc(), severity, confidence),
        "endpoint": (Operation.path.asc().nullslast(), severity, confidence),
        "severity": (severity, confidence, Finding.check.asc()),
    }
    # A unique final key: without it ties (the common case — many findings share
    # a severity, confidence and check) let two pages overlap or skip rows.
    return stmt.order_by(*orders[sort], Finding.id.asc())
