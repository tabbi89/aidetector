"""Server-side persistence for the heavy-lane agent's episodic memory.

The pure half (``app/agent/memory.py``) does the embedding and recall maths; this
is the thin database layer around it. It is called at run completion to
``remember`` a scan's findings (after ``append_finding`` has stamped
fingerprints), and by the ingest API to ``recall`` what prior heavy runs found
on the same target for the same tenant.

A row is upserted on its natural key (tenant, host, fingerprint): a weakness
seen again bumps ``hits`` and refreshes the grade rather than duplicating. Only
fingerprint-bearing findings are remembered — a finding with no stable identity
has nothing to recall against.
"""
from __future__ import annotations

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.agent import memory as mem
from app.models.agent_memory import AgentMemory
from app.models.scan import Scan

#: Never let one target's memory grow without bound; recall reads the newest.
MAX_ROWS_PER_HOST = 500


def remember(db: Session, scan: Scan) -> int:
    """Persist this scan's fingerprinted findings as episodic memory.

    Returns how many rows were written or refreshed. Best-effort: the caller
    commits, and a memory failure must never fail a run (callers wrap it).
    """
    host = mem.host_of(scan.target_base_url)
    tenant = scan.tenant_id
    existing = {
        row.fingerprint: row
        for row in db.scalars(
            select(AgentMemory).where(
                AgentMemory.tenant_id == tenant, AgentMemory.target_host == host
            )
        )
    }
    written = 0
    for finding in scan.findings:
        fingerprint = getattr(finding, "fingerprint", "") or ""
        record = mem.record_from_finding(
            fingerprint=fingerprint,
            check=finding.check,
            severity=_value(finding.severity),
            confidence=_value(finding.confidence),
            title=finding.title or "",
            evidence=finding.evidence or {},
        )
        if record is None:
            continue
        row = existing.get(fingerprint)
        if row is None:
            db.add(
                AgentMemory(
                    tenant_id=tenant,
                    target_host=host,
                    fingerprint=fingerprint,
                    check=record.check,
                    severity=record.severity,
                    confidence=record.confidence,
                    title=record.title,
                    embedding=record.embedding,
                    hits=1,
                )
            )
        else:
            row.hits += 1
            row.severity = record.severity
            row.confidence = record.confidence
            row.title = record.title
            row.embedding = record.embedding
        written += 1
    return written


def recall(db: Session, tenant_id: str, target_host: str, *, limit: int = 100) -> list[dict]:
    """The stored memory rows for a tenant+host, newest first, as dicts.

    The pure ``memory.recall`` ranks and filters these against the current
    scan; this only fetches the candidate set the agent reasons over.
    """
    host = mem.host_of(target_host)
    rows = db.scalars(
        select(AgentMemory)
        .where(AgentMemory.tenant_id == tenant_id, AgentMemory.target_host == host)
        .order_by(AgentMemory.last_seen_at.desc())
        .limit(min(limit, MAX_ROWS_PER_HOST))
    )
    return [
        {
            "fingerprint": r.fingerprint,
            "check": r.check,
            "severity": r.severity,
            "confidence": r.confidence,
            "title": r.title,
            "hits": r.hits,
            "embedding": r.embedding or [],
        }
        for r in rows
    ]


def _value(enum_or_str: object) -> str:
    return getattr(enum_or_str, "value", str(enum_or_str))
