"""Findings — one detected (candidate) vulnerability, with evidence.

Produced by the engine tier (phase 2). The AI cascade (phase 4) later adjudicates
HYBRID findings; ``verdict`` records that outcome. Evidence holds the request/
response summary a human needs to reproduce it.
"""
from __future__ import annotations

import uuid
from collections.abc import Iterable
from datetime import datetime

from sqlalchemy import Enum, ForeignKey, String, Text
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.domain.enums import (
    CONFIDENCE_RANK,
    SEVERITY_RANK,
    Confidence,
    Severity,
    Verdict,
)
from app.models.base import Base, created_at_col, uuid_pk

# The vocabulary lives in ``app/domain/enums.py`` — a severity is a product
# concept, not a column type. This module maps columns onto it and owns the
# ORM row plus the ordering its readers (the API, the reports) share.
__all__ = ["Finding", "sort_findings"]


def sort_findings(findings: Iterable[Finding]) -> list[Finding]:
    """Findings in report order: most severe first, proof before leads, then check.

    The one ordering the API, the JSON export, the PDF and the HTML report all
    use, so a reader sees the same sequence everywhere. Confidence breaks the
    severity tie so the findings a reader can act on immediately sort above the
    ones that still need confirming.
    """
    return sorted(
        findings,
        key=lambda f: (
            -SEVERITY_RANK[f.severity],
            -CONFIDENCE_RANK[f.confidence or Confidence.heuristic],
            f.check,
        ),
    )



class Finding(Base):
    __tablename__ = "findings"

    id: Mapped[uuid.UUID] = uuid_pk()
    scan_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("scans.id", ondelete="CASCADE"), index=True
    )
    operation_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("operations.id", ondelete="SET NULL"), nullable=True
    )
    # Machine key for the check that produced it, e.g. "bola", "bfla".
    check: Mapped[str] = mapped_column(String(60))
    # Stable identity across runs (app/engine/fingerprint.py): what and where,
    # never counts or ids that drift. Carries triage forward and drives the
    # run-to-run diff. Empty on rows recorded before the column existed.
    fingerprint: Mapped[str] = mapped_column(
        String(64), default="", server_default="", index=True
    )
    owasp_id: Mapped[str | None] = mapped_column(String(20), nullable=True)
    severity: Mapped[Severity] = mapped_column(Enum(Severity, name="severity"))
    # Evidence tier. Set by the check that produced the finding; defaults to the
    # cautious tier so an ungraded finding is never read as proof.
    confidence: Mapped[Confidence] = mapped_column(
        Enum(Confidence, name="confidence"),
        default=Confidence.heuristic,
        server_default=Confidence.heuristic.value,
        nullable=False,
    )
    title: Mapped[str] = mapped_column(String(255))
    description: Mapped[str] = mapped_column(Text, default="")
    evidence: Mapped[dict] = mapped_column(JSONB, default=dict)
    # What to change, shaped by this finding's own evidence. Filled from
    # ``app/engine/remediation.py`` when the check does not supply its own.
    remediation: Mapped[str] = mapped_column(Text, default="", server_default="")
    # Supporting links (OWASP cheat sheets, CWE) for the fix above.
    references: Mapped[list] = mapped_column(JSONB, default=list)
    verdict: Mapped[Verdict] = mapped_column(
        Enum(Verdict, name="verdict"), default=Verdict.unreviewed
    )
    # Set by the AI cascade when it adjudicates a HYBRID finding.
    ai_rationale: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = created_at_col()

    scan = relationship("Scan", back_populates="findings")
