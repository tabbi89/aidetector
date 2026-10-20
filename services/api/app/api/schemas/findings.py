"""Findings, their verdicts, and the human work tracked on them."""

from __future__ import annotations

import uuid
from datetime import date, datetime
from typing import Any, Literal

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    computed_field,
    field_validator,
)

from app.api.schemas.common import ResponseModel
from app.domain.enums import Confidence, Severity, Verdict
from app.domain.taxonomy import canonical_taxonomy_id


class VerdictUpdate(BaseModel):
    verdict: Verdict


class FindingOut(ResponseModel):
    model_config = ConfigDict(from_attributes=True)
    id: uuid.UUID
    operation_id: uuid.UUID | None = None
    check: str
    # Stable identity across runs — what the diff and carried triage match on.
    fingerprint: str = ""
    owasp_id: str | None = None
    severity: Severity
    # Evidence tier: how strongly the collected evidence supports the claim.
    confidence: Confidence = Confidence.heuristic
    title: str
    description: str
    evidence: dict[str, Any] = {}
    # What to change, shaped by this finding's evidence, plus supporting links.
    remediation: str = ""
    references: list[str] = []
    verdict: Verdict
    ai_rationale: str | None = None
    created_at: datetime

    @field_validator("owasp_id", mode="before")
    @classmethod
    def canonicalize_taxonomy(cls, value: str | None) -> str | None:
        return canonical_taxonomy_id(value)

    @computed_field  # type: ignore[prop-decorator]
    @property
    def premium(self) -> bool:
        """Whether the check that produced this finding is a premium-tier check.

        Read from the registry (not stored on the row), so the label always
        tracks the check's own ``premium`` trait — the single source of truth.
        """
        from app.engine.checks import premium_check_keys

        return self.check in premium_check_keys()


class FindingSummaryOut(ResponseModel):
    """Full-result counts for the attention summary.

    The findings list is paged, so a count derived from the first page would be
    wrong for every scan larger than a page. These numbers come from grouped
    queries over all of the scan's findings.
    """

    total: int
    active: int
    dismissed: int
    verified_critical: int
    verified_high: int
    severity: dict[str, int]


#: The states a finding work item may hold (mirrored by the model's CHECK).
WorkStatus = Literal["open", "in_progress", "resolved", "accepted_risk"]


class FindingWorkIn(BaseModel):
    """A partial work-item update.

    An omitted key is unchanged; an explicit ``null`` clears ``owner`` or
    ``due_date``. ``status`` null is treated as omitted.
    """

    owner: str | None = Field(default=None, max_length=120)
    #: A workspace member to assign; the display name is filled from the user.
    owner_user_id: uuid.UUID | None = None
    due_date: date | None = None
    status: WorkStatus | None = None


class FindingCommentIn(BaseModel):
    body: str = Field(min_length=1, max_length=4000)


class FindingCommentOut(ResponseModel):
    model_config = ConfigDict(from_attributes=True)
    id: uuid.UUID
    scan_id: uuid.UUID
    fingerprint: str
    author: str
    author_user_id: uuid.UUID | None = None
    body: str
    created_at: datetime


class FindingWorkOut(ResponseModel):
    scan_id: uuid.UUID
    fingerprint: str
    owner: str | None = None
    owner_user_id: uuid.UUID | None = None
    due_date: date | None = None
    status: WorkStatus
    updated_at: datetime
    #: Oldest first, and only the discussion of a live finding.
    comments: list[FindingCommentOut] = []
