"""Ownership verification for public scan targets."""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Literal

from pydantic import BaseModel, Field

from app.api.schemas.common import ResponseModel


class DomainVerificationIn(BaseModel):
    #: An exact host (``api.example.com``) or IP literal — not a URL.
    host: str = Field(min_length=1, max_length=255)


class DomainVerifyRequest(BaseModel):
    #: Where to fetch the HTTP token from; its host must be the record's.
    #: Defaults to ``https://<host>``. Scans always fetch from their own origin.
    url: str | None = Field(default=None, max_length=2048)


class DomainProofOut(ResponseModel):
    """One proof's outcome from the last explicit check."""

    proof: Literal["dns", "http"]
    ok: bool
    #: Why it failed, phrased so the fix is obvious; null when it passed.
    detail: str | None = None


class DomainVerificationOut(ResponseModel):
    id: uuid.UUID
    host: str
    token: str
    #: Publish ``dns_record_value`` as a TXT record named ``dns_record_name``
    #: (null for an IP literal, which has no name to prove).
    dns_record_name: str | None
    dns_record_value: str
    #: Serve the bare token, with status 200, at this path on the target origin.
    http_path: str
    #: ``http_path`` on the default origin (``https://<host>``), ready to open.
    http_url: str
    verified_at: datetime | None
    last_checked_at: datetime | None
    last_error: str | None
    #: Each proof from the last check, in order (DNS, then HTTP). Empty before
    #: the first check, or when the egress policy refused the host outright.
    last_checks: list[DomainProofOut] = Field(default_factory=list)
    created_at: datetime


class TargetOwnershipOut(ResponseModel):
    """Whether a run of this scan's target will need ownership proof.

    Advisory: nothing is fetched from the target to answer it, and the run gate
    re-proves ownership live on every run.
    """

    host: str
    #: False when the egress policy refuses the target outright; ``reason`` says why.
    allowed: bool
    #: True when a run needs this workspace to have proven it controls ``host``.
    required: bool
    #: Why no proof is needed: ``disabled``, ``allowlist`` or ``private``.
    exempt: str | None
    #: This workspace's entry for ``host`` under Workspace → Domains, if any.
    domain_id: uuid.UUID | None
    #: When the entry last passed an explicit check.
    verified_at: datetime | None
    #: Why the entry's last explicit check failed.
    last_error: str | None
    reason: str | None
