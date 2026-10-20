"""Workspace, membership, API tokens, audit, and spending/run admission."""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any

from pydantic import (
    BaseModel,
    Field,
)

from app.api.schemas.common import ResponseModel
from app.core.passwords import MAX_LENGTH, MIN_LENGTH
from app.domain.permissions import Role

_EMAIL = r"^[^@\s]+@[^@\s]+\.[^@\s]+$"

# ---- Workspace, membership, tokens and audit ---------------------------------


class WorkspaceUserOut(ResponseModel):
    id: uuid.UUID
    email: str
    display_name: str


class WorkspaceOut(ResponseModel):
    tenant: str
    name: str
    plan: str
    role: Role
    user: WorkspaceUserOut | None = None
    members: int


class MemberOut(ResponseModel):
    user_id: uuid.UUID
    email: str
    display_name: str
    role: Role
    created_at: datetime


class MemberIn(BaseModel):
    email: str = Field(
        min_length=3,
        max_length=320,
        pattern=_EMAIL,
    )
    display_name: str = Field(min_length=1, max_length=120)
    role: Role = Role.analyst


class MemberRoleIn(BaseModel):
    role: Role


class TokenIn(BaseModel):
    user_id: uuid.UUID
    label: str = Field(default="", max_length=120)
    expires_at: datetime | None = None


class TokenOut(ResponseModel):
    id: uuid.UUID
    user_id: uuid.UUID
    email: str
    display_name: str
    prefix: str
    last4: str
    label: str
    created_at: datetime
    last_used_at: datetime | None = None
    expires_at: datetime | None = None
    revoked_at: datetime | None = None


class TokenCreated(TokenOut):
    token: str


class AuditOut(ResponseModel):
    id: uuid.UUID
    actor: WorkspaceUserOut | None = None
    action: str
    object_type: str
    object_id: str
    summary: dict[str, Any] = Field(default_factory=dict)
    created_at: datetime


# ---- Password sign-in and sign-up approval ----------------------------------


class SignupIn(BaseModel):
    email: str = Field(min_length=3, max_length=320, pattern=_EMAIL)
    display_name: str = Field(min_length=1, max_length=120)
    password: str = Field(min_length=MIN_LENGTH, max_length=MAX_LENGTH)


class SignupAccepted(ResponseModel):
    status: str = "pending"


class LoginIn(BaseModel):
    email: str = Field(min_length=1, max_length=320)
    password: str = Field(min_length=1, max_length=MAX_LENGTH)


class SessionOut(ResponseModel):
    token: str
    expires_at: datetime
    tenant: str
    role: Role
    user: WorkspaceUserOut


class PendingSignupOut(ResponseModel):
    user_id: uuid.UUID
    email: str
    display_name: str
    requested_at: datetime


class SignupApproveIn(BaseModel):
    role: Role = Role.analyst


# ---- Workspace spending and run admission --------------------------------

class BudgetIn(BaseModel):
    ai_monthly_micros: int | None = Field(default=None, ge=0)
    ai_per_scan_micros: int | None = Field(default=None, ge=0)
    max_concurrent_runs: int | None = Field(default=None, ge=1)
    max_queued_runs: int | None = Field(default=None, ge=0)
    scans_per_day: int | None = Field(default=None, ge=1)


class BudgetOut(BudgetIn):
    tenant: str
    plan: str
    month_spent_micros: int
    month_remaining_micros: int | None = None
    active_runs: int
    queued_runs: int
