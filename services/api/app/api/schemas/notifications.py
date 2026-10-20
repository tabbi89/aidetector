"""Notification endpoints and their deliveries."""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Literal

from pydantic import (
    BaseModel,
    Field,
)

from app.api.schemas.common import ResponseModel
from app.domain.enums import Severity

# ---- Notification endpoints and deliveries ---------------------------------


class NotificationEndpointIn(BaseModel):
    kind: Literal["webhook", "slack"]
    destination: str = Field(min_length=8, max_length=2048)
    events: list[str] = Field(default_factory=list, max_length=16)
    min_severity: Severity = Severity.medium
    active: bool = True


class NotificationEndpointUpdate(BaseModel):
    events: list[str] | None = Field(default=None, max_length=16)
    min_severity: Severity | None = None
    active: bool | None = None


class NotificationEndpointOut(ResponseModel):
    id: uuid.UUID
    kind: str
    destination_hint: str
    events: list[str]
    min_severity: Severity
    active: bool
    created_at: datetime


class NotificationEndpointCreated(NotificationEndpointOut):
    #: Webhook HMAC secret, shown once; null for Slack (the URL is the secret).
    signing_secret: str | None = None


class NotificationDeliveryOut(ResponseModel):
    id: uuid.UUID
    event_type: str
    state: str
    attempts: int
    last_error: str | None = None
    created_at: datetime
    delivered_at: datetime | None = None
