"""Notification endpoints and the delivery outbox.

The destination URL is encrypted with the same vault as credentials: a Slack
incoming-webhook URL is itself a bearer secret. Only a sanitized hint
(scheme/host/path, no query) is returned to the UI.

A delivery row is the outbox entry. Its ``(endpoint_id, dedup_key)`` unique
constraint is what makes "the same unchanged state" quiet: enqueueing the same
event twice inserts once.
"""
from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import (
    Boolean,
    CheckConstraint,
    DateTime,
    ForeignKey,
    Integer,
    String,
    Text,
    UniqueConstraint,
    func,
)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.models.base import Base, created_at_col, uuid_pk

__all__ = ["NotificationDelivery", "NotificationEndpoint"]


class NotificationEndpoint(Base):
    __tablename__ = "notification_endpoints"
    __table_args__ = (
        CheckConstraint(
            "kind IN ('webhook', 'slack')", name="ck_notification_endpoints_kind"
        ),
        CheckConstraint(
            "min_severity IN ('info', 'low', 'medium', 'high', 'critical')",
            name="ck_notification_endpoints_severity",
        ),
    )

    id: Mapped[uuid.UUID] = uuid_pk()
    tenant_slug: Mapped[str] = mapped_column(
        ForeignKey("tenants.slug", ondelete="CASCADE"), index=True
    )
    kind: Mapped[str] = mapped_column(String(16))
    #: Fernet-encrypted destination. Never serialized out.
    destination_ref: Mapped[str] = mapped_column(String(4096))
    #: scheme://host/path, query stripped — enough for a person to recognise it.
    destination_hint: Mapped[str] = mapped_column(String(512))
    #: Fernet-encrypted HMAC secret for a generic webhook; null for Slack.
    signing_secret_ref: Mapped[str | None] = mapped_column(
        String(4096), nullable=True
    )
    events: Mapped[list] = mapped_column(JSONB, default=list, server_default="[]")
    min_severity: Mapped[str] = mapped_column(
        String(20), default="medium", server_default="medium"
    )
    active: Mapped[bool] = mapped_column(
        Boolean, default=True, server_default="true", nullable=False
    )
    created_by_user_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )
    created_at: Mapped[datetime] = created_at_col()

    deliveries: Mapped[list[NotificationDelivery]] = relationship(
        "NotificationDelivery", back_populates="endpoint", cascade="all, delete-orphan"
    )


class NotificationDelivery(Base):
    __tablename__ = "notification_deliveries"
    __table_args__ = (
        UniqueConstraint(
            "endpoint_id",
            "dedup_key",
            name="uq_notification_deliveries_endpoint_dedup",
        ),
        CheckConstraint(
            "state IN ('pending', 'delivering', 'delivered', 'failed', 'dead')",
            name="ck_notification_deliveries_state",
        ),
    )

    id: Mapped[uuid.UUID] = uuid_pk()
    tenant_slug: Mapped[str] = mapped_column(
        ForeignKey("tenants.slug", ondelete="CASCADE"), index=True
    )
    endpoint_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("notification_endpoints.id", ondelete="CASCADE"), index=True
    )
    event_type: Mapped[str] = mapped_column(String(40))
    dedup_key: Mapped[str] = mapped_column(String(255))
    #: Value-free event body. Never contains evidence values or secrets.
    payload: Mapped[dict] = mapped_column(JSONB, default=dict, server_default="{}")
    state: Mapped[str] = mapped_column(
        String(16), default="pending", server_default="pending"
    )
    attempts: Mapped[int] = mapped_column(
        Integer, default=0, server_default="0", nullable=False
    )
    next_attempt_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), index=True
    )
    last_error: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = created_at_col()
    delivered_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )

    endpoint: Mapped[NotificationEndpoint] = relationship(
        "NotificationEndpoint", back_populates="deliveries"
    )
