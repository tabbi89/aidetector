"""Credential profiles — auth roles used during a scan.

Dual profiles (e.g. a low-priv 'user' and a high-priv 'admin') are what make
BOLA/BFLA testing possible: the engine replays requests across roles and looks
for cross-privilege access. The actual secret is stored encrypted (vault) and
never returned by the API.
"""
from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import Boolean, Enum, ForeignKey, Integer, String, UniqueConstraint, false
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.domain.enums import AuthType, GrantType
from app.models.base import Base, created_at_col, uuid_pk

# The vocabulary lives in app/domain/enums.py — how a credential authenticates
# is a product concept the engine reasons about, not a column type.
__all__ = ["CredentialProfile"]


class CredentialProfile(Base):
    __tablename__ = "credential_profiles"
    __table_args__ = (
        # Identity is addressed by name in the local lane's secret map and in
        # evidence, so a scan cannot hold two identities with the same name.
        UniqueConstraint("scan_id", "name", name="uq_credential_profiles_scan_name"),
    )

    id: Mapped[uuid.UUID] = uuid_pk()
    scan_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("scans.id", ondelete="CASCADE"), index=True
    )
    name: Mapped[str] = mapped_column(String(120))
    # Free-form role label ('user', 'admin', ...) used to order privilege.
    role: Mapped[str] = mapped_column(String(60))
    # Explicit privilege rank (higher = more privileged). NULL means infer it
    # from ``role`` — fine for user/admin, useless for viewer/editor/owner.
    privilege: Mapped[int | None] = mapped_column(Integer, nullable=True)
    # The tenant (workspace, organisation, account) the identity belongs to.
    # NULL is undeclared: object-level checks then cannot tell two keys of one
    # workspace from two workspaces, and pair by privilege alone.
    tenant: Mapped[str | None] = mapped_column(String(120), nullable=True)
    auth_type: Mapped[AuthType] = mapped_column(Enum(AuthType, name="auth_type"))
    # For header/api_key auth: which header to send; for query/cookie, the
    # parameter or cookie name. Null for bearer/basic.
    header_name: Mapped[str | None] = mapped_column(String(120), nullable=True)
    # Encrypted secret (Fernet). Never serialized out. For a non-static grant it
    # holds the grant's sensitive material (client_secret / password); otherwise
    # it holds the token/value sent as-is. Empty for a local-only identity.
    secret_ref: Mapped[str] = mapped_column(String(1024))
    # A local-only identity's secret never reaches the server: `aidetector run
    # --local` supplies it to its own runner container. The server knows only
    # the shape, so a server-side run leaves the identity out.
    local_only: Mapped[bool] = mapped_column(
        Boolean, default=False, server_default=false(), nullable=False
    )
    # Token-minting grant. ``static`` (default) means secret_ref is the token.
    grant_type: Mapped[GrantType] = mapped_column(
        Enum(GrantType, name="grant_type"),
        default=GrantType.static,
        server_default=GrantType.static.value,
        nullable=False,
    )
    # The auth endpoint a non-static grant POSTs to (token URL / login URL).
    token_url: Mapped[str | None] = mapped_column(String(2048), nullable=True)
    # Non-secret grant parameters (client_id, username, scope, field names,
    # body format, cookie name). The sensitive half lives in secret_ref.
    grant_params: Mapped[dict] = mapped_column(JSONB, default=dict, server_default="{}")
    refresh_url: Mapped[str | None] = mapped_column(String(2048), nullable=True)
    refresh_secret_ref: Mapped[str | None] = mapped_column(String(1024), nullable=True)
    refresh_token_field: Mapped[str] = mapped_column(
        String(120), default="refresh_token", nullable=False
    )
    access_token_field: Mapped[str] = mapped_column(
        String(120), default="access_token", nullable=False
    )
    # When the identity was added: one half of the pilot's setup timing.
    created_at: Mapped[datetime] = created_at_col()

    scan = relationship("Scan", back_populates="credential_profiles")

    @property
    def has_refresh_secret(self) -> bool:
        return bool(self.refresh_secret_ref)
