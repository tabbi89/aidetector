"""credential token-minting grant

Lets a credential mint its own token at scan time (OAuth client_credentials /
password, or a cookie login) instead of carrying a static bearer that expires —
what keeps a scheduled scan from rotting, and lets the scanner test APIs whose
tokens are short-lived.

Existing rows default to ``static`` (the token *is* the stored secret), which is
exactly today's behaviour, so nothing changes for them.

Revision ID: 0014
Revises: 0013
"""
from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0014"
down_revision: str | None = "0013"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

_GRANT = postgresql.ENUM(
    "static", "client_credentials", "password", "cookie",
    name="grant_type", create_type=False,
)


def upgrade() -> None:
    _GRANT.create(op.get_bind(), checkfirst=True)
    op.add_column(
        "credential_profiles",
        sa.Column("grant_type", _GRANT, server_default="static", nullable=False),
    )
    op.add_column(
        "credential_profiles",
        sa.Column("token_url", sa.String(length=2048), nullable=True),
    )
    op.add_column(
        "credential_profiles",
        sa.Column(
            "grant_params",
            postgresql.JSONB(astext_type=sa.Text()),
            server_default="{}",
            nullable=False,
        ),
    )


def downgrade() -> None:
    op.drop_column("credential_profiles", "grant_params")
    op.drop_column("credential_profiles", "token_url")
    op.drop_column("credential_profiles", "grant_type")
    _GRANT.drop(op.get_bind(), checkfirst=True)
