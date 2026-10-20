"""credential profiles

Revision ID: 0002
Revises: 0001
Create Date: 2026-08-29
"""
from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0002"
down_revision: str | None = "0001"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "credential_profiles",
        sa.Column("id", sa.Uuid(), primary_key=True),
        sa.Column("scan_id", sa.Uuid(), nullable=False),
        sa.Column("name", sa.String(length=120), nullable=False),
        sa.Column("role", sa.String(length=60), nullable=False),
        sa.Column(
            "auth_type",
            sa.Enum("bearer", "header", "api_key", "basic", "none", name="auth_type"),
            nullable=False,
        ),
        sa.Column("header_name", sa.String(length=120), nullable=True),
        sa.Column("secret_ref", sa.String(length=1024), nullable=False),
        sa.ForeignKeyConstraint(["scan_id"], ["scans.id"], ondelete="CASCADE"),
    )
    op.create_index(
        "ix_credential_profiles_scan_id", "credential_profiles", ["scan_id"]
    )


def downgrade() -> None:
    op.drop_index(
        "ix_credential_profiles_scan_id", table_name="credential_profiles"
    )
    op.drop_table("credential_profiles")
    sa.Enum(name="auth_type").drop(op.get_bind(), checkfirst=True)
