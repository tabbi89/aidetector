"""initial scan spine: scans + operations

Revision ID: 0001
Revises:
Create Date: 2026-08-29
"""
from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0001"
down_revision: str | None = None
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "scans",
        sa.Column("id", sa.Uuid(), primary_key=True),
        sa.Column("target_base_url", sa.String(length=2048), nullable=False),
        sa.Column(
            "status",
            sa.Enum(
                "draft",
                "queued",
                "running",
                "completed",
                "failed",
                "cancelled",
                name="scan_status",
            ),
            nullable=False,
            server_default="draft",
        ),
        sa.Column("cost_cents", sa.Integer(), nullable=False, server_default="0"),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        ),
    )
    op.create_table(
        "operations",
        sa.Column("id", sa.Uuid(), primary_key=True),
        sa.Column("scan_id", sa.Uuid(), nullable=False),
        sa.Column("method", sa.String(length=10), nullable=False),
        sa.Column("path", sa.String(length=2048), nullable=False),
        sa.Column(
            "params",
            postgresql.JSONB(astext_type=sa.Text()),
            nullable=False,
            server_default="{}",
        ),
        sa.Column("auth_scope", sa.String(length=255), nullable=True),
        sa.ForeignKeyConstraint(["scan_id"], ["scans.id"], ondelete="CASCADE"),
    )
    op.create_index("ix_operations_scan_id", "operations", ["scan_id"])


def downgrade() -> None:
    op.drop_index("ix_operations_scan_id", table_name="operations")
    op.drop_table("operations")
    op.drop_table("scans")
    sa.Enum(name="scan_status").drop(op.get_bind(), checkfirst=True)
