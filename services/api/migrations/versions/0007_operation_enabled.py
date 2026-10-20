"""add operations.enabled

Per-operation opt-out so the UI can exclude endpoints from a run without
deleting them. Existing rows default to enabled (server_default true).

Revision ID: 0007
Revises: cab07b2a583f
Create Date: 2026-08-30 00:00:00.000000
"""
from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0007"
down_revision: str | None = "cab07b2a583f"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column(
        "operations",
        sa.Column(
            "enabled",
            sa.Boolean(),
            nullable=False,
            server_default=sa.true(),
        ),
    )


def downgrade() -> None:
    op.drop_column("operations", "enabled")
