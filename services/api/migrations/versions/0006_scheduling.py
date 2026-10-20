"""scheduling: scan.schedule_minutes + next_run_at

Revision ID: 0006
Revises: 0005
Create Date: 2026-08-29
"""
from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0006"
down_revision: str | None = "0005"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column("scans", sa.Column("schedule_minutes", sa.Integer(), nullable=True))
    op.add_column(
        "scans",
        sa.Column("next_run_at", sa.DateTime(timezone=True), nullable=True),
    )
    op.create_index("ix_scans_next_run_at", "scans", ["next_run_at"])


def downgrade() -> None:
    op.drop_index("ix_scans_next_run_at", table_name="scans")
    op.drop_column("scans", "next_run_at")
    op.drop_column("scans", "schedule_minutes")
