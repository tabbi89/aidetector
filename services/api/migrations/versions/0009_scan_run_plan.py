"""add scan_runs.plan

Optional AI pre-scan plan for a run — per-operation risk priority + rationale the
planner produced to order the scan. Existing rows default to an empty list.

Revision ID: 0009
Revises: 0008
Create Date: 2026-08-30 08:00:00.000000
"""
from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects.postgresql import JSONB

revision: str = "0009"
down_revision: str | None = "0008"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column(
        "scan_runs",
        sa.Column(
            "plan",
            JSONB(),
            nullable=False,
            server_default=sa.text("'[]'::jsonb"),
        ),
    )


def downgrade() -> None:
    op.drop_column("scan_runs", "plan")
