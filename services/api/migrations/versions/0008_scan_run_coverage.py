"""add scan_runs.coverage

Per-operation activity for a run — one row per endpoint with the requests fired,
the checks that touched it, and its finding count. Existing rows default to an
empty list (older runs simply have no coverage record).

Revision ID: 0008
Revises: 0007
Create Date: 2026-08-30 07:00:00.000000
"""
from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects.postgresql import JSONB

revision: str = "0008"
down_revision: str | None = "0007"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column(
        "scan_runs",
        sa.Column(
            "coverage",
            JSONB(),
            nullable=False,
            server_default=sa.text("'[]'::jsonb"),
        ),
    )


def downgrade() -> None:
    op.drop_column("scan_runs", "coverage")
