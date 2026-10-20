"""finding remediation + references

Findings carry the change to make, not just the problem. Text is filled from the
per-check catalogue in ``app/engine/remediation.py`` as findings are recorded.

Existing rows are left empty rather than back-filled: remediation is shaped by a
finding's own evidence, and re-running a scan fills it correctly.

Revision ID: 0012
Revises: 0011
"""
from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0012"
down_revision: str | None = "0011"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column(
        "findings",
        sa.Column("remediation", sa.Text(), server_default="", nullable=False),
    )
    op.add_column(
        "findings",
        sa.Column(
            "references",
            postgresql.JSONB(astext_type=sa.Text()),
            server_default="[]",
            nullable=False,
        ),
    )


def downgrade() -> None:
    op.drop_column("findings", "references")
    op.drop_column("findings", "remediation")
