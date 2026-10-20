"""adjudication cache: cached AI remediation

When the adjudicator confirms a finding it can return a fix specific to that
finding's evidence, which replaces the static catalogue remediation. Caching it
alongside the verdict means a re-scan reuses the better text without re-spending
tokens. Existing rows get an empty string (the static remediation stands).

Revision ID: 0015
Revises: 0014
"""
from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0015"
down_revision: str | None = "0014"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column(
        "adjudication_cache",
        sa.Column("remediation", sa.Text(), server_default="", nullable=False),
    )


def downgrade() -> None:
    op.drop_column("adjudication_cache", "remediation")
