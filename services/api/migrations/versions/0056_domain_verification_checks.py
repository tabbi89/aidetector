"""domain_verifications.last_checks: each proof's outcome from the last check

Revision ID: 0056
Revises: 0055
Create Date: 2026-10-18 16:30:00.000000
"""
from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = '0056'
down_revision: str | None = '0055'
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column(
        'domain_verifications',
        sa.Column('last_checks', postgresql.JSONB(astext_type=sa.Text()), nullable=True),
    )


def downgrade() -> None:
    op.drop_column('domain_verifications', 'last_checks')
