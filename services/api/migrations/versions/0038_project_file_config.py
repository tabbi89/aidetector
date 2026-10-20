"""project file config: scans.managed_config, scan_runs.config_source

Revision ID: 0038
Revises: 0037
Create Date: 2026-10-16 20:10:00.000000
"""
from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = '0038'
down_revision: str | None = '0037'
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    # Both default to {} — "the web owns everything" — so existing rows need no
    # backfill and read exactly as they did before.
    op.add_column(
        'scans',
        sa.Column(
            'managed_config', postgresql.JSONB(astext_type=sa.Text()),
            server_default='{}', nullable=False,
        ),
    )
    op.add_column(
        'scan_runs',
        sa.Column(
            'config_source', postgresql.JSONB(astext_type=sa.Text()),
            server_default='{}', nullable=False,
        ),
    )


def downgrade() -> None:
    op.drop_column('scan_runs', 'config_source')
    op.drop_column('scans', 'managed_config')
