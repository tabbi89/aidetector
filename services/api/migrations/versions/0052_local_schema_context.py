"""local-only schema context: scan_runs.schema_context, drop database_connections

Schema context moved to the CLI's local runner: the database is read on the
machine that runs ``aidetector --local`` and only the structural snapshot is
uploaded with the run. The server no longer holds a database password, so the
encrypted connections are dropped rather than migrated — there is nothing a
local run could do with a server-side secret.

Revision ID: 0052
Revises: 0051
Create Date: 2026-10-18 12:00:00.000000
"""
from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = '0052'
down_revision: str | None = '0051'
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column(
        'scan_runs',
        sa.Column(
            'schema_context', postgresql.JSONB(astext_type=sa.Text()),
            server_default='{}', nullable=False,
        ),
    )
    op.drop_table('database_connections')


def downgrade() -> None:
    # The table comes back empty: the dropped secrets are gone by design.
    op.create_table(
        'database_connections',
        sa.Column('id', sa.Uuid(), nullable=False),
        sa.Column('scan_id', sa.Uuid(), nullable=False),
        sa.Column('revision', sa.Uuid(), nullable=False),
        sa.Column('config', postgresql.JSONB(), nullable=False),
        sa.Column('secret_ref', sa.Text(), nullable=False),
        sa.Column('status', sa.String(20), nullable=False),
        sa.Column('reason', sa.String(60), nullable=True),
        sa.Column('checked_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('test_id', sa.Uuid(), nullable=True),
        sa.ForeignKeyConstraint(['scan_id'], ['scans.id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('scan_id'),
    )
    op.drop_column('scan_runs', 'schema_context')
