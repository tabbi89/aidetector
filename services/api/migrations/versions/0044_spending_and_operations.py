"""spending budgets, queue timing and check timings

Revision ID: 0044
Revises: 0043
Create Date: 2026-10-17 12:20:00.000000
"""
from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = '0044'
down_revision: str | None = '0043'
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column(
        'scan_runs',
        sa.Column('queued_at', sa.DateTime(timezone=True), nullable=True),
    )
    op.add_column(
        'scan_runs',
        sa.Column('claimed_at', sa.DateTime(timezone=True), nullable=True),
    )
    op.add_column(
        'scan_runs',
        sa.Column(
            'check_timings',
            postgresql.JSONB(astext_type=sa.Text()),
            server_default='{}',
            nullable=False,
        ),
    )
    op.add_column(
        'scans',
        sa.Column('queued_at', sa.DateTime(timezone=True), nullable=True),
    )
    op.add_column(
        'scans',
        sa.Column('claimed_at', sa.DateTime(timezone=True), nullable=True),
    )
    op.add_column(
        'tenants', sa.Column('ai_monthly_micros', sa.BigInteger(), nullable=True)
    )
    op.add_column(
        'tenants', sa.Column('ai_per_scan_micros', sa.BigInteger(), nullable=True)
    )
    op.add_column(
        'tenants', sa.Column('max_concurrent_runs', sa.Integer(), nullable=True)
    )
    op.add_column(
        'tenants', sa.Column('max_queued_runs', sa.Integer(), nullable=True)
    )
    op.add_column(
        'tenants', sa.Column('scans_per_day', sa.Integer(), nullable=True)
    )


def downgrade() -> None:
    op.drop_column('tenants', 'scans_per_day')
    op.drop_column('tenants', 'max_queued_runs')
    op.drop_column('tenants', 'max_concurrent_runs')
    op.drop_column('tenants', 'ai_per_scan_micros')
    op.drop_column('tenants', 'ai_monthly_micros')
    op.drop_column('scans', 'claimed_at')
    op.drop_column('scans', 'queued_at')
    op.drop_column('scan_runs', 'check_timings')
    op.drop_column('scan_runs', 'claimed_at')
    op.drop_column('scan_runs', 'queued_at')
