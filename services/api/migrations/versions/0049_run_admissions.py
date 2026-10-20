"""one durable admission row per accepted execution

Revision ID: 0049
Revises: 0048
Create Date: 2026-10-17 20:00:00.000000

The daily allowance counted distinct ``scans`` rows queued or started today:
two runs of one scan counted once, and deleting history refunded the
allowance. Record every accepted execution instead. Today's already-started
runs are backfilled so a rollout mid-day does not reset the count.
"""
from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = '0049'
down_revision: str | None = '0048'
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        'run_admissions',
        sa.Column('id', sa.Uuid(), nullable=False),
        sa.Column('tenant_slug', sa.String(length=120), nullable=False),
        sa.Column('scan_id', sa.Uuid(), nullable=True),
        sa.Column('source', sa.String(length=20), nullable=False),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(['tenant_slug'], ['tenants.slug'], ondelete='CASCADE'),
        sa.ForeignKeyConstraint(['scan_id'], ['scans.id'], ondelete='SET NULL'),
        sa.PrimaryKeyConstraint('id'),
    )
    op.create_index('ix_run_admissions_tenant_slug', 'run_admissions', ['tenant_slug'])
    op.create_index('ix_run_admissions_scan_id', 'run_admissions', ['scan_id'])
    op.create_index('ix_run_admissions_created_at', 'run_admissions', ['created_at'])
    op.execute(
        """
        INSERT INTO run_admissions (id, tenant_slug, scan_id, source, created_at)
        SELECT gen_random_uuid(), s.tenant_id, r.scan_id, 'manual',
               COALESCE(r.queued_at, r.started_at)
          FROM scan_runs AS r
          JOIN scans AS s ON s.id = r.scan_id
          JOIN tenants AS t ON t.slug = s.tenant_id
         WHERE COALESCE(r.queued_at, r.started_at) >= now() - interval '2 days'
        """
    )
    # A scan queued right now has no run row yet: it is an execution too.
    op.execute(
        """
        INSERT INTO run_admissions (id, tenant_slug, scan_id, source, created_at)
        SELECT gen_random_uuid(), s.tenant_id, s.id, 'manual', s.queued_at
          FROM scans AS s
          JOIN tenants AS t ON t.slug = s.tenant_id
         WHERE s.status = 'queued' AND s.queued_at IS NOT NULL
        """
    )


def downgrade() -> None:
    op.drop_index('ix_run_admissions_created_at', table_name='run_admissions')
    op.drop_index('ix_run_admissions_scan_id', table_name='run_admissions')
    op.drop_index('ix_run_admissions_tenant_slug', table_name='run_admissions')
    op.drop_table('run_admissions')
