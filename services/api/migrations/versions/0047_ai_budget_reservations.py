"""pre-call AI budget reservations

Revision ID: 0047
Revises: 0046
Create Date: 2026-10-17 18:20:00.000000
"""
from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = '0047'
down_revision: str | None = '0046'
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    # The ledger is written after a call returns; without a claimed worst-case
    # row two concurrent callers both see the same remaining allowance.
    op.create_table(
        'ai_budget_reservations',
        sa.Column('id', sa.Uuid(), primary_key=True),
        sa.Column(
            'tenant_slug',
            sa.String(length=120),
            sa.ForeignKey('tenants.slug', ondelete='CASCADE'),
            nullable=False,
        ),
        sa.Column(
            'scan_id',
            sa.Uuid(),
            sa.ForeignKey('scans.id', ondelete='CASCADE'),
            nullable=False,
        ),
        sa.Column('phase', sa.String(length=30), nullable=False),
        sa.Column('reserved_micros', sa.BigInteger(), nullable=False),
        sa.Column(
            'created_at',
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.func.now(),
        ),
    )
    op.create_index(
        'ix_ai_budget_reservations_tenant_slug',
        'ai_budget_reservations',
        ['tenant_slug'],
    )
    op.create_index(
        'ix_ai_budget_reservations_scan_id',
        'ai_budget_reservations',
        ['scan_id'],
    )


def downgrade() -> None:
    op.drop_index(
        'ix_ai_budget_reservations_scan_id',
        table_name='ai_budget_reservations',
    )
    op.drop_index(
        'ix_ai_budget_reservations_tenant_slug',
        table_name='ai_budget_reservations',
    )
    op.drop_table('ai_budget_reservations')
