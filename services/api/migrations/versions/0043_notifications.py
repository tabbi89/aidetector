"""notification endpoints and the delivery outbox

Revision ID: 0043
Revises: 0042
Create Date: 2026-10-17 12:07:00.000000
"""
from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = '0043'
down_revision: str | None = '0042'
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        'notification_endpoints',
        sa.Column('id', sa.Uuid(), nullable=False),
        sa.Column('tenant_slug', sa.String(length=120), nullable=False),
        sa.Column('kind', sa.String(length=16), nullable=False),
        sa.Column('destination_ref', sa.String(length=4096), nullable=False),
        sa.Column('destination_hint', sa.String(length=512), nullable=False),
        sa.Column('signing_secret_ref', sa.String(length=4096), nullable=True),
        sa.Column(
            'events',
            postgresql.JSONB(astext_type=sa.Text()),
            server_default='[]',
            nullable=False,
        ),
        sa.Column(
            'min_severity', sa.String(length=20), server_default='medium', nullable=False
        ),
        sa.Column(
            'active', sa.Boolean(), server_default='true', nullable=False
        ),
        sa.Column('created_by_user_id', sa.Uuid(), nullable=True),
        sa.Column(
            'created_at',
            sa.DateTime(timezone=True),
            server_default=sa.text('now()'),
            nullable=False,
        ),
        sa.CheckConstraint(
            "kind IN ('webhook', 'slack')", name='ck_notification_endpoints_kind'
        ),
        sa.CheckConstraint(
            "min_severity IN ('info', 'low', 'medium', 'high', 'critical')",
            name='ck_notification_endpoints_severity',
        ),
        sa.ForeignKeyConstraint(
            ['created_by_user_id'], ['users.id'], ondelete='SET NULL'
        ),
        sa.ForeignKeyConstraint(
            ['tenant_slug'], ['tenants.slug'], ondelete='CASCADE'
        ),
        sa.PrimaryKeyConstraint('id'),
    )
    op.create_index(
        op.f('ix_notification_endpoints_tenant_slug'),
        'notification_endpoints',
        ['tenant_slug'],
        unique=False,
    )

    op.create_table(
        'notification_deliveries',
        sa.Column('id', sa.Uuid(), nullable=False),
        sa.Column('tenant_slug', sa.String(length=120), nullable=False),
        sa.Column('endpoint_id', sa.Uuid(), nullable=False),
        sa.Column('event_type', sa.String(length=40), nullable=False),
        sa.Column('dedup_key', sa.String(length=255), nullable=False),
        sa.Column(
            'payload',
            postgresql.JSONB(astext_type=sa.Text()),
            server_default='{}',
            nullable=False,
        ),
        sa.Column('state', sa.String(length=16), server_default='pending', nullable=False),
        sa.Column('attempts', sa.Integer(), server_default='0', nullable=False),
        sa.Column(
            'next_attempt_at',
            sa.DateTime(timezone=True),
            server_default=sa.text('now()'),
            nullable=False,
        ),
        sa.Column('last_error', sa.Text(), nullable=True),
        sa.Column(
            'created_at',
            sa.DateTime(timezone=True),
            server_default=sa.text('now()'),
            nullable=False,
        ),
        sa.Column('delivered_at', sa.DateTime(timezone=True), nullable=True),
        sa.CheckConstraint(
            "state IN ('pending', 'delivering', 'delivered', 'failed', 'dead')",
            name='ck_notification_deliveries_state',
        ),
        sa.ForeignKeyConstraint(
            ['endpoint_id'], ['notification_endpoints.id'], ondelete='CASCADE'
        ),
        sa.ForeignKeyConstraint(
            ['tenant_slug'], ['tenants.slug'], ondelete='CASCADE'
        ),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint(
            'endpoint_id',
            'dedup_key',
            name='uq_notification_deliveries_endpoint_dedup',
        ),
    )
    op.create_index(
        op.f('ix_notification_deliveries_endpoint_id'),
        'notification_deliveries',
        ['endpoint_id'],
        unique=False,
    )
    op.create_index(
        op.f('ix_notification_deliveries_next_attempt_at'),
        'notification_deliveries',
        ['next_attempt_at'],
        unique=False,
    )
    op.create_index(
        op.f('ix_notification_deliveries_tenant_slug'),
        'notification_deliveries',
        ['tenant_slug'],
        unique=False,
    )


def downgrade() -> None:
    op.drop_index(
        op.f('ix_notification_deliveries_tenant_slug'),
        table_name='notification_deliveries',
    )
    op.drop_index(
        op.f('ix_notification_deliveries_next_attempt_at'),
        table_name='notification_deliveries',
    )
    op.drop_index(
        op.f('ix_notification_deliveries_endpoint_id'),
        table_name='notification_deliveries',
    )
    op.drop_table('notification_deliveries')
    op.drop_index(
        op.f('ix_notification_endpoints_tenant_slug'),
        table_name='notification_endpoints',
    )
    op.drop_table('notification_endpoints')
