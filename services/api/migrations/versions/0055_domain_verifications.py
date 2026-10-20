"""domain_verifications: ownership proof for public scan targets

Revision ID: 0055
Revises: 0054
Create Date: 2026-10-18 22:00:00.000000
"""
from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = '0055'
down_revision: str | None = '0054'
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        'domain_verifications',
        sa.Column('id', sa.Uuid(), nullable=False),
        sa.Column('tenant_slug', sa.String(120), nullable=False),
        sa.Column('host', sa.String(255), nullable=False),
        sa.Column('token', sa.String(64), nullable=False),
        sa.Column('verified_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('last_checked_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('last_error', sa.String(1000), nullable=True),
        sa.Column('created_by_user_id', sa.Uuid(), nullable=True),
        sa.Column(
            'created_at',
            sa.DateTime(timezone=True),
            server_default=sa.text('now()'),
            nullable=False,
        ),
        sa.ForeignKeyConstraint(['tenant_slug'], ['tenants.slug'], ondelete='CASCADE'),
        sa.ForeignKeyConstraint(['created_by_user_id'], ['users.id'], ondelete='SET NULL'),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('tenant_slug', 'host', name='uq_domain_verifications_tenant_host'),
    )
    op.create_index(
        'ix_domain_verifications_tenant_slug', 'domain_verifications', ['tenant_slug']
    )


def downgrade() -> None:
    op.drop_index('ix_domain_verifications_tenant_slug', table_name='domain_verifications')
    op.drop_table('domain_verifications')
