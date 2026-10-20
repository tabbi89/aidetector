"""team identity: tenants, users, memberships, tokens and the audit log

Revision ID: 0042
Revises: 0041
Create Date: 2026-10-17 11:45:00.000000
"""
from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = '0042'
down_revision: str | None = '0041'
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        'tenants',
        sa.Column('slug', sa.String(length=120), nullable=False),
        sa.Column('name', sa.String(length=200), nullable=False),
        sa.Column('plan', sa.String(length=20), server_default='free', nullable=False),
        sa.Column(
            'created_at',
            sa.DateTime(timezone=True),
            server_default=sa.text('now()'),
            nullable=False,
        ),
        sa.CheckConstraint("plan IN ('free', 'premium')", name='ck_tenants_plan'),
        sa.PrimaryKeyConstraint('slug'),
    )
    # The historical rows use tenant_id='default'; keep that workspace addressable
    # before the first member is invited.
    op.execute(
        sa.text(
            "INSERT INTO tenants (slug, name, plan) "
            "VALUES ('default', 'Default workspace', 'free') "
            "ON CONFLICT (slug) DO NOTHING"
        )
    )

    op.create_table(
        'users',
        sa.Column('id', sa.Uuid(), nullable=False),
        sa.Column('email', sa.String(length=320), nullable=False),
        sa.Column('display_name', sa.String(length=120), nullable=False),
        sa.Column(
            'created_at',
            sa.DateTime(timezone=True),
            server_default=sa.text('now()'),
            nullable=False,
        ),
        sa.Column('disabled_at', sa.DateTime(timezone=True), nullable=True),
        sa.PrimaryKeyConstraint('id'),
    )
    op.create_index(op.f('ix_users_email'), 'users', ['email'], unique=True)

    op.create_table(
        'memberships',
        sa.Column('id', sa.Uuid(), nullable=False),
        sa.Column('tenant_slug', sa.String(length=120), nullable=False),
        sa.Column('user_id', sa.Uuid(), nullable=False),
        sa.Column('role', sa.String(length=20), server_default='viewer', nullable=False),
        sa.Column(
            'created_at',
            sa.DateTime(timezone=True),
            server_default=sa.text('now()'),
            nullable=False,
        ),
        sa.CheckConstraint(
            "role IN ('admin', 'analyst', 'viewer')", name='ck_memberships_role'
        ),
        sa.ForeignKeyConstraint(['tenant_slug'], ['tenants.slug'], ondelete='CASCADE'),
        sa.ForeignKeyConstraint(['user_id'], ['users.id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('tenant_slug', 'user_id', name='uq_memberships_tenant_user'),
    )
    op.create_index(
        op.f('ix_memberships_tenant_slug'), 'memberships', ['tenant_slug'], unique=False
    )
    op.create_index(
        op.f('ix_memberships_user_id'), 'memberships', ['user_id'], unique=False
    )

    op.create_table(
        'api_tokens',
        sa.Column('id', sa.Uuid(), nullable=False),
        sa.Column('membership_id', sa.Uuid(), nullable=False),
        sa.Column('token_hash', sa.String(length=64), nullable=False),
        sa.Column('prefix', sa.String(length=12), nullable=False),
        sa.Column('last4', sa.String(length=4), nullable=False),
        sa.Column('label', sa.String(length=120), server_default='', nullable=False),
        sa.Column(
            'created_at',
            sa.DateTime(timezone=True),
            server_default=sa.text('now()'),
            nullable=False,
        ),
        sa.Column('last_used_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('expires_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('revoked_at', sa.DateTime(timezone=True), nullable=True),
        sa.ForeignKeyConstraint(['membership_id'], ['memberships.id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id'),
    )
    op.create_index(
        op.f('ix_api_tokens_membership_id'),
        'api_tokens',
        ['membership_id'],
        unique=False,
    )
    op.create_index(
        op.f('ix_api_tokens_token_hash'), 'api_tokens', ['token_hash'], unique=True
    )

    op.create_table(
        'audit_log',
        sa.Column('id', sa.Uuid(), nullable=False),
        sa.Column('tenant_slug', sa.String(length=120), nullable=False),
        sa.Column('actor_user_id', sa.Uuid(), nullable=True),
        sa.Column('action', sa.String(length=80), nullable=False),
        sa.Column('object_type', sa.String(length=40), nullable=False),
        sa.Column('object_id', sa.String(length=120), nullable=False),
        sa.Column(
            'summary',
            postgresql.JSONB(astext_type=sa.Text()),
            server_default='{}',
            nullable=False,
        ),
        sa.Column(
            'created_at',
            sa.DateTime(timezone=True),
            server_default=sa.text('now()'),
            nullable=False,
        ),
        sa.ForeignKeyConstraint(['actor_user_id'], ['users.id'], ondelete='SET NULL'),
        sa.ForeignKeyConstraint(['tenant_slug'], ['tenants.slug'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id'),
    )
    op.create_index(op.f('ix_audit_log_action'), 'audit_log', ['action'], unique=False)
    op.create_index(
        op.f('ix_audit_log_actor_user_id'), 'audit_log', ['actor_user_id'], unique=False
    )
    op.create_index(
        op.f('ix_audit_log_tenant_slug'), 'audit_log', ['tenant_slug'], unique=False
    )

    op.add_column(
        'finding_comment', sa.Column('author_user_id', sa.Uuid(), nullable=True)
    )
    op.create_index(
        op.f('ix_finding_comment_author_user_id'),
        'finding_comment',
        ['author_user_id'],
        unique=False,
    )
    op.create_foreign_key(
        'fk_finding_comment_author_user_id_users',
        'finding_comment',
        'users',
        ['author_user_id'],
        ['id'],
        ondelete='SET NULL',
    )

    op.add_column(
        'finding_work', sa.Column('owner_user_id', sa.Uuid(), nullable=True)
    )
    op.create_index(
        op.f('ix_finding_work_owner_user_id'),
        'finding_work',
        ['owner_user_id'],
        unique=False,
    )
    op.create_foreign_key(
        'fk_finding_work_owner_user_id_users',
        'finding_work',
        'users',
        ['owner_user_id'],
        ['id'],
        ondelete='SET NULL',
    )


def downgrade() -> None:
    op.drop_constraint(
        'fk_finding_work_owner_user_id_users', 'finding_work', type_='foreignkey'
    )
    op.drop_index(op.f('ix_finding_work_owner_user_id'), table_name='finding_work')
    op.drop_column('finding_work', 'owner_user_id')

    op.drop_constraint(
        'fk_finding_comment_author_user_id_users',
        'finding_comment',
        type_='foreignkey',
    )
    op.drop_index(
        op.f('ix_finding_comment_author_user_id'), table_name='finding_comment'
    )
    op.drop_column('finding_comment', 'author_user_id')

    op.drop_index(op.f('ix_audit_log_tenant_slug'), table_name='audit_log')
    op.drop_index(op.f('ix_audit_log_actor_user_id'), table_name='audit_log')
    op.drop_index(op.f('ix_audit_log_action'), table_name='audit_log')
    op.drop_table('audit_log')

    op.drop_index(op.f('ix_api_tokens_token_hash'), table_name='api_tokens')
    op.drop_index(op.f('ix_api_tokens_membership_id'), table_name='api_tokens')
    op.drop_table('api_tokens')

    op.drop_index(op.f('ix_memberships_user_id'), table_name='memberships')
    op.drop_index(op.f('ix_memberships_tenant_slug'), table_name='memberships')
    op.drop_table('memberships')

    op.drop_index(op.f('ix_users_email'), table_name='users')
    op.drop_table('users')

    op.drop_table('tenants')
