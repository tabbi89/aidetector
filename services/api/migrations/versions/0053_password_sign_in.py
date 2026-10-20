"""password sign-in: users.password_hash/status, api_tokens.kind

Self-service sign-up lands as a ``pending`` user with a password and no
membership; an admin approves it into the workspace. A password sign-in mints a
``session`` token — an expiring row in the same table, so every route keeps
resolving one kind of principal.

Revision ID: 0053
Revises: 0052
Create Date: 2026-10-18 18:00:00.000000
"""
from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = '0053'
down_revision: str | None = '0052'
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column(
        'users',
        sa.Column(
            'status', sa.String(20), server_default='active', nullable=False
        ),
    )
    op.add_column(
        'users', sa.Column('password_hash', sa.String(255), nullable=True)
    )
    op.create_check_constraint(
        'ck_users_status', 'users', "status IN ('active', 'pending')"
    )
    op.add_column(
        'api_tokens',
        sa.Column('kind', sa.String(20), server_default='api', nullable=False),
    )
    op.create_check_constraint(
        'ck_api_tokens_kind', 'api_tokens', "kind IN ('api', 'session')"
    )


def downgrade() -> None:
    # Sessions and unapproved sign-ups have no meaning without passwords.
    op.execute("DELETE FROM api_tokens WHERE kind = 'session'")
    op.execute("DELETE FROM users WHERE status = 'pending'")
    op.drop_constraint('ck_api_tokens_kind', 'api_tokens', type_='check')
    op.drop_column('api_tokens', 'kind')
    op.drop_constraint('ck_users_status', 'users', type_='check')
    op.drop_column('users', 'password_hash')
    op.drop_column('users', 'status')
