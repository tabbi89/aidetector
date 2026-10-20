"""auth_throttle: fixed-window counters for sign-in and sign-up

Revision ID: 0054
Revises: 0053
Create Date: 2026-10-18 20:00:00.000000
"""
from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = '0054'
down_revision: str | None = '0053'
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        'auth_throttle',
        sa.Column('bucket', sa.String(120), nullable=False),
        sa.Column('count', sa.Integer(), nullable=False),
        sa.Column('window_start', sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint('bucket'),
    )
    op.create_index(
        'ix_auth_throttle_window_start', 'auth_throttle', ['window_start']
    )


def downgrade() -> None:
    op.drop_index('ix_auth_throttle_window_start', table_name='auth_throttle')
    op.drop_table('auth_throttle')
