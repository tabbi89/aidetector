"""scan event sequence

Revision ID: 0045
Revises: 0044
Create Date: 2026-10-17 13:39:00.000000
"""
from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = '0045'
down_revision: str | None = '0044'
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    # Events written in one transaction share created_at; the identity column
    # preserves the order they were appended so a bounded latest-page read can
    # reproduce the log exactly.
    op.add_column(
        'scan_events',
        sa.Column(
            'seq', sa.BigInteger(), sa.Identity(always=False), nullable=False
        ),
    )
    op.create_index(
        op.f('ix_scan_events_seq'), 'scan_events', ['seq'], unique=False
    )


def downgrade() -> None:
    op.drop_index(op.f('ix_scan_events_seq'), table_name='scan_events')
    op.drop_column('scan_events', 'seq')
