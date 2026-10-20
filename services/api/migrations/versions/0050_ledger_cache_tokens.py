"""token ledger records prompt-cache tokens

Revision ID: 0050
Revises: 0049
Create Date: 2026-10-17 21:00:00.000000

The anthropic agent planner's turns are mostly prompt-cache reads and writes,
which the ledger dropped, so its recorded spend was a fraction of the bill.
Existing rows had none recorded; they keep zero.
"""
from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = '0050'
down_revision: str | None = '0049'
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column(
        'token_ledger',
        sa.Column('cache_read_tokens', sa.BigInteger(), server_default='0', nullable=False),
    )
    op.add_column(
        'token_ledger',
        sa.Column('cache_write_tokens', sa.BigInteger(), server_default='0', nullable=False),
    )


def downgrade() -> None:
    op.drop_column('token_ledger', 'cache_write_tokens')
    op.drop_column('token_ledger', 'cache_read_tokens')
