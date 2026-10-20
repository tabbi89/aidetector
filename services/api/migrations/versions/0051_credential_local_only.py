"""credential profiles can be local-only

Revision ID: 0051
Revises: 0050
Create Date: 2026-10-17 22:00:00.000000

A local run supplies each identity's secret from the CLI machine, yet the
server could only create an identity with a secret, so the secret reached the
server once anyway. A local-only identity stores the shape alone. Existing rows
all carry a secret, so they default to false.
"""
from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = '0051'
down_revision: str | None = '0050'
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column(
        'credential_profiles',
        sa.Column('local_only', sa.Boolean(), server_default=sa.false(), nullable=False),
    )


def downgrade() -> None:
    op.drop_column('credential_profiles', 'local_only')
