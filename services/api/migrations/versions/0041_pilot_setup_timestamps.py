"""pilot setup timestamps

Revision ID: 0041
Revises: 0040
Create Date: 2026-10-17 13:00:00.000000
"""
from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = '0041'
down_revision: str | None = '0040'
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    # Setup timing starts at the scan's creation and needs the moment its spec
    # first parsed; the identity timestamps are the other half of that funnel.
    op.add_column(
        'scans',
        sa.Column('spec_uploaded_at', sa.DateTime(timezone=True), nullable=True),
    )
    op.add_column(
        'credential_profiles',
        sa.Column(
            'created_at',
            sa.DateTime(timezone=True),
            server_default=sa.text('now()'),
            nullable=False,
        ),
    )


def downgrade() -> None:
    op.drop_column('credential_profiles', 'created_at')
    op.drop_column('scans', 'spec_uploaded_at')
