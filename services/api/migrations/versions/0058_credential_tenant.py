"""credential_profiles.tenant: the workspace an identity belongs to

Revision ID: 0058
Revises: 0057
Create Date: 2026-10-19 22:30:00.000000
"""
from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = '0058'
down_revision: str | None = '0057'
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    # NULL keeps the old behaviour: identities are paired by privilege alone.
    op.add_column(
        'credential_profiles', sa.Column('tenant', sa.String(length=120), nullable=True)
    )


def downgrade() -> None:
    op.drop_column('credential_profiles', 'tenant')
