"""credential_profiles.privilege, and API keys sent in the query string or a cookie

Revision ID: 0057
Revises: 0056
Create Date: 2026-10-18 19:30:00.000000
"""
from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = '0057'
down_revision: str | None = '0056'
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    # Adding a value is allowed inside a transaction (PostgreSQL 12+) as long as
    # this transaction does not also use it, and nothing here does.
    op.execute("ALTER TYPE auth_type ADD VALUE IF NOT EXISTS 'query' BEFORE 'none'")
    op.execute("ALTER TYPE auth_type ADD VALUE IF NOT EXISTS 'cookie' BEFORE 'none'")
    # Explicit privilege rank. NULL keeps the old behaviour: rank inferred from
    # the role name.
    op.add_column('credential_profiles', sa.Column('privilege', sa.Integer(), nullable=True))


def downgrade() -> None:
    op.drop_column('credential_profiles', 'privilege')
    # PostgreSQL cannot drop an enum value. Rows using one would no longer load
    # under the older code, so fold them into the nearest older channel: both
    # carried a raw key, which ``api_key`` sends as a header.
    op.execute(
        "UPDATE credential_profiles SET auth_type = 'api_key' "
        "WHERE auth_type IN ('query', 'cookie')"
    )
