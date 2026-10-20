"""Opt a monitor into scheduled short-window WAF reads."""

import sqlalchemy as sa
from alembic import op

revision = "0033"
down_revision = "0032"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "infrastructure_monitors",
        sa.Column("rapid_enabled", sa.Boolean(), nullable=False, server_default="false"),
    )


def downgrade() -> None:
    op.drop_column("infrastructure_monitors", "rapid_enabled")
