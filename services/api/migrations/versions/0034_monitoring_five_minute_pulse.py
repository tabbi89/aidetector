"""Store a value-free five-minute pulse beside rolling monitoring windows."""

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects.postgresql import JSONB

revision = "0034"
down_revision = "0033"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "monitoring_rapid_runs",
        sa.Column("pulse", JSONB(), nullable=False, server_default="{}"),
    )


def downgrade() -> None:
    op.drop_column("monitoring_rapid_runs", "pulse")
