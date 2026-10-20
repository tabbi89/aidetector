"""Store the latest on-demand AI traffic briefing on a monitor."""

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects.postgresql import JSONB

revision = "0031"
down_revision = "0030"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "infrastructure_monitors",
        sa.Column("ai_briefing", JSONB(), nullable=False, server_default="{}"),
    )


def downgrade() -> None:
    op.drop_column("infrastructure_monitors", "ai_briefing")
