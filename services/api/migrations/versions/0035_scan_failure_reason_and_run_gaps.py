"""Record why a scan failed and what a run was asked to do but did not."""

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects.postgresql import JSONB

revision = "0035"
down_revision = "0034"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("scans", sa.Column("failure_reason", sa.Text(), nullable=True))
    op.add_column(
        "scan_runs",
        sa.Column("gaps", JSONB(), nullable=False, server_default="{}"),
    )


def downgrade() -> None:
    op.drop_column("scan_runs", "gaps")
    op.drop_column("scans", "failure_reason")
