"""Record which executor ran a scan run, and a hashed per-run runner token."""

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects.postgresql import JSONB

revision = "0036"
down_revision = "0035"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "scan_runs",
        sa.Column("executor", JSONB(), nullable=False, server_default="{}"),
    )
    op.add_column(
        "scan_runs",
        sa.Column("run_token_hash", sa.String(length=64), nullable=True),
    )
    op.create_index(
        "ix_scan_runs_run_token_hash", "scan_runs", ["run_token_hash"]
    )


def downgrade() -> None:
    op.drop_index("ix_scan_runs_run_token_hash", table_name="scan_runs")
    op.drop_column("scan_runs", "run_token_hash")
    op.drop_column("scan_runs", "executor")
