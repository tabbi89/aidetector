"""Track contract provenance and short-window monitoring results."""

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects.postgresql import JSONB

revision = "0032"
down_revision = "0031"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "scans", sa.Column("spec_origin", sa.String(16), nullable=False, server_default="unknown")
    )
    op.create_table(
        "monitoring_rapid_runs",
        sa.Column("id", sa.Uuid(), primary_key=True),
        sa.Column(
            "monitor_id", sa.Uuid(),
            sa.ForeignKey("infrastructure_monitors.id", ondelete="CASCADE"), nullable=False,
        ),
        sa.Column("window_start", sa.DateTime(timezone=True), nullable=False),
        sa.Column("window_end", sa.DateTime(timezone=True), nullable=False),
        sa.Column("observations", JSONB(), nullable=False, server_default="[]"),
        sa.Column("skipped", JSONB(), nullable=False, server_default="{}"),
        sa.Column("waf_count", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("application_count", sa.Integer(), nullable=False, server_default="0"),
        sa.Column(
            "created_at", sa.DateTime(timezone=True),
            nullable=False, server_default=sa.func.now(),
        ),
        sa.UniqueConstraint(
            "monitor_id", "window_start", "window_end", name="uq_monitoring_rapid_window"
        ),
    )
    op.create_index("ix_monitoring_rapid_runs_monitor_id", "monitoring_rapid_runs", ["monitor_id"])


def downgrade() -> None:
    op.drop_index("ix_monitoring_rapid_runs_monitor_id", table_name="monitoring_rapid_runs")
    op.drop_table("monitoring_rapid_runs")
    op.drop_column("scans", "spec_origin")
