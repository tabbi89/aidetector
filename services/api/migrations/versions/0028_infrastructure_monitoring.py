"""Add tenant-scoped daily infrastructure monitoring storage."""

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision = "0028"
down_revision = "0027"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "infrastructure_monitors",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("tenant_id", sa.String(length=120), nullable=False),
        sa.Column("name", sa.String(length=160), nullable=False),
        sa.Column("target_binding", sa.String(length=2048), nullable=False),
        sa.Column(
            "source_ids",
            postgresql.JSONB(astext_type=sa.Text()),
            nullable=False,
            server_default="[]",
        ),
        sa.Column("schedule_minutes", sa.Integer(), nullable=False, server_default="1440"),
        sa.Column("minimum_baseline_days", sa.Integer(), nullable=False, server_default="7"),
        sa.Column("status", sa.String(length=20), nullable=False, server_default="active"),
        sa.Column("last_observation_date", sa.Date(), nullable=True),
        sa.Column("last_run_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column(
            "created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(
        "ix_infrastructure_monitors_tenant_id",
        "infrastructure_monitors",
        ["tenant_id"],
    )
    op.create_table(
        "monitoring_runs",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("monitor_id", sa.Uuid(), nullable=False),
        sa.Column("observation_date", sa.Date(), nullable=False),
        sa.Column("status", sa.String(length=20), nullable=False, server_default="queued"),
        sa.Column("baseline_start", sa.Date(), nullable=True),
        sa.Column("baseline_end", sa.Date(), nullable=True),
        sa.Column("baseline_days_available", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("data_quality", sa.String(length=20), nullable=False, server_default="unknown"),
        sa.Column(
            "source_revisions",
            postgresql.JSONB(astext_type=sa.Text()),
            nullable=False,
            server_default="{}",
        ),
        sa.Column(
            "metrics", postgresql.JSONB(astext_type=sa.Text()), nullable=False, server_default="{}"
        ),
        sa.Column(
            "observations",
            postgresql.JSONB(astext_type=sa.Text()),
            nullable=False,
            server_default="[]",
        ),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("finished_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column(
            "created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
        sa.ForeignKeyConstraint(["monitor_id"], ["infrastructure_monitors.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("monitor_id", "observation_date", name="uq_monitoring_run_day"),
    )
    op.create_index("ix_monitoring_runs_monitor_id", "monitoring_runs", ["monitor_id"])


def downgrade() -> None:
    op.drop_index("ix_monitoring_runs_monitor_id", table_name="monitoring_runs")
    op.drop_table("monitoring_runs")
    op.drop_index("ix_infrastructure_monitors_tenant_id", table_name="infrastructure_monitors")
    op.drop_table("infrastructure_monitors")
