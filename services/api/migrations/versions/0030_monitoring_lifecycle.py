"""Complete passive evidence source and monitoring lifecycle storage."""

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects.postgresql import JSONB

revision = "0030"
down_revision = "0029"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("infrastructure_monitors", sa.Column("scan_id", sa.Uuid(), nullable=True))
    op.create_foreign_key(
        "fk_monitor_scan",
        "infrastructure_monitors",
        "scans",
        ["scan_id"],
        ["id"],
        ondelete="SET NULL",
    )
    for col in [
        sa.Column("schedule_enabled", sa.Boolean(), nullable=False, server_default="false"),
        sa.Column("retention_days", sa.Integer(), nullable=False, server_default="90"),
        sa.Column("context", JSONB(), nullable=False, server_default="{}"),
        sa.Column("triage", JSONB(), nullable=False, server_default="{}"),
    ]:
        op.add_column("infrastructure_monitors", col)
    for col in [
        sa.Column("state", sa.String(24), nullable=False, server_default="no_data"),
        sa.Column("error_code", sa.String(40)),
        sa.Column("claim", sa.Uuid()),
        sa.Column("scope_revision", sa.String(64), nullable=False, server_default=""),
        sa.Column("correlations", JSONB(), nullable=False, server_default="[]"),
    ]:
        op.add_column("monitoring_runs", col)
    for col in [
        sa.Column("config", JSONB(), nullable=False, server_default="{}"),
        sa.Column("secret_ref", sa.Text()),
        sa.Column("error_code", sa.String(40)),
        sa.Column("watermark", sa.Date()),
    ]:
        op.add_column("evidence_sources", col)
    op.create_table(
        "evidence_audit",
        sa.Column("id", sa.Uuid(), primary_key=True),
        sa.Column("tenant_id", sa.String(120), nullable=False),
        sa.Column(
            "source_id",
            sa.Uuid(),
            sa.ForeignKey("evidence_sources.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("action", sa.String(32), nullable=False),
        sa.Column("outcome", sa.String(40), nullable=False),
        sa.Column(
            "created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()
        ),
    )
    op.create_index("ix_evidence_audit_tenant_id", "evidence_audit", ["tenant_id"])
    op.create_table(
        "monitoring_alerts",
        sa.Column("id", sa.Uuid(), primary_key=True),
        sa.Column(
            "monitor_id",
            sa.Uuid(),
            sa.ForeignKey("infrastructure_monitors.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("observation_date", sa.Date(), nullable=False),
        sa.Column("state", sa.String(24), nullable=False),
        sa.Column("acknowledged", sa.Boolean(), nullable=False, server_default="false"),
        sa.Column(
            "created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()
        ),
    )
    op.create_index("ix_monitoring_alerts_monitor_id", "monitoring_alerts", ["monitor_id"])


def downgrade() -> None:
    op.drop_table("monitoring_alerts")
    op.drop_table("evidence_audit")
    for name in ["config", "secret_ref", "error_code", "watermark"]:
        op.drop_column("evidence_sources", name)
    for name in ["state", "error_code", "claim", "scope_revision", "correlations"]:
        op.drop_column("monitoring_runs", name)
    op.drop_constraint("fk_monitor_scan", "infrastructure_monitors", type_="foreignkey")
    for name in ["scan_id", "schedule_enabled", "retention_days", "context", "triage"]:
        op.drop_column("infrastructure_monitors", name)
