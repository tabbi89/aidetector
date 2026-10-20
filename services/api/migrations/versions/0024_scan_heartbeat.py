"""Scan liveness heartbeat, so a scan whose worker died can be recovered.

Scans already queued or running when this ships get ``now()``: that gives an
in-flight run one full stale window to finish instead of being reaped the
moment the new reaper first looks.

Revision ID: 0024
Revises: 0023
"""
import sqlalchemy as sa
from alembic import op

revision = "0024"
down_revision = "0023"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("scans", sa.Column("heartbeat_at", sa.DateTime(timezone=True), nullable=True))
    op.execute("UPDATE scans SET heartbeat_at = now() WHERE status IN ('queued', 'running')")


def downgrade() -> None:
    op.drop_column("scans", "heartbeat_at")
