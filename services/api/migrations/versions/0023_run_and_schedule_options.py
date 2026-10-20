"""Archive run options on each run, and saved options on a schedule.

A schedule now carries the options it was authorized with, and a diff needs to
know which passes each run used so a finding only an opt-in pass produces is
"not re-tested" rather than "fixed". Existing rows get ``{}``: existing
schedules keep running as default read-only scans, and old runs compare as
all-off, which is the previous behaviour.

Revision ID: 0023
Revises: 0022
"""
import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision = "0023"
down_revision = "0022"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "scans",
        sa.Column("schedule_options", postgresql.JSONB(), nullable=False, server_default="{}"),
    )
    op.add_column(
        "scan_runs",
        sa.Column("options", postgresql.JSONB(), nullable=False, server_default="{}"),
    )


def downgrade() -> None:
    op.drop_column("scan_runs", "options")
    op.drop_column("scans", "schedule_options")
