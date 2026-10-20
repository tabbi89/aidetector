"""Persist the request cadence for manual and scheduled scan runs.

Revision ID: 0019
Revises: 0018
"""

import sqlalchemy as sa
from alembic import op

revision = "0019"
down_revision = "0018"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "scans",
        sa.Column("requests_per_second", sa.Integer(), nullable=False, server_default="10"),
    )
    op.create_check_constraint(
        "ck_scans_requests_per_second",
        "scans",
        "requests_per_second BETWEEN 1 AND 100",
    )


def downgrade() -> None:
    op.drop_constraint("ck_scans_requests_per_second", "scans", type_="check")
    op.drop_column("scans", "requests_per_second")
