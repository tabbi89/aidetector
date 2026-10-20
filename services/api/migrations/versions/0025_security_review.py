"""Archive the optional AI security design review separately from findings."""
import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision = "0025"
down_revision = "0024"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("scan_runs", sa.Column(
        "security_review", postgresql.JSONB(), nullable=False, server_default="{}",
    ))


def downgrade() -> None:
    op.drop_column("scan_runs", "security_review")
