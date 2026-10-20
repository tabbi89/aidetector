"""Archive reproducibility and complete-case effectiveness metrics."""
import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision = "0026"
down_revision = "0025"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("scan_runs", sa.Column(
        "manifest", postgresql.JSONB(), nullable=False, server_default="{}",
    ))


def downgrade() -> None:
    op.drop_column("scan_runs", "manifest")
