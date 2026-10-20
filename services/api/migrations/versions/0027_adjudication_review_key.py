"""Keep stable finding identity separate from evidence-sensitive AI reuse."""
import sqlalchemy as sa
from alembic import op

revision = "0027"
down_revision = "0026"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.drop_constraint(
        "adjudication_cache_scan_id_fingerprint_key",
        "adjudication_cache",
        type_="unique",
    )
    op.add_column(
        "adjudication_cache",
        sa.Column("review_key", sa.String(length=64), nullable=False, server_default=""),
    )
    op.create_unique_constraint(
        "uq_adjudication_cache_scan_fingerprint_review",
        "adjudication_cache",
        ["scan_id", "fingerprint", "review_key"],
    )


def downgrade() -> None:
    op.drop_constraint(
        "uq_adjudication_cache_scan_fingerprint_review",
        "adjudication_cache",
        type_="unique",
    )
    op.drop_column("adjudication_cache", "review_key")
    op.create_unique_constraint(
        "adjudication_cache_scan_id_fingerprint_key",
        "adjudication_cache",
        ["scan_id", "fingerprint"],
    )
