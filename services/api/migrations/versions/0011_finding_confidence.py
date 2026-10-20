"""finding confidence (evidence tier)

Promotes the heuristic/verified evidence tier from prose to a column so SARIF
levels, the report and a CI gate can act on it.

Existing rows are back-filled with the cautious tier (``heuristic``) rather than
guessed at from their check key: a stale row understating its evidence is
harmless, one overstating it is not. Re-running a scan re-grades its findings.

Revision ID: 0011
Revises: 0010
"""
from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0011"
down_revision: str | None = "0010"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

_CONFIDENCE = postgresql.ENUM(
    "heuristic", "verified", name="confidence", create_type=False
)


def upgrade() -> None:
    _CONFIDENCE.create(op.get_bind(), checkfirst=True)
    op.add_column(
        "findings",
        sa.Column(
            "confidence",
            _CONFIDENCE,
            server_default="heuristic",
            nullable=False,
        ),
    )


def downgrade() -> None:
    op.drop_column("findings", "confidence")
    _CONFIDENCE.drop(op.get_bind(), checkfirst=True)
