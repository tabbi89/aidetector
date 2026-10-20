"""finding fingerprint + per-scan triage

Gives a finding a stable identity across runs, so the same problem is
recognisable from one scan to the next: it carries human triage forward and it
is what the run-to-run diff matches on.

Existing rows keep an empty fingerprint rather than a back-filled guess —
identity is derived from evidence this migration cannot re-derive reliably, and
an empty fingerprint reads as "never matched" everywhere it is used. The next
run stamps them.

Revision ID: 0013
Revises: 0012
"""
from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0013"
down_revision: str | None = "0012"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column(
        "findings",
        sa.Column("fingerprint", sa.String(length=64), server_default="", nullable=False),
    )
    op.create_index("ix_findings_fingerprint", "findings", ["fingerprint"])
    op.add_column(
        "scans",
        sa.Column(
            "triage",
            postgresql.JSONB(astext_type=sa.Text()),
            server_default="{}",
            nullable=False,
        ),
    )


def downgrade() -> None:
    op.drop_column("scans", "triage")
    op.drop_index("ix_findings_fingerprint", table_name="findings")
    op.drop_column("findings", "fingerprint")
