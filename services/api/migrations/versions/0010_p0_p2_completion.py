"""tenant isolation, credential refresh, adjudication cache

Revision ID: 0010
Revises: 0009
"""
from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0010"
down_revision: str | None = "0009"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column(
        "scans",
        sa.Column("tenant_id", sa.String(length=120), server_default="default", nullable=False),
    )
    op.create_index("ix_scans_tenant_id", "scans", ["tenant_id"])
    op.add_column("credential_profiles", sa.Column("refresh_url", sa.String(2048)))
    op.add_column("credential_profiles", sa.Column("refresh_secret_ref", sa.String(1024)))
    op.add_column(
        "credential_profiles",
        sa.Column(
            "refresh_token_field",
            sa.String(120),
            server_default="refresh_token",
            nullable=False,
        ),
    )
    op.add_column(
        "credential_profiles",
        sa.Column(
            "access_token_field",
            sa.String(120),
            server_default="access_token",
            nullable=False,
        ),
    )
    op.create_table(
        "adjudication_cache",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("scan_id", sa.Uuid(), nullable=False),
        sa.Column("fingerprint", sa.String(64), nullable=False),
        sa.Column(
            "verdict",
            # Reference the EXISTING "verdict" enum (created with the findings
            # table); the PG-specific ENUM honours create_type=False so this
            # migration does not try to CREATE TYPE a second time.
            postgresql.ENUM(
                "unreviewed", "confirmed", "dismissed", name="verdict", create_type=False
            ),
            nullable=False,
        ),
        sa.Column("rationale", sa.Text(), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        ),
        sa.ForeignKeyConstraint(["scan_id"], ["scans.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("scan_id", "fingerprint"),
    )
    op.create_index("ix_adjudication_cache_scan_id", "adjudication_cache", ["scan_id"])


def downgrade() -> None:
    op.drop_index("ix_adjudication_cache_scan_id", table_name="adjudication_cache")
    op.drop_table("adjudication_cache")
    op.drop_column("credential_profiles", "access_token_field")
    op.drop_column("credential_profiles", "refresh_token_field")
    op.drop_column("credential_profiles", "refresh_secret_ref")
    op.drop_column("credential_profiles", "refresh_url")
    op.drop_index("ix_scans_tenant_id", table_name="scans")
    op.drop_column("scans", "tenant_id")
