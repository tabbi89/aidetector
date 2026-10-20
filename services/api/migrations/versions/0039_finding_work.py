"""finding work: finding_work and finding_comment

Revision ID: 0039
Revises: 0038
Create Date: 2026-10-17 12:00:00.000000
"""
from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = '0039'
down_revision: str | None = '0038'
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    # Work items are keyed by the finding's stable fingerprint, not its row: a
    # re-run replaces findings and the item must follow the weakness. The FK
    # cascade is what removes them with the scan.
    op.create_table(
        'finding_work',
        sa.Column('id', sa.Uuid(), nullable=False),
        sa.Column('scan_id', sa.Uuid(), nullable=False),
        sa.Column('fingerprint', sa.String(length=64), nullable=False),
        sa.Column('owner', sa.String(length=120), nullable=True),
        sa.Column('due_date', sa.Date(), nullable=True),
        sa.Column('status', sa.String(length=20), server_default='open', nullable=False),
        sa.Column(
            'created_at', sa.DateTime(timezone=True),
            server_default=sa.text('now()'), nullable=False,
        ),
        sa.Column(
            'updated_at', sa.DateTime(timezone=True),
            server_default=sa.text('now()'), nullable=False,
        ),
        sa.CheckConstraint(
            "status IN ('open', 'in_progress', 'resolved', 'accepted_risk')",
            name='ck_finding_work_status',
        ),
        sa.ForeignKeyConstraint(['scan_id'], ['scans.id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint(
            'scan_id', 'fingerprint', name='uq_finding_work_scan_fingerprint'
        ),
    )
    op.create_index(
        op.f('ix_finding_work_scan_id'), 'finding_work', ['scan_id'], unique=False
    )

    op.create_table(
        'finding_comment',
        sa.Column('id', sa.Uuid(), nullable=False),
        sa.Column('scan_id', sa.Uuid(), nullable=False),
        sa.Column('fingerprint', sa.String(length=64), nullable=False),
        sa.Column('author', sa.String(length=120), nullable=False),
        sa.Column('body', sa.Text(), nullable=False),
        sa.Column(
            'created_at', sa.DateTime(timezone=True),
            server_default=sa.text('now()'), nullable=False,
        ),
        sa.ForeignKeyConstraint(['scan_id'], ['scans.id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id'),
    )
    op.create_index(
        op.f('ix_finding_comment_scan_id'), 'finding_comment', ['scan_id'], unique=False
    )
    op.create_index(
        op.f('ix_finding_comment_fingerprint'),
        'finding_comment', ['fingerprint'], unique=False,
    )


def downgrade() -> None:
    op.drop_index(op.f('ix_finding_comment_fingerprint'), table_name='finding_comment')
    op.drop_index(op.f('ix_finding_comment_scan_id'), table_name='finding_comment')
    op.drop_table('finding_comment')
    op.drop_index(op.f('ix_finding_work_scan_id'), table_name='finding_work')
    op.drop_table('finding_work')
