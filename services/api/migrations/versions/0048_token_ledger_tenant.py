"""incurred AI spend survives deleting its scan

Revision ID: 0048
Revises: 0047
Create Date: 2026-10-17 18:40:00.000000

``token_ledger`` rows cascaded with their scan and the monthly figure joined
``scans`` to find the tenant, so deleting a scan refunded its spend. Record the
tenant on the row and null ``scan_id`` instead of deleting it.
"""
from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = '0048'
down_revision: str | None = '0047'
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column(
        'token_ledger',
        sa.Column('tenant_slug', sa.String(length=120), nullable=True),
    )
    op.execute(
        """
        UPDATE token_ledger AS tl
           SET tenant_slug = s.tenant_id
          FROM scans AS s
         WHERE s.id = tl.scan_id
        """
    )
    # Every ledger row belongs to a scan today; the fallback keeps an orphan
    # row (only possible from a partial manual cleanup) from blocking rollout.
    op.execute(
        "UPDATE token_ledger SET tenant_slug = 'default' WHERE tenant_slug IS NULL"
    )
    op.alter_column('token_ledger', 'tenant_slug', nullable=False)
    op.create_index(
        'ix_token_ledger_tenant_slug', 'token_ledger', ['tenant_slug']
    )
    op.drop_constraint(
        'token_ledger_scan_id_fkey', 'token_ledger', type_='foreignkey'
    )
    op.alter_column('token_ledger', 'scan_id', nullable=True)
    op.create_foreign_key(
        'token_ledger_scan_id_fkey',
        'token_ledger',
        'scans',
        ['scan_id'],
        ['id'],
        ondelete='SET NULL',
    )


def downgrade() -> None:
    # Rows orphaned by a scan deletion cannot be re-attached; removing them is
    # the only way back to a non-nullable, cascading column.
    op.execute("DELETE FROM token_ledger WHERE scan_id IS NULL")
    op.drop_constraint(
        'token_ledger_scan_id_fkey', 'token_ledger', type_='foreignkey'
    )
    op.alter_column('token_ledger', 'scan_id', nullable=False)
    op.create_foreign_key(
        'token_ledger_scan_id_fkey',
        'token_ledger',
        'scans',
        ['scan_id'],
        ['id'],
        ondelete='CASCADE',
    )
    op.drop_index('ix_token_ledger_tenant_slug', table_name='token_ledger')
    op.drop_column('token_ledger', 'tenant_slug')
