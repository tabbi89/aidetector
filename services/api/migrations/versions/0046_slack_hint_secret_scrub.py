"""scrub bearer secrets from stored Slack destination hints

Revision ID: 0046
Revises: 0045
Create Date: 2026-10-17 18:00:00.000000

A Slack incoming-webhook URL carries its secret in the path
(``/services/T…/B…/secret``). Before this revision the hint stored the whole
path in plaintext beside the encrypted destination, so an existing row keeps a
copy of the credential. Reduce every Slack hint to its scheme and host.
"""
from __future__ import annotations

from collections.abc import Sequence

from alembic import op

revision: str = '0046'
down_revision: str | None = '0045'
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.execute(
        """
        UPDATE notification_endpoints
           SET destination_hint = regexp_replace(
                   destination_hint,
                   '^([a-zA-Z][a-zA-Z0-9+.-]*://[^/]+).*$',
                   '\\1'
               )
         WHERE kind = 'slack'
        """
    )


def downgrade() -> None:
    # The removed path segment is the credential; it is deliberately not
    # recoverable from a hint. The encrypted destination is untouched.
    pass
