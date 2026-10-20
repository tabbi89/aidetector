"""credential names are unique per scan

Revision ID: 0040
Revises: 0039
Create Date: 2026-10-17 12:30:00.000000
"""
from __future__ import annotations

from collections.abc import Sequence

from alembic import op

revision: str = '0040'
down_revision: str | None = '0039'
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    # Identity is addressed by name in the local lane's secret map and in
    # finding evidence, so a scan cannot hold two identities with one name.
    #
    # Before 0040 the service allowed duplicates, so a database upgraded from
    # 0039 can legitimately hold rows that would fail the constraint and block
    # deployment. Give the later rows a deterministic, still-unique name rather
    # than dropping an identity: the secret and its role survive, and an
    # operator can rename it from the UI.
    #
    # The generated name is allocated against every name the scan already
    # holds, renamed rows included: a previously legal row may already be
    # called `alice-dup-11111111`, and two duplicates may share a UUID prefix.
    # Clashing candidates take a counter until one is free.
    op.execute(
        """
        DO $$
        DECLARE
            dup record;
            candidate text;
            attempt int;
        BEGIN
            FOR dup IN
                SELECT id, scan_id, name
                  FROM (
                        SELECT id, scan_id, name,
                               row_number() OVER (
                                   PARTITION BY scan_id, name ORDER BY id
                               ) AS rn
                          FROM credential_profiles
                       ) AS ranked
                 WHERE ranked.rn > 1
                 ORDER BY scan_id, name, id
            LOOP
                attempt := 0;
                LOOP
                    candidate := left(dup.name, 90) || '-dup-' || left(dup.id::text, 8)
                        || CASE WHEN attempt = 0 THEN '' ELSE '-' || attempt END;
                    EXIT WHEN NOT EXISTS (
                        SELECT 1 FROM credential_profiles
                         WHERE scan_id = dup.scan_id AND name = candidate
                    );
                    attempt := attempt + 1;
                END LOOP;
                UPDATE credential_profiles SET name = candidate WHERE id = dup.id;
            END LOOP;
        END
        $$;
        """
    )
    op.create_unique_constraint(
        'uq_credential_profiles_scan_name',
        'credential_profiles',
        ['scan_id', 'name'],
    )


def downgrade() -> None:
    op.drop_constraint(
        'uq_credential_profiles_scan_name',
        'credential_profiles',
        type_='unique',
    )
