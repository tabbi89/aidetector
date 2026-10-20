"""adjudication cache: key on Finding.fingerprint, drop the retired title hashes

The cache used to be keyed on ``sha256(check|owasp_id|title)[:64]`` — an
identity scheme of its own, separate from ``Finding.fingerprint`` and governed
by none of the rules that protect it. Titles are not stable for every check
(the header checks carry endpoint counts, ``mass_assignment`` carries the probed
field name), so an edit to a title silently invalidated a paid cache.

Both schemes are hex of the same alphabet but different lengths — the retired
one is 64 characters, ``Finding.fingerprint`` is 32 — so the old rows are
identifiable and are deleted here rather than left to accumulate as permanent
misses. The column is already ``String(64)``, so no type change is needed.

Cost: one re-adjudication per existing scan that had cached verdicts, on the
next run that asks for adjudication. Verdicts a *human* set are unaffected —
those live in ``Scan.triage``, keyed on ``Finding.fingerprint`` already, and are
re-applied after adjudication precisely so a person outranks the model.

Revision ID: 0016
Revises: 0015
"""
from __future__ import annotations

from collections.abc import Sequence

from alembic import op

revision: str = "0016"
down_revision: str | None = "0015"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.execute("DELETE FROM adjudication_cache WHERE length(fingerprint) > 32")


def downgrade() -> None:
    # The deleted rows were keyed by a scheme this codebase no longer computes,
    # so there is nothing to restore. Rolling back leaves the cache empty and
    # the next adjudication run repopulates it under the old scheme.
    pass
