"""Comparing two runs of a scan: what is new, what is fixed, what is still there.

A single scan report answers "what is wrong". A team fixing things needs "what
changed since last time" — three new highs is a decision, sixty findings is a
document nobody reads. Every run already archives a findings snapshot
(``ScanRun.findings_snapshot``); this reads two of them.

Matching is by fingerprint (``app/engine/fingerprint.py``), which is what makes
"the same finding" a meaningful phrase across runs. Snapshots written before
fingerprints existed carry none: those rows are reported as **unmatchable**
rather than silently counted as new, because "12 new findings" that only means
"the older run predates the feature" is worse than saying so.

Pure — no DB, no I/O. The route hands it two snapshots and serialises the result.
"""
from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

from app.domain.enums import CONFIDENCE_RANK, SEVERITY_RANK


@dataclass
class RunDiff:
    """What changed between two archived runs."""

    #: In the newer run, not the older — a regression, or newly reachable.
    added: list[dict[str, Any]] = field(default_factory=list)
    #: In the older run, not the newer — fixed, or no longer reachable.
    resolved: list[dict[str, Any]] = field(default_factory=list)
    #: In the older run only, but produced by a pass the newer run left off —
    #: the newer run never looked, so calling these "fixed" would be a lie.
    not_retested: list[dict[str, Any]] = field(default_factory=list)
    #: In both. Carries the *newer* row, since that is the current state.
    unchanged: list[dict[str, Any]] = field(default_factory=list)
    #: Rows on either side with no fingerprint, which cannot be matched.
    unmatchable: int = 0


#: Checks whose fix *is* the endpoint refusing the caller the finding was
#: about, with no other caller of that endpoint getting a 2xx: a 401/403 on the
#: retest is then the answer, not a failure to test. BOLA and BFLA are not here:
#: fixed, their owner/privileged reference still succeeds, so the endpoint is
#: still exercised and needs no exception.
REFUSAL_IS_AN_ANSWER = frozenset({"broken_auth", "write_authz", "seeded_bola"})


@dataclass(frozen=True)
class Unexercised:
    """Endpoints a run did not test properly, by how badly."""

    #: Sent nothing, got no response, was excluded, or was left out of a run
    #: that recorded coverage for others.
    unanswered: frozenset[str] = frozenset()
    #: Answered, but never with a 2xx.
    no_success: frozenset[str] = frozenset()
    #: Of ``no_success``, those that answered with a 401/403 refusal.
    refused: frozenset[str] = frozenset()
    #: Whether any endpoint in the run got a 2xx. A run with none (every key
    #: expired, every path 404) proves nothing about any endpoint.
    any_exercised: bool = True

    def __bool__(self) -> bool:
        return bool(self.unanswered or self.no_success)

    def hides(self, check: str, operation_id: str | None) -> bool:
        """Whether a missing finding of ``check`` on this endpoint is unproven."""
        if not operation_id:
            return False
        if operation_id in self.unanswered:
            return True
        if operation_id not in self.no_success:
            return False
        refusal_answers = (
            check in REFUSAL_IS_AN_ANSWER and self.any_exercised and operation_id in self.refused
        )
        return not refusal_answers


def unexercised_operations(
    coverage: list[dict[str, Any]], known_operations: frozenset[str] = frozenset()
) -> Unexercised:
    """The endpoints a run reached without a 2xx, split by how it answered.

    A finding on such an endpoint that the run did not reproduce was usually not
    tested again — wrong auth, path or body — so it is not fixed. Only an
    explicit ``exercised: false`` counts as "no 2xx": a row archived before the
    field existed says nothing either way. ``known_operations`` are the scan's
    current operation ids: one of them absent from a run that recorded coverage
    (the local runner records enabled operations only) was not tested either.
    """
    unanswered: set[str] = set()
    no_success: set[str] = set()
    refused: set[str] = set()
    covered: set[str] = set()
    any_exercised = False
    for row in coverage:
        if not row.get("operation_id"):
            continue
        oid = str(row["operation_id"])
        covered.add(oid)
        if not row.get("enabled", True):
            unanswered.add(oid)
            continue
        if row.get("exercised") is True:
            any_exercised = True
            continue
        if row.get("exercised") is not False:
            continue
        if not row.get("requests") or not row.get("responses"):
            unanswered.add(oid)
        else:
            no_success.add(oid)
            if row.get("denied"):
                refused.add(oid)
    if covered:
        unanswered |= set(known_operations) - covered
    return Unexercised(
        frozenset(unanswered), frozenset(no_success), frozenset(refused), any_exercised
    )


def _by_fingerprint(rows: list[dict[str, Any]]) -> tuple[dict[str, dict[str, Any]], int]:
    """Index a snapshot by fingerprint, counting rows that have none.

    A run can legitimately produce two findings with one fingerprint only if a
    check emits duplicates; the first wins and the rest are treated as the same
    finding, which is the honest reading of an identity collision.
    """
    indexed: dict[str, dict[str, Any]] = {}
    unmatchable = 0
    for row in rows:
        fp = str(row.get("fingerprint") or "")
        if not fp:
            unmatchable += 1
            continue
        indexed.setdefault(fp, row)
    return indexed, unmatchable


def diff_snapshots(
    older: list[dict[str, Any]],
    newer: list[dict[str, Any]],
    *,
    not_retested: Callable[[dict[str, Any]], bool] | None = None,
) -> RunDiff:
    """Compare two ``findings_snapshot`` lists, oldest first.

    ``not_retested`` marks an older-only row the newer run could not have
    reproduced (its pass was off); such rows are split out of ``resolved``.
    """
    old_index, old_bad = _by_fingerprint(older)
    new_index, new_bad = _by_fingerprint(newer)

    added = [row for fp, row in new_index.items() if fp not in old_index]
    gone = [row for fp, row in old_index.items() if fp not in new_index]
    unchanged = [row for fp, row in new_index.items() if fp in old_index]
    skipped = [row for row in gone if not_retested is not None and not_retested(row)]
    resolved = [row for row in gone if not (not_retested is not None and not_retested(row))]

    return RunDiff(
        added=_ordered(added),
        resolved=_ordered(resolved),
        not_retested=_ordered(skipped),
        unchanged=_ordered(unchanged),
        unmatchable=old_bad + new_bad,
    )


# Derived from the one vocabulary in app.domain.enums, so a new severity or
# confidence tier can never reorder the diff differently from the API/reports.
_SEVERITY_RANK = {s.value: r for s, r in SEVERITY_RANK.items()}
_CONFIDENCE_RANK = {c.value: r for c, r in CONFIDENCE_RANK.items()}


def _ordered(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Most severe first, proof before leads — the order used everywhere else."""
    return sorted(
        rows,
        key=lambda r: (
            -_SEVERITY_RANK.get(str(r.get("severity", "")), 0),
            -_CONFIDENCE_RANK.get(str(r.get("confidence", "heuristic")), 0),
            str(r.get("check", "")),
        ),
    )
