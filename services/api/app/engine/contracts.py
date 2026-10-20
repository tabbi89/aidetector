"""The engine's check contract and the findings it returns."""
from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING, Any, Protocol

from app.domain.enums import Confidence, Severity
from app.domain.taxonomy import canonical_taxonomy_id

if TYPE_CHECKING:
    from app.engine.context import ScanContext


@dataclass
class EngineFinding:
    check: str
    owasp_id: str | None
    severity: Severity
    title: str
    description: str
    evidence: dict[str, Any]
    operation_id: str | None = None
    # Evidence tier. Defaults to the cautious side on purpose: a check that
    # forgets to grade a finding understates it rather than passing a lead off
    # as proof. Checks whose evidence demonstrates the weakness directly — the
    # authz oracles, OOB callbacks, the header/TLS inspections — set
    # ``Confidence.verified`` explicitly.
    confidence: Confidence = Confidence.heuristic
    # Optional per-finding remediation override. Left empty by almost every
    # check: ``run_record.append_finding`` fills it from the per-check catalogue
    # in ``engine/remediation.py``, shaped by this finding's evidence.
    remediation: str = ""

    def __post_init__(self) -> None:
        self.owasp_id = canonical_taxonomy_id(self.owasp_id)


class Check(Protocol):
    key: str

    def run(self, ctx: ScanContext) -> list[EngineFinding]: ...


# They used to live in ``runner.py`` as two sets of strings, four modules away
# from the checks they governed — so a new mutating check that nobody remembered
# to list there was dispatched into the thread pool alongside the write oracles,
# against the same resources, silently and non-deterministically.
#
# Read through these accessors rather than the attributes directly: the defaults
# are the safe answers, so a check that declares nothing keeps behaving exactly
# as it does today and only an author who opts in changes anything.


def mutates(check: object) -> bool:
    """Whether the check may write to the target, under any run options.

    Such a check must never run concurrently with another that touches the same
    resources — the write oracles create, update and restore objects, and two
    of them interleaved would each see the other's canary.
    """
    return bool(getattr(check, "mutates", False))


def needs_identities(check: object) -> bool:
    """Whether the check's findings depend on the scan's identities.

    A run that left an identity out (local-only, or a secret no vault key
    opens) could not have re-found such a finding, so its absence is no fix.
    """
    return bool(getattr(check, "needs_identities", False))


def premium(check: object) -> bool:
    """Whether the check is reserved for the premium tier.

    Read through the accessor so the default (``False``) is the safe answer: a
    check that declares nothing runs in the free engine, and only an author who
    opts in is gated behind ``premium: true``.
    """
    return bool(getattr(check, "premium", False))


def serial_when_mutating(check: object) -> bool:
    """Read-only by default, but may create or update once ``mutate: true``."""
    return bool(getattr(check, "serial_when_mutating", False))


def runs_serially(check: object, *, allow_mutation: bool) -> bool:
    """Whether this check must be kept out of the parallel pool for this run."""
    return mutates(check) or (allow_mutation and serial_when_mutating(check))


def inapplicable(check: object, ctx: ScanContext) -> str | None:
    """Why this check cannot run against this scan, or None if it can.

    A check with nothing to work with — no spec-paired create endpoint, no
    url-shaped parameter, no second identity — returns no findings, and that is
    indistinguishable from a clean result. It is the worst possible ambiguity in
    a security report: "we looked and found nothing" and "we never looked" read
    identically, and only one of them is good news.

    So a check may declare it. The accessor is optional and the default is
    ``None`` (runs), because a check that says nothing should be *run*, not
    silently skipped — the safe direction, the same reasoning as
    :func:`premium`. A reason is a short phrase naming what is missing, and it
    is shown to the user as an event; write it so the fix is obvious.
    """
    reason = getattr(check, "inapplicable", None)
    if reason is None:
        return None
    try:
        return reason(ctx) if callable(reason) else str(reason)
    except Exception:  # noqa: BLE001 — a broken accessor must not stop the check
        return None
