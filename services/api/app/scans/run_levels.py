"""Scan levels: one word for "how hard should this run look".

The web and the CLI both offer three levels instead of a dozen pass switches:

- ``quick``    — the engine tier alone. The default, and what a run with no
  level has always been.
- ``standard`` — adds schema fuzzing and, when the workspace is entitled, the
  premium detections.
- ``deep``     — adds the external tools (ZAP, Kali, the lead-confirmation
  tools, the testssl.sh TLS audit). Server lane only: a local run cannot reach
  them.

Two things are never part of a level, because each needs its own explicit act:

- **writes** (``mutate``) change target data, so a level never implies them —
  however deep, a level only reads and fuzzes.
- **ai** spends tokens, so it is its own switch. It turns on the AI passes that
  fit the level and the lane; it never adds target traffic beyond what those
  passes already do.

A level *expands* into the ordinary run flags before any gate runs, so the
authorization gate, the entitlement check, the local-lane refusals, the run
archive and the diff all see plain flags and need not know levels exist. The
expansion only ever turns flags **on** — an explicit flag the caller set stays
set — and it is lane- and entitlement-aware: a level asks for "the most this
run can do up to here", so a premium pass the tenant lacks is left out rather
than refused, while an *explicit* ``premium: true`` is still refused (402).

Pure: no FastAPI, no SQLAlchemy. The web mirrors the table below in
``apps/web/app/components/scanLevels.ts``; ``tests/test_coverage_mirror.py``
fails when the two disagree.
"""
from __future__ import annotations

from dataclasses import fields
from typing import Literal

from app.scans.run_options import RunOptions

ScanLevel = Literal["quick", "standard", "deep"]
Lane = Literal["server", "local"]

LEVELS: tuple[ScanLevel, ...] = ("quick", "standard", "deep")

#: Non-AI passes each level turns on. Cumulative by construction.
LEVEL_PASSES: dict[ScanLevel, tuple[str, ...]] = {
    "quick": (),
    "standard": ("fuzz", "premium"),
    "deep": ("fuzz", "premium", "zap", "kali", "confirm", "testssl"),
}

#: AI passes the ``ai`` switch turns on at each level.
LEVEL_AI_PASSES: dict[ScanLevel, tuple[str, ...]] = {
    "quick": ("plan", "adjudicate", "security_review"),
    "standard": ("plan", "adjudicate", "security_review"),
    "deep": (
        "plan",
        "adjudicate",
        "security_review",
        "genai_payloads",
        "adaptive",
        "resource_refine",
    ),
}

#: Passes that need the premium tier; a level includes them only when entitled.
PREMIUM_PASSES = frozenset({"premium", "adaptive", "resource_refine"})

#: Passes that need ``mutate`` on as well; a level includes them only with writes.
WRITE_PASSES = frozenset({"resource_refine"})

#: Empty: a local run now performs every pass. The external tools run from the
#: CLI machine (ZAP/Kali as siblings, the confirm tools and testssl in the
#: runner image); the in-loop AI passes (plan, adjudicate, security_review,
#: genai_payloads, adaptive, resource_refine) make their planner calls on the
#: service, which holds the model keys, the ledger and the per-run cap.
LOCAL_REFUSED: tuple[str, ...] = ()


#: The only names a level may turn on: RunOptions' boolean passes, less the two
#: that are always the caller's own act — ``mutate`` (writes) and ``agent``
#: (needs a source tree). Anything else (``authorized`` above all) can never
#: come out of a level, whatever the tables above say.
EXPANDABLE = frozenset(
    f.name for f in fields(RunOptions) if f.type in ("bool", bool)
) - {"mutate", "agent"}


def expand(
    level: ScanLevel | None,
    *,
    ai: bool,
    writes: bool,
    entitled: bool,
    lane: Lane,
) -> frozenset[str]:
    """The run flags ``level`` (and the ``ai`` switch) turn on for this run.

    ``level=None`` contributes no passes, so a request that names no level
    behaves exactly as before; ``ai`` without a level reads as ``quick``. Never
    contains ``mutate`` — writes are the caller's own explicit act — and never
    a name outside :data:`EXPANDABLE`.
    """
    effective: ScanLevel = level or "quick"
    wanted = set(LEVEL_PASSES[effective]) if level is not None else set()
    if ai:
        wanted.update(LEVEL_AI_PASSES[effective])
    if not entitled:
        wanted -= PREMIUM_PASSES
    if not writes:
        wanted -= WRITE_PASSES
    if lane == "local":
        wanted -= set(LOCAL_REFUSED)
    return frozenset(wanted & EXPANDABLE)
