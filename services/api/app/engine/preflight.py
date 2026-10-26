"""A cheap reachability check before the engine spends its request budget.

A scan against a target that is down, or whose base URL is wrong, would still
run every check — ~750 requests — and finish looking like a (empty) result. The
post-hoc :mod:`app.engine.target_health` diagnosis catches this, but only *after*
the budget is gone. This module sends a handful of safe GETs first and, when
*nothing* answers, says so and stops the run before it wastes the budget.

It is deliberately narrow: it aborts only on the unambiguous "no answer at all"
case (a closed port, an unresolvable host), where there is genuinely nothing to
scan and so no finding can be hidden. A target that answers *anything* — even
404 or 401 everywhere — is left to the full run and the richer post-hoc
diagnosis, because partial reachability (some routes, one working identity, a
discovered shadow path) is common and worth the full pass.

Pure: no SQLAlchemy, no ``app.models``, no probe type — it takes the operations
and a ``send`` callable, so both lanes (server worker and local runner) share
one copy. ``tests/test_layering.py`` keeps it that way.
"""
from __future__ import annotations

from collections.abc import Callable, Sequence
from typing import Any

from app.engine.operations import TargetOperation, render_path

#: Representative endpoints to probe. Enough signal to tell "nothing answers"
#: from "one route happens to be down", small next to the 750-request budget.
MAX_PROBES = 3

#: Stage name a client reads to know the run never reached the API. Shared with
#: :mod:`app.engine.target_health` so both the early abort and the post-hoc
#: diagnosis surface under one stage.
UNREACHED = "target_unreached"


def choose_probe_ops(
    operations: Sequence[TargetOperation], limit: int = MAX_PROBES
) -> list[TargetOperation]:
    """Pick up to ``limit`` safe GET operations, fewest path params first.

    A GET with no path parameters is the cleanest reachability probe (nothing to
    invent); the sort just prefers those before falling back to templated ones.
    """
    gets = [op for op in operations if op.method.upper() == "GET"]
    gets.sort(key=lambda op: len(op.path_params))
    return gets[:limit]


def assess(answered: int, attempted: int) -> list[tuple[str, str]]:
    """``[(stage, message)]`` when the run should be called off, else ``[]``.

    Aborts only when at least two probes were attempted and *none* were answered
    — the target is unreachable from where the scan runs. One probe is too little
    signal; any answer at all means the run should proceed.
    """
    if attempted < 2 or answered > 0:
        return []
    return [
        (
            UNREACHED,
            f"preflight: none of the {attempted} probe requests got an answer — the "
            "target is down or unreachable from where the scan runs, so the run was "
            "stopped before it spent its request budget. Check that the target URL is "
            "reachable (for a local run on a Docker network, pass --docker-network).",
        )
    ]


def run_preflight(
    operations: Sequence[TargetOperation],
    headers: dict[str, str],
    send: Callable[..., Any],
) -> list[tuple[str, str]]:
    """Probe a few endpoints and assess reachability.

    ``send(method, path, headers=...)`` is the probe's own send — a returned
    response (any status) counts as answered; ``None`` or a raised transport
    error counts as no answer. Returns the events :func:`assess` produced (empty
    when the run should proceed).
    """
    ops = choose_probe_ops(operations)
    answered = 0
    attempted = 0
    for op in ops:
        path = render_path(op.path, {name: "1" for name in op.path_params})
        attempted += 1
        try:
            result = send(op.method, path, headers=headers)
        except Exception:  # noqa: BLE001 — a transport error is "no answer"
            continue
        if result is not None:
            answered += 1
    return assess(answered, attempted)
