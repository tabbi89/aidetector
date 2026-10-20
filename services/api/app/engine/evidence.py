"""The evidence keys that cross a tier boundary.

Most of a finding's ``evidence`` is free-form: whatever that check wants to show
the reader. Three keys are not — they are a **contract** the confirmation
adjuncts read back:

``app/engine/confirm_base.py:select_family_targets`` picks its sqlmap / dalfox /
commix / tplmap targets by matching ``family`` and then re-probing ``path`` with
``param``. A check that renames or drops one of them does not fail a test; it
silently stops any lead of that family from ever being confirmed.

:func:`injection_evidence` names those keys in one place — its required
``family``/``path``/``param`` arguments are the contract — and adds the optional
presentation keys the injection checks share.
"""
from __future__ import annotations

from typing import Any

#: How much of a response body a finding may carry as a sample.
RESPONSE_SAMPLE_CHARS = 400


def injection_evidence(
    *,
    family: str,
    path: str,
    route: str | None = None,
    param: str,
    location: str,
    payload: str,
    status: int | None = None,
    reflected: bool | None = None,
    response_sample: str | None = None,
    **extra: Any,
) -> dict[str, Any]:
    """Build injection-point evidence, truncating the response sample.

    ``path`` is the URL actually attacked, so it carries the payload; ``route``
    is the spec path template it came from. Both are useful — the first to
    reproduce, the second to name the handler — and only the second is stable
    across runs, which is what the fingerprint needs.
    """
    ev: dict[str, Any] = {
        "family": family,
        "path": path,
        "param": param,
        "location": location,
        "payload": payload,
    }
    if route:
        ev["route"] = route
    if status is not None:
        ev["status"] = status
    if reflected is not None:
        ev["reflected"] = reflected
    if response_sample is not None:
        ev["response_sample"] = response_sample[:RESPONSE_SAMPLE_CHARS]
    ev.update(extra)
    return ev
