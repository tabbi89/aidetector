"""Checking credentials before a full scan: which routes, and what the answers mean.

A full scan that runs with a rejected key spends its whole budget learning
nothing, and says so only afterwards. ``runpentests auth check`` asks first: a
few GET requests per identity, plus the same requests sent anonymously, and a
verdict per identity. Pure — the server picks the routes, the local runner
sends the requests and reads the answers with :func:`verdict`.

The verdicts are deliberately strict. A 200 proves nothing about a key when the
route answers 200 to anyone: only a route that refuses the anonymous request and
accepts the identity's proves the key is accepted. Everything else is said as
what it is — rejected, unproven, inconclusive.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any

#: At most this many routes are probed, so a check costs a handful of requests
#: per identity — never a scan.
MAX_ROUTES = 3
#: Requests a check may send in all, whatever the identity count.
MAX_REQUESTS = 40

ACCEPTED = "accepted"  # refused anonymously, answered 2xx with the key
REJECTED = "rejected"  # every answer was 401/403
UNPROVEN = "unproven"  # 2xx, but only where anonymous callers get 2xx too
INCONCLUSIVE = "inconclusive"  # 404s, 5xx, no answers: the routes said nothing
MISSING_SECRET = "missing_secret"
GRANT_FAILED = "grant_failed"
NO_CREDENTIAL = "no_credential"  # auth: none — nothing to check
NOT_CHECKED = "not_checked"  # the check's request cap ran out before this identity


def pick_routes(operations: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """The safe routes to probe: GET only, declared-protected first, no path params first.

    A route with path parameters needs an id that exists, so it ranks last —
    its 404 would say nothing about the key.
    """
    gets = [op for op in operations if str(op.get("method", "")).upper() == "GET"]

    def rank(op: dict[str, Any]) -> tuple[int, int, str]:
        has_params = "{" in str(op.get("path", ""))
        protected = bool(op.get("auth_scope"))
        return (0 if protected else 1, 1 if has_params else 0, str(op.get("path", "")))

    return sorted(gets, key=rank)[:MAX_ROUTES]


def _ok(status: int | None) -> bool:
    return status is not None and 200 <= status < 300


def _denied(status: int | None) -> bool:
    return status in (401, 403)


@dataclass(frozen=True)
class Verdict:
    state: str
    detail: str


def verdict(identity: list[int | None], anonymous: list[int | None]) -> Verdict:
    """One identity's verdict from its statuses and the anonymous ones, route by route."""
    answered = [s for s in identity if s is not None]
    if not answered:
        return Verdict(INCONCLUSIVE, "no route answered")
    for mine, anon in zip(identity, anonymous, strict=False):
        if _ok(mine) and _denied(anon):
            return Verdict(ACCEPTED, "a route that refuses anonymous callers answered 2xx")
    if all(_denied(s) for s in answered):
        return Verdict(REJECTED, f"every answer was 401/403 ({len(answered)} of {len(identity)})")
    if any(_ok(s) for s in answered):
        return Verdict(
            UNPROVEN,
            "2xx only on routes that also answer anonymous callers: acceptance is not proven "
            "— add a route that requires authentication to the spec, or check a protected one",
        )
    codes = ", ".join(sorted({str(s) for s in answered}))
    return Verdict(INCONCLUSIVE, f"no 2xx and not refused (statuses {codes})")
