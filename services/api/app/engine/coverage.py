"""Attributing requests to the operation they targeted — the coverage report.

Purely observational. Nothing here can refuse a request: it answers "which
operation was that?" and remembers "this check touched it once more", so the
runner can say what the engine did to each endpoint without threading an
operation id through every check.

Kept out of :class:`~app.engine.base.HttpProbe` because the probe owns the
request budget, which is a stated safety ceiling ("removing it turns the tool
into a DoS"). The two used to share one locked block, so a change to the
coverage report was a change to the DoS guard and reviewing a diff to either
meant reasoning about both.

Attribution is best-effort by design: a request whose path matches no template
— a traversal payload in a path segment, a discovered shadow endpoint — is
simply not attributed rather than being rejected or mis-assigned.
"""
from __future__ import annotations

import re
from typing import TYPE_CHECKING

if TYPE_CHECKING:  # import-time cycle: base imports this module
    from app.engine.base import TargetOperation

_PATH_VAR = re.compile(r"\{([^}]+)\}")


def path_matcher(path: str) -> re.Pattern[str]:
    """Compile an operation's path template into a regex matching a rendered path.

    ``{var}`` becomes exactly one path segment, so ``/a/{id}`` matches ``/a/7``
    but not ``/a/7/b``.
    """
    parts: list[str] = []
    last = 0
    for m in _PATH_VAR.finditer(path):
        parts.append(re.escape(path[last : m.start()]))
        parts.append(r"[^/]+")
        last = m.end()
    parts.append(re.escape(path[last:]))
    return re.compile("^" + "".join(parts) + "$")


class CoverageRecorder:
    """Maps a sent request back to its operation, and counts what touched it.

    Not thread-safe on its own — :class:`HttpProbe` calls :meth:`note` inside the
    lock that already guards the budget, so the two stay consistent with each
    other. :meth:`operation_id` is pure and needs no lock.
    """

    def __init__(self, operations: list[TargetOperation] | None = None) -> None:
        ops = operations or []
        # (method, matcher, operation id) — exact paths first, so a static path
        # wins over a templated one that could also match it.
        self._matchers: list[tuple[str, re.Pattern[str], str | None, str]] = sorted(
            ((op.method.upper(), path_matcher(op.path), op.id, op.path) for op in ops),
            key=lambda t: "[^/]+" in t[1].pattern,
        )
        #: operation id -> {check key -> request count}. What the report renders.
        self.per_operation: dict[str, dict[str, int]] = {}

    def operation_id(self, method: str, path: str) -> str | None:
        """The operation a request targeted, or None when nothing matches."""
        wanted = method.upper()
        for op_method, matcher, op_id, _ in self._matchers:
            if op_method == wanted and op_id and matcher.match(path):
                return op_id
        return None

    def _route(self, method: str, path: str) -> str | None:
        """Return the matched path template without exposing rendered ids."""
        wanted = method.upper()
        for op_method, matcher, _, route in self._matchers:
            if op_method == wanted and matcher.match(path):
                return route
        return None

    def note(self, op_id: str, check: str | None) -> None:
        """Record one request against an operation, attributed to a check."""
        bucket = self.per_operation.setdefault(op_id, {})
        key = check or "?"
        bucket[key] = bucket.get(key, 0) + 1
