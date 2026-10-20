"""Recovering from a 401 mid-scan by refreshing the credential that failed.

A long scan outlives short-lived tokens. When a request comes back 401 carrying
a bearer token the scan knows, this refreshes that credential once and replays
the request with the new token — so an expiry mid-run costs one retry instead of
turning every later finding into a false "endpoint requires auth".

Split out of :class:`~app.engine.base.HttpProbe` because it is a third concern
in a class that already owned the request budget and the rate-limit backoff.
It still spends from the budget through the injected ``reserve`` callback: a
refresh is a real outbound request, and so is the replay, so neither is free.

Best-effort throughout. Anything unexpected returns the original 401 rather than
raising — a failed refresh must look like an auth failure, not like a broken
scan.
"""
from __future__ import annotations

from collections.abc import Callable
from typing import TYPE_CHECKING, Any

from app.engine.credentials import wire_kwargs

if TYPE_CHECKING:  # import-time cycle: base imports this module
    from app.engine.base import ResolvedCredential

#: Reserves one outbound request from the probe's budgets. False when spent.
Reserve = Callable[[str, str], bool]


class ReauthPolicy:
    """Refresh-and-replay for a 401, bounded by the caller's request budget."""

    def __init__(
        self,
        credentials: list[ResolvedCredential],
        client: Any,
        reserve: Reserve,
        record_secret: Callable[[str], None] | None = None,
    ) -> None:
        self._credentials = credentials
        self._client = client
        self._reserve = reserve
        self._record_secret = record_secret or (lambda _secret: None)

    def retry(
        self,
        method: str,
        path: str,
        kwargs: dict[str, Any],
        headers: dict[str, str],
        original: Any,
    ) -> Any:
        """Replay ``original``'s request with a refreshed token, or return it.

        Returns the original 401 unless every step succeeds: the request carried
        a refreshable token belonging to a credential this scan resolved, the
        refresh works, and both refresh and replay can reserve budget.
        """
        cred = self._credential_for(headers)
        if cred is None:
            return original
        failed = cred.secret
        if not self._reserve("POST", cred.refresh_url or ""):
            return original
        try:
            refreshed = cred.refresh(self._client, failed)
        except Exception:  # noqa: BLE001 — refresh is best-effort; keep the 401
            return original
        if not refreshed or not self._reserve(method, path):
            return original
        self._record_secret(cred.secret)
        new_headers = dict(headers)
        new_headers.update(cred.headers())
        kwargs["headers"] = new_headers
        return self._client.request(method.upper(), path, **wire_kwargs(kwargs))

    def _credential_for(self, headers: dict[str, str]) -> ResolvedCredential | None:
        """The scan credential whose current token is the one that just failed."""
        actual = {name.lower(): value for name, value in headers.items()}
        for credential in self._credentials:
            if not credential.refresh_url or not credential.refresh_secret:
                continue
            expected = credential.headers()
            if expected and all(
                actual.get(name.lower()) == value for name, value in expected.items()
            ):
                return credential
        return None
