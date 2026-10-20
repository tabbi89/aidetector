"""``prepare_credentials``: the credential half of the egress guard, shared by both lanes.

The server worker and the local runner both call it, so these pin the order
(every URL checked before anything is minted), what a refusal drops, and what
a failed grant leaves behind.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from app.core.target_guard import TargetNotAllowed
from app.domain.enums import AuthType, GrantType
from app.engine.credentials import ResolvedCredential
from app.engine.execution import prepare_credentials


@dataclass
class _Cred(ResolvedCredential):
    """A credential whose mint is scripted and logged instead of calling a target."""

    minted_token: str | None = None
    log: list[str] = field(default_factory=list)

    def mint(self, client: Any) -> bool:
        self.log.append(f"mint:{self.name}")
        if self.grant_type == GrantType.static:
            return True
        if not self.token_url or self.minted_token is None:
            return False
        self.secret = self.minted_token
        return True


def _cred(name: str, log: list[str], **kw: Any) -> _Cred:
    return _Cred(
        name=name,
        role=name,
        auth_type=kw.pop("auth_type", AuthType.bearer),
        header_name=None,
        secret=kw.pop("secret", "grant-input-secret"),
        log=log,
        **kw,
    )


def _guard(log: list[str], blocked: set[str]):
    def allowed(url: str) -> None:
        log.append(f"check:{url}")
        if url in blocked:
            raise TargetNotAllowed("metadata address")

    return allowed


def test_every_url_is_checked_before_anything_is_minted() -> None:
    log: list[str] = []
    a = _cred("a", log, grant_type=GrantType.client_credentials,
              token_url="https://auth.test/a", minted_token="tok-a")
    b = _cred("b", log, grant_type=GrantType.client_credentials,
              token_url="https://auth.test/b", minted_token="tok-b")

    prepare_credentials(
        [a, b], allowed=_guard(log, set()), transport=object(), on_secret=lambda s: None
    )

    first_mint = next(i for i, step in enumerate(log) if step.startswith("mint:"))
    assert all(step.startswith("check:") for step in log[:first_mint])
    assert log[:first_mint] == ["check:https://auth.test/a", "check:https://auth.test/b"]


def test_a_blocked_token_url_is_dropped_and_the_identity_left_out() -> None:
    log: list[str] = []
    blocked = _cred("blocked", log, grant_type=GrantType.client_credentials,
                    token_url="http://169.254.169.254/token", minted_token="never")
    static = _cred("static", log, secret="static-token")
    secrets: list[str] = []

    ready, events = prepare_credentials(
        [blocked, static],
        allowed=_guard(log, {"http://169.254.169.254/token"}),
        transport=object(),
        on_secret=secrets.append,
    )

    assert ready == [static]
    assert blocked.token_url is None
    # Defence in depth: the grant's sensitive input can never become a header.
    assert blocked.auth_type == AuthType.none
    assert blocked.secret == ""
    assert [stage for stage, _ in events] == ["egress_blocked", "auth_grant_failed"]
    assert "token_url blocked" in events[0][1]
    assert secrets == ["static-token"]


def test_a_blocked_refresh_url_keeps_the_identity_but_not_the_refresh() -> None:
    log: list[str] = []
    cred = _cred("r", log, secret="static-token", refresh_url="http://10.0.0.1/refresh")

    ready, events = prepare_credentials(
        [cred],
        allowed=_guard(log, {"http://10.0.0.1/refresh"}),
        transport=object(),
        on_secret=lambda s: None,
    )

    assert ready == [cred]
    assert cred.refresh_url is None
    assert [stage for stage, _ in events] == ["egress_blocked"]


def test_the_redactor_learns_the_minted_token_not_the_grant_input() -> None:
    log: list[str] = []
    cred = _cred("m", log, grant_type=GrantType.password,
                 token_url="https://auth.test/token", minted_token="fresh-access-token")
    secrets: list[str] = []

    ready, events = prepare_credentials(
        [cred], allowed=_guard(log, set()), transport=object(), on_secret=secrets.append
    )

    assert ready == [cred]
    assert events == []
    assert secrets == ["fresh-access-token"]
