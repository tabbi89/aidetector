"""Credentials resolved for use: secret decrypted, auth headers derived."""
from __future__ import annotations

import threading
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

from app.domain.enums import AuthType, GrantType
from app.engine.http_types import HEADER_NAME

if TYPE_CHECKING:
    from app.engine.http_types import HttpClient

#: A query-string key cannot ride in headers, yet every check builds its
#: requests from :meth:`ResolvedCredential.headers`. So inside the scanner it
#: travels as this pseudo-header — the suffix is the parameter name in hex, which
#: keeps any name a legal header — and :func:`wire_kwargs` moves it into the
#: query string only at the transport call. Everything upstream (identity
#: matching in the trace, forged variants, refresh) treats it as one more auth
#: header, and the trace redacts it by name like any other key.
QUERY_KEY_HEADER_PREFIX = "X-Aidetector-Query-Apikey-"


def wire_kwargs(kwargs: dict[str, Any]) -> dict[str, Any]:
    """The request kwargs as they go on the wire: query keys moved into ``params``.

    Returns ``kwargs`` itself when there is nothing to move, so the common path
    costs one scan of the header names.
    """
    headers = kwargs.get("headers") or {}
    prefix = QUERY_KEY_HEADER_PREFIX.lower()
    moved = {k: v for k, v in headers.items() if str(k).lower().startswith(prefix)}
    if not moved:
        return kwargs
    params = dict(kwargs.get("params") or {})
    # The key wins over a same-named spec parameter: fuzzing that parameter then
    # sends the key, not the payload — lost coverage, never a leaked payload.
    for raw_name, value in moved.items():
        try:
            name = bytes.fromhex(str(raw_name)[len(prefix):]).decode()
        except ValueError:
            continue
        params[name] = value
    out = dict(kwargs)
    out["headers"] = {k: v for k, v in headers.items() if k not in moved}
    out["params"] = params
    return out


@dataclass
class ResolvedCredential:
    name: str
    role: str
    auth_type: AuthType
    header_name: str | None
    secret: str
    # Explicit privilege rank (higher = more privileged); None infers it from
    # ``role``. Declared after ``secret`` so positional construction still works.
    privilege: int | None = None
    refresh_url: str | None = None
    refresh_secret: str | None = None
    refresh_token_field: str = "refresh_token"
    access_token_field: str = "access_token"
    # Token-minting grant. When not ``static``, ``secret`` starts as the grant's
    # sensitive material (client_secret / password) and ``mint`` replaces it with
    # a freshly obtained token before the scan sends anything.
    grant_type: GrantType = GrantType.static
    token_url: str | None = None
    grant_params: dict[str, Any] = field(default_factory=dict)
    # Which tenant (workspace, organisation, account) this identity belongs to.
    # None means undeclared. Object-level checks pair identities of different
    # tenants; function-level checks pair identities within one.
    tenant: str | None = None
    _refresh_lock: threading.Lock = field(default_factory=threading.Lock, repr=False)

    def headers(self) -> dict[str, str]:
        """Auth headers this credential contributes to a request."""
        if self.auth_type == AuthType.bearer:
            return {"Authorization": f"Bearer {self.secret}"}
        if self.auth_type == AuthType.basic:
            import base64

            token = base64.b64encode(self.secret.encode()).decode()
            return {"Authorization": f"Basic {token}"}
        if self.auth_type in (AuthType.header, AuthType.api_key):
            default = "X-API-Key" if self.auth_type == AuthType.api_key else "Authorization"
            name = self.header_name
            if not name or not HEADER_NAME.fullmatch(name):
                name = default
            return {name: self.secret}
        if self.auth_type in (AuthType.query, AuthType.cookie):
            name = self.header_name
            if not name or not HEADER_NAME.fullmatch(name):
                # Validated on the way in; a name that is not a token cannot be
                # sent safely, so send nothing rather than guess one.
                return {}
            if self.auth_type == AuthType.cookie:
                return {"Cookie": f"{name}={self.secret}"}
            return {QUERY_KEY_HEADER_PREFIX + name.encode().hex(): self.secret}
        return {}

    def refresh(self, client: HttpClient, failed_secret: str) -> bool:
        """Refresh an expired token once, preserving its authentication channel."""
        if (
            self.auth_type
            not in {
                AuthType.bearer,
                AuthType.header,
                AuthType.api_key,
                AuthType.query,
                AuthType.cookie,
            }
            or not self.refresh_url
            or not self.refresh_secret
        ):
            return False
        with self._refresh_lock:
            if self.secret != failed_secret:
                return True  # another worker already refreshed this credential
            response = client.request(
                "POST",
                self.refresh_url,
                json={self.refresh_token_field: self.refresh_secret},
            )
            if response.status_code >= 400:
                return False
            try:
                data = response.json()
            except (TypeError, ValueError):
                return False
            token = data.get(self.access_token_field) if isinstance(data, dict) else None
            if not isinstance(token, str) or not token:
                return False
            self.secret = token
            return True

    def mint(self, client: HttpClient) -> bool:
        """Obtain the token this credential authenticates with, if it uses a grant.

        ``static`` credentials already hold their token — nothing to do. For the
        OAuth and cookie grants this calls the target's own auth endpoint once,
        at scan start, and rewrites ``secret``/``auth_type`` in place so every
        subsequent request carries a fresh token. Returns True when the
        credential is ready to use (always, for static), False when a grant was
        configured but minting failed — the caller decides what to do then.

        Never raises: a target auth endpoint is untrusted, so any transport or
        shape error is a False, not an exception that aborts the scan.
        """
        if self.grant_type == GrantType.static:
            return True
        if not self.token_url:
            return False
        params = self.grant_params or {}
        try:
            if self.grant_type in (GrantType.client_credentials, GrantType.password):
                return self._mint_oauth(client, params)
            if self.grant_type == GrantType.cookie:
                return self._mint_cookie(client, params)
        except Exception:  # noqa: BLE001 — auth endpoint is untrusted; never crash
            return False
        return False

    def _mint_oauth(self, client: HttpClient, params: dict[str, Any]) -> bool:
        # OAuth2 token endpoints take a form-encoded body. The sensitive half is
        # ``secret`` (client_secret or password); everything else is non-secret.
        body: dict[str, str] = {"grant_type": self.grant_type.value}
        if self.grant_type == GrantType.client_credentials:
            body["client_id"] = str(params.get("client_id", ""))
            body["client_secret"] = self.secret
        else:  # password
            body["username"] = str(params.get("username", ""))
            body["password"] = self.secret
            if params.get("client_id"):
                body["client_id"] = str(params["client_id"])
        if params.get("scope"):
            body["scope"] = str(params["scope"])
        assert self.token_url is not None
        resp = client.request("POST", self.token_url, data=body)
        if resp.status_code >= 400:
            return False
        try:
            data = resp.json()
        except (TypeError, ValueError):
            return False
        field_name = str(params.get("access_token_field") or self.access_token_field)
        token = data.get(field_name) if isinstance(data, dict) else None
        if not isinstance(token, str) or not token:
            return False
        # Whatever the credential was declared as, it now bears a bearer token.
        self.auth_type = AuthType.bearer
        self.secret = token
        return True

    def _mint_cookie(self, client: HttpClient, params: dict[str, Any]) -> bool:
        # A login endpoint that sets a session cookie. Body is JSON by default,
        # form when ``format: "form"``. ``secret`` is the password.
        user_field = str(params.get("username_field") or "username")
        pass_field = str(params.get("password_field") or "password")
        payload = {user_field: str(params.get("username", "")), pass_field: self.secret}
        assert self.token_url is not None
        if str(params.get("format") or "json").lower() == "form":
            resp = client.request("POST", self.token_url, data=payload)
        else:
            resp = client.request("POST", self.token_url, json=payload)
        if resp.status_code >= 400:
            return False
        jar = getattr(resp, "cookies", None)
        if jar is None:
            return False
        wanted = params.get("cookie_name")
        pairs = list(jar.items())
        if not pairs:
            return False
        if wanted:
            value = jar.get(str(wanted))
            if value is None:
                return False
            cookie = f"{wanted}={value}"
        else:
            cookie = "; ".join(f"{k}={v}" for k, v in pairs)
        # A cookie is just a header; carry it as one.
        self.auth_type = AuthType.header
        self.header_name = "Cookie"
        self.secret = cookie
        return True
