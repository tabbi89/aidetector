"""Credential profiles: what a caller sends, and the secret-free view the API returns."""

from __future__ import annotations

import re
import uuid
from typing import Any, Literal

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    field_validator,
    model_validator,
)

from app.api.schemas.common import ResponseModel
from app.domain.enums import AuthType, GrantType
from app.domain.privilege import MAX_PRIVILEGE

# RFC 7230 token — a legal HTTP header name. Rejects the "Authorization Basic"
# mistake (space in the name) and CRLF injection before it can reach the worker.
_HEADER_NAME = re.compile(r"^[!#$%&'*+\-.^_`|~0-9A-Za-z]+$")


def _valid_header_name(v: str | None) -> str | None:
    if v is not None and not _HEADER_NAME.fullmatch(v):
        raise ValueError("header_name must be a valid HTTP header name (no spaces or colons)")
    return v


#: Channels whose name cannot be defaulted: a query key or a cookie is always
#: called something specific.
_NAMED_CHANNELS = {AuthType.query, AuthType.cookie}


def _require_channel_name(auth_type: AuthType, header_name: str | None) -> None:
    if auth_type in _NAMED_CHANNELS and not header_name:
        raise ValueError(
            f"header_name is required for {auth_type.value} auth: the "
            f"{'query parameter' if auth_type == AuthType.query else 'cookie'} name"
        )


class CredentialCreate(BaseModel):
    name: str = Field(min_length=1, max_length=120)
    role: str = Field(min_length=1, max_length=60)
    # Explicit privilege rank on the role-name scale (0 guest … 3 admin), so an
    # explicit rank and an inferred one compare; None infers it from role.
    privilege: int | None = Field(default=None, ge=0, le=MAX_PRIVILEGE)
    # The tenant (workspace, organisation) the identity belongs to. Object-level
    # checks pair identities of different tenants, function-level ones within one.
    tenant: str | None = Field(default=None, min_length=1, max_length=120)
    auth_type: AuthType
    header_name: str | None = Field(default=None, max_length=120)
    # Required unless local_only, which must not carry one.
    secret: str | None = Field(default=None, min_length=1)
    refresh_url: str | None = Field(default=None, max_length=2048)
    refresh_secret: str | None = Field(default=None, min_length=1)
    refresh_token_field: str = Field(default="refresh_token", min_length=1, max_length=120)
    access_token_field: str = Field(default="access_token", min_length=1, max_length=120)
    # Token-minting grant. `static` (default) means `secret` is the token sent
    # as-is; otherwise `secret` is the grant's sensitive half (client_secret /
    # password) and a token is minted from `token_url` + `grant_params`.
    grant_type: GrantType = GrantType.static
    token_url: str | None = Field(default=None, max_length=2048)
    grant_params: dict[str, Any] = Field(default_factory=dict)
    # The secret stays on the CLI machine; only a CLI run (`aidetector run`) can
    # use this identity, and a server run leaves it out.
    local_only: bool = False

    @field_validator("header_name")
    @classmethod
    def _check_header_name(cls, v: str | None) -> str | None:
        return _valid_header_name(v)

    @model_validator(mode="after")
    def _secret_matches_locality(self) -> CredentialCreate:
        _require_channel_name(self.auth_type, self.header_name)
        # Refusing a secret on a local-only identity is the point: accepting
        # and discarding it would still have carried it over the wire.
        if self.local_only and (self.secret or self.refresh_secret):
            raise ValueError(
                "a local-only identity's secret stays on the CLI machine: do not send it"
            )
        if not self.local_only and not self.secret:
            raise ValueError(
                "secret is required (or set local_only for an identity only local runs use)"
            )
        return self


class CredentialOut(ResponseModel):
    """Note: no secret field — credentials are write-only."""

    model_config = ConfigDict(from_attributes=True)
    id: uuid.UUID
    name: str
    role: str
    privilege: int | None = None
    tenant: str | None = None
    auth_type: AuthType
    header_name: str | None = None
    refresh_url: str | None = None
    refresh_token_field: str = "refresh_token"
    access_token_field: str = "access_token"
    has_refresh_secret: bool = False
    grant_type: GrantType = GrantType.static
    token_url: str | None = None
    # Non-secret grant params only — the sensitive half is the write-only secret.
    grant_params: dict[str, Any] = {}
    local_only: bool = False


class CredentialUpdate(BaseModel):
    name: str = Field(min_length=1, max_length=120)
    role: str = Field(min_length=1, max_length=60)
    privilege: int | None = Field(default=None, ge=0, le=MAX_PRIVILEGE)
    # The tenant (workspace, organisation) the identity belongs to. Object-level
    # checks pair identities of different tenants, function-level ones within one.
    tenant: str | None = Field(default=None, min_length=1, max_length=120)
    auth_type: AuthType
    header_name: str | None = Field(default=None, max_length=120)
    # Optional: the stored secret is replaced only when a new one is provided.
    secret: str | None = Field(default=None, min_length=1)
    refresh_url: str | None = Field(default=None, max_length=2048)
    refresh_secret: str | None = Field(default=None, min_length=1)
    refresh_token_field: str = Field(default="refresh_token", min_length=1, max_length=120)
    access_token_field: str = Field(default="access_token", min_length=1, max_length=120)
    grant_type: GrantType = GrantType.static
    token_url: str | None = Field(default=None, max_length=2048)
    grant_params: dict[str, Any] = Field(default_factory=dict)

    @field_validator("header_name")
    @classmethod
    def _check_header_name(cls, v: str | None) -> str | None:
        return _valid_header_name(v)

    @model_validator(mode="after")
    def _channel_named(self) -> CredentialUpdate:
        _require_channel_name(self.auth_type, self.header_name)
        return self


class AuthSchemeHintOut(ResponseModel):
    """One ``securitySchemes`` entry, translated into credential-form terms."""

    name: str
    kind: str
    auth_type: AuthType
    header_name: str | None = None
    grant_type: GrantType = GrantType.static
    token_url: str | None = None
    scopes: list[str] = []
    description: str | None = None


class RoleHintOut(ResponseModel):
    name: str
    privilege: int


class AuthHintsOut(ResponseModel):
    """How the spec says its API authenticates — defaults for the setup forms.

    Advisory only: nothing here reaches the engine.
    """

    suggested: Literal["public", "single", "roles"]
    reason: str
    operations: int
    protected_operations: int
    schemes: list[AuthSchemeHintOut] = []
    roles: list[RoleHintOut] = []


class AuthHintsRequest(BaseModel):
    """A spec to read auth hints from, before any scan exists (``aidetector init``)."""

    # Same ceiling as a stored spec is not enforced here; this bounds the work
    # one anonymous-to-the-scan request can ask for.
    spec: str = Field(min_length=1, max_length=5_000_000)


class IdentityShapeIn(BaseModel):
    """An identity's shape for pairing: never its secret."""

    name: str = Field(min_length=1, max_length=120)
    role: str = Field(min_length=1, max_length=60)
    privilege: int | None = Field(default=None, ge=0, le=3)
    tenant: str | None = Field(default=None, max_length=120)


class IdentityPairsIn(BaseModel):
    identities: list[IdentityShapeIn] = Field(default_factory=list, max_length=50)


class ObjectLevelPair(ResponseModel):
    owner: str
    attacker: str


class FunctionLevelPair(ResponseModel):
    privileged: str
    lower: str


class IdentityPairsOut(ResponseModel):
    """The pairs a run would use for each authorization boundary, or why none."""

    tenants_declared: bool
    #: Cross-identity (with tenants: cross-tenant) object access — BOLA.
    object_level: ObjectLevelPair | None = None
    object_level_gap: str | None = None
    #: A lower identity calling a privileged function in one tenant — BFLA.
    function_level: FunctionLevelPair | None = None
    function_level_gap: str | None = None
    #: Identities with no tenant once others declare one: they sit out.
    left_out: list[str] = []
