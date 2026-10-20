"""What a spec says about how its API authenticates — the setup forms' defaults.

A spec usually already answers the questions the credentials form asks: is a
bearer token, a header key, a query key or an OAuth token endpoint in use, and
does any operation need auth at all. The parser keeps only the scheme *names*
(``auth_scope``, for privilege decisions); this reads ``securitySchemes`` (or
Swagger 2's ``securityDefinitions``) so the web form and ``aidetector init`` can
prefill instead of making the user type it again.

Everything here is a suggestion. Nothing it returns reaches the engine, and a
spec that declares nothing is reported as such rather than guessed at.

Pure — no I/O, no database, no settings.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Literal

from app.domain.enums import AuthType, GrantType
from app.domain.privilege import PRIVILEGE_TOKENS
from app.specs.parser import HTTP_METHODS

Suggestion = Literal["public", "single", "roles"]

#: Bound on what one spec can make us return; a hint list is read by a person.
MAX_SCHEMES = 20
MAX_SCOPES = 40


@dataclass(frozen=True)
class SchemeHint:
    name: str
    #: The spec's own word: http | apiKey | oauth2 | openIdConnect | basic.
    kind: str
    auth_type: AuthType
    header_name: str | None = None
    grant_type: GrantType = GrantType.static
    token_url: str | None = None
    scopes: tuple[str, ...] = ()
    description: str | None = None


@dataclass(frozen=True)
class RoleHint:
    name: str
    privilege: int


@dataclass(frozen=True)
class AuthHints:
    suggested: Suggestion
    reason: str
    operations: int
    protected_operations: int
    schemes: tuple[SchemeHint, ...] = ()
    roles: tuple[RoleHint, ...] = field(default_factory=tuple)


#: Bounds on the walk: a spec is untrusted, and ``yaml.safe_load`` keeps
#: aliases, so one small document can name the same huge list many times.
MAX_OPERATIONS = 5000
MAX_USED = MAX_SCOPES * 10


def _word(value: Any) -> str:
    """A spec value that should be a word, or "" — never ``str()`` of a node.

    ``str()`` on an aliased list expands every reference: a few hundred bytes of
    YAML become gigabytes. Anything that is not already a string is ignored.
    """
    return value if isinstance(value, str) else ""


def _text(value: Any, limit: int = 300) -> str | None:
    if not isinstance(value, str) or not value.strip():
        return None
    return value.strip()[:limit]


def _api_key_hint(name: str, raw: dict[str, Any]) -> SchemeHint | None:
    where = (_word(raw.get("in")) or "header").lower()
    param = _text(raw.get("name"), 120)
    description = _text(raw.get("description"))
    if where == "query":
        return SchemeHint(name, "apiKey", AuthType.query, param, description=description)
    if where == "cookie":
        return SchemeHint(name, "apiKey", AuthType.cookie, param, description=description)
    if param and param.lower() == "authorization":
        # The whole Authorization value is the key: send it verbatim.
        return SchemeHint(name, "apiKey", AuthType.header, "Authorization",
                          description=description)
    return SchemeHint(name, "apiKey", AuthType.api_key, param or "X-API-Key",
                      description=description)


def _oauth_hint(name: str, raw: dict[str, Any], *, swagger2: bool) -> SchemeHint:
    """Prefer a flow the scanner can mint by itself; otherwise a pasted token."""
    description = _text(raw.get("description"))
    flows: dict[str, Any]
    if swagger2:
        flow = _word(raw.get("flow"))
        flows = {flow: raw} if flow else {}
        names = {"application": GrantType.client_credentials, "password": GrantType.password}
    else:
        declared = raw.get("flows")
        flows = declared if isinstance(declared, dict) else {}
        names = {
            "clientCredentials": GrantType.client_credentials,
            "password": GrantType.password,
        }
    scopes: list[str] = []
    for body in flows.values():
        if isinstance(body, dict) and isinstance(body.get("scopes"), dict):
            scopes.extend(s for s in list(body["scopes"])[:MAX_SCOPES] if _word(s))
    scopes = list(dict.fromkeys(scopes))[:MAX_SCOPES]
    for flow_name, grant in names.items():
        body = flows.get(flow_name)
        if isinstance(body, dict) and _text(body.get("tokenUrl"), 2048):
            return SchemeHint(
                name, "oauth2", AuthType.bearer, grant_type=grant,
                token_url=_text(body.get("tokenUrl"), 2048), scopes=tuple(scopes),
                description=description,
            )
    return SchemeHint(name, "oauth2", AuthType.bearer, scopes=tuple(scopes),
                      description=description)


def _scheme_hint(name: str, raw: Any, *, swagger2: bool) -> SchemeHint | None:
    if not isinstance(raw, dict):
        return None
    kind = _word(raw.get("type"))
    description = _text(raw.get("description"))
    if kind == "http":
        scheme = _word(raw.get("scheme")).lower()
        if scheme == "basic":
            return SchemeHint(name, "http", AuthType.basic, description=description)
        # bearer, and any other Authorization scheme a person pastes whole.
        return SchemeHint(name, "http", AuthType.bearer, description=description)
    if kind == "basic":  # Swagger 2
        return SchemeHint(name, "basic", AuthType.basic, description=description)
    if kind == "apiKey":
        return _api_key_hint(name, raw)
    if kind == "oauth2":
        return _oauth_hint(name, raw, swagger2=swagger2)
    if kind == "openIdConnect":
        return SchemeHint(name, "openIdConnect", AuthType.bearer, description=description)
    return None


def _declared_schemes(data: dict[str, Any]) -> tuple[dict[str, Any], bool]:
    if "swagger" in data:
        defs = data.get("securityDefinitions")
        return (defs if isinstance(defs, dict) else {}), True
    components = data.get("components")
    schemes = components.get("securitySchemes") if isinstance(components, dict) else None
    return (schemes if isinstance(schemes, dict) else {}), False


def _requirements(security: Any) -> list[dict[str, Any]] | None:
    """A ``security`` list, or None when the operation inherits."""
    return security if isinstance(security, list) else None


def _is_protected(requirements: list[dict[str, Any]] | None) -> bool:
    # ``[]`` and ``[{}]`` both mean "no auth required" in OpenAPI.
    return bool(requirements) and all(isinstance(r, dict) and r for r in requirements or [])


def derive_auth_hints(data: dict[str, Any]) -> AuthHints:
    """Suggest how to set up identities for the API this spec describes."""
    raw_schemes, swagger2 = _declared_schemes(data)
    hints: list[SchemeHint] = []
    for name, raw in list(raw_schemes.items())[:MAX_SCHEMES]:
        if not _word(name):
            continue
        hint = _scheme_hint(name[:120], raw, swagger2=swagger2)
        if hint is not None:
            hints.append(hint)

    global_security = _requirements(data.get("security"))
    operations = protected = 0
    used_scopes: list[str] = []
    declared_paths = data.get("paths")
    paths: dict[str, Any] = declared_paths if isinstance(declared_paths, dict) else {}
    for item in paths.values():
        if not isinstance(item, dict):
            continue
        for method, op in item.items():
            if _word(method).lower() not in HTTP_METHODS or not isinstance(op, dict):
                continue
            operations += 1
            if operations > MAX_OPERATIONS:
                break
            own = _requirements(op.get("security"))
            effective = own if own is not None else global_security
            if not _is_protected(effective):
                continue
            protected += 1
            if len(used_scopes) >= MAX_USED:
                continue
            for requirement in (effective or [])[:MAX_SCHEMES]:
                for scheme, scopes in list(requirement.items())[:MAX_SCHEMES]:
                    if _word(scheme):
                        used_scopes.append(scheme)
                    if isinstance(scopes, list):
                        used_scopes.extend(x for x in scopes[:MAX_SCOPES] if _word(x))
        if operations > MAX_OPERATIONS:
            break

    # Schemes the operations actually use first: that is the one to prefill.
    used = set(used_scopes)
    hints.sort(key=lambda h: (h.name not in used, h.name))

    privileged = any(
        token in scope.lower() for scope in used_scopes for token in PRIVILEGE_TOKENS
    ) or any(
        "admin" in {seg.lower() for seg in _word(path).split("/") if seg}
        for path in list(paths)[:MAX_OPERATIONS]
    )
    roles: tuple[RoleHint, ...] = ()
    if privileged:
        roles = (RoleHint("user", 1), RoleHint("admin", 3))

    if operations and not protected and not hints:
        return AuthHints(
            "public",
            "The spec declares no security on any operation. If the API does need a "
            "key, choose a single API key instead.",
            operations, protected, (), (),
        )
    if privileged:
        reason = (
            "Some operations are admin-scoped, so testing whether a normal account "
            "can reach them needs at least a normal and an admin identity."
        )
        return AuthHints("roles", reason, operations, protected, tuple(hints), roles)
    reason = (
        "One key is enough to scan authenticated endpoints. Add a second account's "
        "key to test whether one account can read another's data."
    )
    if not hints:
        reason = (
            "Operations declare security but no scheme describes it; enter how the "
            "key is sent yourself. " + reason
        )
    return AuthHints("single", reason, operations, protected, tuple(hints), ())
