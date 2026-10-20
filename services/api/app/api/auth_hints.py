"""Adapt the pure auth-hint derivation to its response schema."""
from __future__ import annotations

from typing import Any

from app.api import schemas
from app.specs.auth_hints import derive_auth_hints


def hints_out(data: dict[str, Any]) -> schemas.AuthHintsOut:
    hints = derive_auth_hints(data)
    return schemas.AuthHintsOut(
        suggested=hints.suggested,
        reason=hints.reason,
        operations=hints.operations,
        protected_operations=hints.protected_operations,
        schemes=[
            schemas.AuthSchemeHintOut(
                name=s.name,
                kind=s.kind,
                auth_type=s.auth_type,
                header_name=s.header_name,
                grant_type=s.grant_type,
                token_url=s.token_url,
                scopes=list(s.scopes),
                description=s.description,
            )
            for s in hints.schemes
        ],
        roles=[schemas.RoleHintOut(name=r.name, privilege=r.privilege) for r in hints.roles],
    )
