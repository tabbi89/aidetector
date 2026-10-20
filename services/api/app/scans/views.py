"""Value objects exchanged between the scan service and its callers.

The service layer is not the HTTP layer. These projections keep it from
importing ``app.api.schemas``: a route adapter maps them onto the Pydantic
response models, and a future caller (a CLI, a job, a test) can use the service
without dragging FastAPI into the call graph.

Only the shapes that cross that boundary live here. ORM entities are still
returned directly where the caller needs the live, mutable row.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

from app.domain.enums import AuthType, GrantType


@dataclass
class FindingCountsView:
    """Live findings per severity. Dismissed false positives are not counted."""

    critical: int = 0
    high: int = 0
    medium: int = 0
    low: int = 0
    info: int = 0


@dataclass
class ScanListEntry:
    """One row of the scan index: the row plus the metrics the index shows."""

    scan: Any
    finding_counts: FindingCountsView = field(default_factory=FindingCountsView)
    last_run_at: datetime | None = None


@dataclass(frozen=True)
class CredentialInput:
    """A credential write, already validated by the caller.

    ``secret`` and ``refresh_secret`` are optional on update: omitting one
    keeps the stored ciphertext rather than clearing it.
    """

    name: str
    role: str
    auth_type: AuthType
    header_name: str | None = None
    secret: str | None = None
    privilege: int | None = None
    tenant: str | None = None
    refresh_url: str | None = None
    refresh_secret: str | None = None
    refresh_token_field: str = "refresh_token"
    access_token_field: str = "access_token"
    grant_type: GrantType = GrantType.static
    token_url: str | None = None
    grant_params: dict[str, Any] = field(default_factory=dict)
    # Read on creation only: an identity's locality is fixed once it exists.
    local_only: bool = False
