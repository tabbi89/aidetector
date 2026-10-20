"""A scan, its target, its operations, its spec upload and the config a project file owns."""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Annotated, Any, Literal
from urllib.parse import urlsplit, urlunsplit

from pydantic import (
    AfterValidator,
    BaseModel,
    ConfigDict,
    Field,
    field_validator,
)

from app.api.schemas.common import ResponseModel
from app.api.schemas.credentials import CredentialOut
from app.models.scan import ScanStatus


def _target_base_url(value: str) -> str:
    """A base URL the engine can actually send to.

    Mangled targets used to be stored (two URLs pasted together, a port that is
    not a number) and only surfaced as a failed run. Private/loopback targets
    are deliberately *not* decided here: that policy stays at the run endpoint.
    """
    url = value.strip()
    if not url:
        raise ValueError("target_base_url is required")
    if any(ch.isspace() for ch in url):
        raise ValueError("target_base_url must not contain whitespace")
    try:
        parsed = urlsplit(url)
        _ = parsed.port  # a malformed port raises here
    except ValueError as exc:
        raise ValueError(f"target_base_url is not a valid URL: {exc}") from exc
    if parsed.scheme not in ("http", "https"):
        raise ValueError("target_base_url must start with http:// or https://")
    if not parsed.hostname:
        raise ValueError("target_base_url must include a hostname")
    if parsed.username or parsed.password:
        raise ValueError("target_base_url must not contain credentials — add a credential profile")
    if parsed.query:
        raise ValueError("target_base_url must not contain a query string")
    if parsed.fragment:
        raise ValueError("target_base_url must not contain a fragment")
    # A trailing slash names the same base URL; dropping it keeps the stored
    # value canonical, which is what the engine joins routes onto.
    return urlunsplit(parsed._replace(path=parsed.path.rstrip("/")))


#: The grammar published in the OpenAPI document. Deliberately a subset of what
#: the validator takes (no IPv6 literals or five-digit ports), so a request built
#: from the document — the contract tests generate them — is never refused.
_TARGET_URL_PATTERN = r"^https?://[A-Za-z0-9.-]+(:\d{1,4})?(/[^\s?#@]*)?$"


#: The target as both create and edit accept it — one validator, so a URL the
#: create form took can never be one the edit form refuses.
TargetBaseUrl = Annotated[
    str,
    Field(min_length=1, max_length=2048, json_schema_extra={"pattern": _TARGET_URL_PATTERN}),
    AfterValidator(_target_base_url),
]


class ScanCreate(BaseModel):
    target_base_url: TargetBaseUrl


class ScanUpdate(BaseModel):
    target_base_url: TargetBaseUrl


class OperationOut(ResponseModel):
    model_config = ConfigDict(from_attributes=True)
    id: uuid.UUID
    method: str
    path: str
    params: list[dict[str, Any]] = []
    auth_scope: str | None = None
    enabled: bool = True


class OperationSelection(BaseModel):
    """One entry in a bulk enable/disable request."""

    id: uuid.UUID
    enabled: bool


class OperationsUpdate(BaseModel):
    """Bulk-set which operations are in scope for the run."""

    operations: list[OperationSelection]


class SpecUpload(BaseModel):
    """Inline spec content (JSON or YAML text). File upload uses a separate route."""

    content: str = Field(min_length=1)


#: The settings a project file can own. Each is one control (or group) the web
#: marks read-only while a file manages it.
ManagedField = Literal["target", "spec", "identities", "requests_per_second", "run_options"]


class ConfigSource(BaseModel):
    """Where a run's settings came from when a project file supplied them.

    ``digest`` is the SHA-256 of the file's bytes, so two runs from an unchanged
    file compare equal however many commits sit between them; ``commit`` is
    there for a person reading the run, not for the comparison.
    """

    path: str = Field(min_length=1, max_length=255)
    digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    commit: str | None = Field(default=None, pattern=r"^[0-9a-f]{7,64}$")


class ManagedConfigIn(ConfigSource):
    """What the CLI reports a project file owns on this scan."""

    fields: list[ManagedField] = Field(default_factory=list, max_length=8)
    # Identities are owned by name: one the file lists is managed, one that
    # exists only in the web is left alone.
    identities: list[Annotated[str, Field(min_length=1, max_length=120)]] = Field(
        default_factory=list, max_length=50
    )


class ScanOut(ResponseModel):
    model_config = ConfigDict(from_attributes=True)
    id: uuid.UUID
    tenant_id: str
    target_base_url: str
    status: ScanStatus
    progress: int
    cancel_requested: bool
    requests_per_second: int
    cost_cents: int
    cost_usd: float = 0.0
    # Why the latest run failed (redacted); None unless status is failed.
    failure_reason: str | None = None
    schedule_minutes: int | None = None
    next_run_at: datetime | None = None
    # The run options every scheduled run uses; empty when no schedule is set.
    # Stored whole (a scheduled run needs its resource ids) but returned without
    # predefined_resource_ids: those are target identifiers the UI promises are
    # never written to reports, and this model also feeds the JSON export.
    schedule_options: dict[str, Any] = {}

    @field_validator("schedule_options")
    @classmethod
    def _hide_resource_ids(cls, value: dict[str, Any]) -> dict[str, Any]:
        return {k: v for k, v in value.items() if k != "predefined_resource_ids"}

    # Raw uploaded spec, so the UI can prefill the spec editor.
    spec_text: str | None = None
    created_at: datetime
    operations: list[OperationOut] = []
    credential_profiles: list[CredentialOut] = []
    # Settings a project file owns (see ManagedConfigIn); {} when the web owns all.
    managed_config: dict[str, Any] = {}


class ScanProgressOut(ResponseModel):
    """The volatile scan state, built from the row alone.

    ``ScanOut`` eager-loads operations, credentials, findings, events and the
    token ledger. The one-second progress poll must not pay for any of them, so
    this response carries only columns that change while a run is in flight.
    """

    model_config = ConfigDict(from_attributes=True)
    id: uuid.UUID
    status: ScanStatus
    progress: int
    cancel_requested: bool
    failure_reason: str | None = None
    heartbeat_at: datetime | None = None
    cost_cents: int
    schedule_minutes: int | None = None
    next_run_at: datetime | None = None
    created_at: datetime


class SpecSkipOut(ResponseModel):
    """One path item or method the parser dropped, and why.

    ``method`` is absent when the whole path item was unusable, so the user sees
    ``/orders — path item is not an object`` rather than a bare path.
    """

    path: str
    method: str | None = None
    reason: str


class SpecReportOut(ResponseModel):
    """What a spec upload parsed, dropped and complained about."""

    operations: int
    skipped: list[SpecSkipOut]
    warnings: list[str]


class SpecUploadOut(ScanOut):
    """A spec upload's scan plus its parse report, which the wizard displays."""

    spec_report: SpecReportOut


class FindingCounts(ResponseModel):
    """Live findings per severity. Dismissed false positives are not counted."""

    critical: int = 0
    high: int = 0
    medium: int = 0
    low: int = 0
    info: int = 0


class ScanSummary(ResponseModel):
    model_config = ConfigDict(from_attributes=True)
    id: uuid.UUID
    tenant_id: str
    target_base_url: str
    status: ScanStatus
    progress: int
    cancel_requested: bool
    requests_per_second: int
    schedule_minutes: int | None = None
    # Filled by ``scans.service.list_scans``; a scan serialized straight off the
    # ORM row (the cancel handler) carries zeros rather than a missing field.
    finding_counts: FindingCounts = Field(default_factory=FindingCounts)
    # ``started_at`` of the newest run, or null before the first one.
    last_run_at: datetime | None = None
    created_at: datetime


class ScanEventOut(ResponseModel):
    model_config = ConfigDict(from_attributes=True)
    stage: str
    pct: int
    message: str
    created_at: datetime


class RequestRateUpdate(BaseModel):
    requests_per_second: int = Field(ge=1, le=100)
