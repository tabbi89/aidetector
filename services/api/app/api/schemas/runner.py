"""The local runner's (CLI heavy lane) claim and token-authenticated ingest."""

from __future__ import annotations

import json
import uuid
from typing import Any

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    field_validator,
    model_validator,
)

from app.api.schemas.common import ResponseModel
from app.api.schemas.credentials import CredentialOut
from app.api.schemas.scans import OperationOut
from app.domain.enums import Confidence, Severity


# --- Local runner (CLI heavy lane) ingest ----------------------------------
# A scan whose traffic originates on the CLI machine. The claim hands the runner
# everything it needs to build a ScanContext *except* credential secrets (which
# stay local), plus a per-run bearer token used by every later call.
class TargetPolicy(ResponseModel):
    """What the runner must re-establish about the target from its own machine.

    The server cleared the target from *its* vantage point; the runner resolves
    the name itself, and its resolver (``/etc/hosts``) is the user's. So a target
    cleared as private stays private-only, and a verified one must serve the
    token from the address the runner pins.
    """

    private_only: bool = False
    verification_token: str | None = None


class OastConfig(ResponseModel):
    """The out-of-band collector the runner registers with, when the service has one.

    The token is the collector's, handed to the CLI user for this run; the
    runner masks it in everything it uploads.
    """

    server: str
    token: str | None = None


class LocalRunConfig(ResponseModel):
    """Claim response: the per-run token (returned once) and the run config."""

    run_id: uuid.UUID
    run_number: int
    # The clear bearer token. Present it as X-Run-Token on every runner call;
    # the server stores only its hash and clears it when the run ends.
    token: str
    options: dict[str, Any]
    # The engine request budget and cadence the server issued. The runner cannot
    # raise them, and an upload reporting more requests than this is refused.
    max_requests: int
    requests_per_second: int
    target_base_url: str
    # The scan's spec text, so spec-driven checks (schema fuzzing, design review,
    # declared-field drift) work on the runner. It is the user's own document and
    # holds no credential.
    spec_text: str | None = None
    operations: list[OperationOut]
    # Credential *shapes* only — never a secret. The runner binds secrets locally.
    credentials: list[CredentialOut]
    target_policy: TargetPolicy = Field(default_factory=TargetPolicy)
    oast: OastConfig | None = None
    # The wall-clock budget the adjunct phase (ZAP, Kali, …) shares, when the
    # run asked for a pass that uses it. The CLI starts those tools as sibling
    # containers and passes their URLs into the runner config.
    adjunct_budget_seconds: int = 0


class AuthCheckRequest(BaseModel):
    """Consent for one credential check: it sends live requests to the target."""

    authorized: bool = False


class AuthCheckConfig(ResponseModel):
    """What the local runner needs to check credentials: no run, no token.

    The routes are a few GET operations the server picked; the credentials are
    shapes only — secrets stay on the CLI machine. Nothing is uploaded back.
    """

    target_base_url: str
    operations: list[OperationOut]
    credentials: list[CredentialOut]
    target_policy: TargetPolicy = Field(default_factory=TargetPolicy)
    max_requests: int
    requests_per_second: int


class RunnerEvent(BaseModel):
    stage: str = Field(max_length=60)
    pct: int = Field(default=0, ge=0, le=100)
    message: str = Field(default="", max_length=2000)


class RunnerEventBatch(BaseModel):
    events: list[RunnerEvent] = Field(default_factory=list, max_length=100)


class RunnerHeartbeatOut(ResponseModel):
    cancel: bool


class RunnerPlanOut(ResponseModel):
    """The run's operations in AI priority order, and what the plan step said.

    The events are the runner's to journal, so a local run's event stream
    reads the same as a server run's.
    """

    operation_ids: list[str]
    events: list[RunnerEvent]


class AgentMemoryRow(ResponseModel):
    """One recalled prior finding for the heavy-lane agent."""

    fingerprint: str
    check: str
    severity: str
    confidence: str
    title: str
    hits: int
    # The offline embedding, so the runner can rank recalls locally.
    embedding: list[float] = Field(default_factory=list)


class RunnerMemoryOut(ResponseModel):
    """What prior heavy runs found on this target, for this tenant."""

    memories: list[AgentMemoryRow] = Field(default_factory=list)


class RunnerFinding(BaseModel):
    """One finding a runner uploads. The server re-derives identity, remediation
    and references, so those are not accepted here."""

    check: str = Field(max_length=100)
    owasp_id: str | None = Field(default=None, max_length=40)
    severity: Severity
    confidence: Confidence = Confidence.heuristic
    title: str = Field(max_length=255)
    description: str = Field(default="", max_length=20000)
    evidence: dict[str, Any] = Field(default_factory=dict)
    operation_id: uuid.UUID | None = None
    remediation: str = Field(default="", max_length=4000)


#: Per-row caps on an uploaded trace row. They mirror what ``app/engine/probe.py``
#: retains (4000 characters for a write or an error, a bounded shape), so an honest
#: runner never meets them; a runner holding a stolen token cannot use the trace
#: to park arbitrary data on the server.
_TRACE_TEXT = 4000
_TRACE_SHAPE_CHARS = 8000
_TRACE_HEADERS = 100
_TRACE_HEADER_VALUE = 1000
#: The whole trace's retained body text: the probe's run budget plus one row's
#: detail limit (the row that crossed it keeps its sample).
TRACE_BODY_BUDGET = 512_000 + _TRACE_TEXT
#: The probe's own row cap (``probe._MAX_TRACE_ROWS``).
TRACE_MAX_ROWS = 2000
#: A run's methodology manifest, serialized.
MANIFEST_MAX_CHARS = 256_000


def _bounded_headers(value: Any) -> dict[str, str]:
    if not isinstance(value, dict):
        raise ValueError("headers must be an object")
    if len(value) > _TRACE_HEADERS:
        raise ValueError(f"at most {_TRACE_HEADERS} headers")
    out: dict[str, str] = {}
    for name, item in value.items():
        if len(str(name)) > 200 or len(str(item)) > _TRACE_HEADER_VALUE:
            raise ValueError("a header name or value is too long")
        out[str(name)] = str(item)
    return out


def _bounded_shape(value: Any) -> Any:
    if value is not None and len(json.dumps(value, default=str)) > _TRACE_SHAPE_CHARS:
        raise ValueError(f"a JSON shape is over {_TRACE_SHAPE_CHARS} characters")
    return value


class RunnerTraceRequest(BaseModel):
    """What the runner sent: header names with redacted values, field names, our payload."""

    headers: dict[str, str] = Field(default_factory=dict)
    query_fields: list[str] = Field(default_factory=list, max_length=200)
    json_shape: Any = None
    json_body: str = Field(default="", max_length=_TRACE_TEXT)
    content_bytes: int = Field(default=0, ge=0)

    _headers = field_validator("headers", mode="before")(_bounded_headers)
    _shape = field_validator("json_shape")(_bounded_shape)


class RunnerTraceResponse(BaseModel):
    """What came back: status, redacted headers and a redacted, capped body sample."""

    status: int | None = None
    attempt_statuses: list[int] = Field(default_factory=list, max_length=10)
    headers: dict[str, str] = Field(default_factory=dict)
    content_type: str = Field(default="", max_length=80)
    body_bytes: int = Field(default=0, ge=0)
    body: str = Field(default="", max_length=_TRACE_TEXT)
    truncated: bool = False
    body_omitted: bool = False
    sensitive_fields: list[str] = Field(default_factory=list, max_length=100)
    json_shape: Any = None

    _headers = field_validator("headers", mode="before")(_bounded_headers)
    _shape = field_validator("json_shape")(_bounded_shape)


class RunnerTraceRow(BaseModel):
    """One request the runner made, in the shape the probe records it."""

    model_config = ConfigDict(populate_by_name=True)

    sequence: int = Field(ge=1)
    method: str = Field(max_length=10)
    route: str = Field(max_length=2048)
    check: str = Field(max_length=100)
    pass_: str = Field(default="engine", alias="pass", max_length=40)
    identity: str = Field(default="anonymous", max_length=120)
    elapsed_ms: float | None = None
    error: str | None = Field(default=None, max_length=80)
    request: RunnerTraceRequest = Field(default_factory=RunnerTraceRequest)
    response: RunnerTraceResponse = Field(default_factory=RunnerTraceResponse)


class RunnerAiIn(BaseModel):
    """A local run asking the service to run one planner call on its behalf.

    The runner sends no secrets and no raw bodies — ``payload`` is the already
    redacted, evidence-shaped input the planner mode expects. The service runs
    the planner, prices it on the run's ledger, and enforces the per-run cap.
    """

    mode: str = Field(max_length=40)
    payload: dict[str, Any] = Field(default_factory=dict)


class RunnerAiOut(ResponseModel):
    """The planner's structured result, or an empty one when it was unavailable
    or the per-run AI budget is spent — the runner degrades either way."""

    result: dict[str, Any] = Field(default_factory=dict)


class RunnerComplete(BaseModel):
    findings: list[RunnerFinding] = Field(default_factory=list, max_length=2000)
    # Requests the runner made; checked against the issued budget.
    requests: int = Field(default=0, ge=0)
    coverage: list[dict[str, Any]] = Field(default_factory=list, max_length=4000)
    gaps: dict[str, Any] = Field(default_factory=dict)
    # Reported by the runner for the run record's executor column.
    runner_version: str = Field(default="", max_length=100)
    engine_digest: str = Field(default="", max_length=100)
    # The run's schema read on the CLI machine (runpentests.yml ``schema:``),
    # absent when the project configures none. Deliberately untyped here: the
    # server validates it separately (``db_schema.contracts.accept_upload``) so a
    # snapshot it cannot accept is recorded as such without refusing findings.
    schema_context: Any = None
    # Every request the run made, already redacted by the runner; the server
    # redacts it again before it becomes the run's trace.
    trace: list[RunnerTraceRow] = Field(default_factory=list, max_length=TRACE_MAX_ROWS)
    # The methodology manifest (``engine/methodology.finish_manifest``).
    manifest: dict[str, Any] = Field(default_factory=dict)

    @model_validator(mode="after")
    def _bounded_record(self) -> RunnerComplete:
        retained = sum(len(row.response.body) for row in self.trace)
        if retained > TRACE_BODY_BUDGET:
            raise ValueError(
                f"the trace retains {retained} characters of response body, over the "
                f"run budget of {TRACE_BODY_BUDGET}"
            )
        if len(json.dumps(self.manifest, default=str)) > MANIFEST_MAX_CHARS:
            raise ValueError(f"the manifest is over {MANIFEST_MAX_CHARS} characters")
        return self


class RunnerFail(BaseModel):
    reason: str = Field(default="", max_length=2000)
    # The runner stopped because a cancel was requested: the run ends
    # ``cancelled``, not ``failed``, exactly as a server-side cancel does.
    cancelled: bool = False
