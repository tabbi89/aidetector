"""Run requests, schedules, and what an archived run carries: diff, coverage, trace, gaps."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta
from typing import Any, Self

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    field_validator,
    model_validator,
)

from app.ai.security_review import SecurityReview
from app.api.schemas.common import ResourceId, ResourceName, ResponseModel
from app.api.schemas.scans import ConfigSource
from app.domain.enums import Confidence, Severity, Verdict
from app.domain.taxonomy import canonical_taxonomy_id
from app.engine.adaptive.contracts import AdaptiveHistory
from app.models.scan import ScanStatus
from app.scans.run_levels import Lane, ScanLevel, expand
from app.scans.run_options import RunOptions


def _check_key_enum(schema: dict[str, Any]) -> None:
    """Publish the registered engine check keys as the ``checks`` item enum.

    Lazy, because the registry imports every check module and this runs only
    when the OpenAPI document is built.
    """
    from app.engine.checks import ALL_CHECKS

    schema["items"] = {"type": "string", "enum": [c.key for c in ALL_CHECKS]}


class RunFindingOut(ResponseModel):
    check: str
    severity: Severity
    # Absent from snapshots archived before the tier existed — default, not fail.
    confidence: Confidence = Confidence.heuristic
    # Stable identity across runs; empty on snapshots from before it existed.
    fingerprint: str = ""
    title: str
    owasp_id: str | None = None
    verdict: Verdict

    @field_validator("owasp_id", mode="before")
    @classmethod
    def canonicalize_taxonomy(cls, value: str | None) -> str | None:
        return canonical_taxonomy_id(value)


class RunDiffOut(ResponseModel):
    """What changed between two runs of one scan."""

    from_run: int
    to_run: int
    #: Present in the newer run only — a regression, or newly reachable.
    added: list[RunFindingOut] = []
    #: Present in the older run only — fixed, or no longer reachable.
    resolved: list[RunFindingOut] = []
    #: Present in the older run only, but produced by an opt-in pass the newer
    #: run left off — never looked for, so not counted as fixed.
    not_retested: list[RunFindingOut] = []
    #: The two runs used different options, so the comparison is partial.
    options_changed: bool = False
    #: The two runs were executed by different executors (the server worker vs a
    #: local runner). A different vantage point or credential set can make a
    #: finding look fixed or new, so the comparison is partial.
    executor_changed: bool = False
    #: The two runs took their settings from different places — the web vs a
    #: project file, or two different versions of the file.
    config_changed: bool = False
    #: Present in both; carries the newer row.
    unchanged: list[RunFindingOut] = []
    #: Rows on either side with no fingerprint, which cannot be matched. A
    #: non-zero count means one run predates fingerprinting, not that something
    #: went wrong.
    unmatchable: int = 0


class CoverageRow(ResponseModel):
    """What the engine did to one operation during a run."""

    operation_id: uuid.UUID | None = None
    method: str
    path: str
    enabled: bool = True
    requests: int = 0
    checks: list[str] = []
    findings: int = 0


class PlanRow(ResponseModel):
    """The AI planner's risk priority for one operation."""

    operation_id: uuid.UUID | None = None
    method: str
    path: str
    priority: str = "medium"
    rationale: str = ""


class ResourceAttemptRow(ResponseModel):
    """One bounded resource-create attempt, without its request values."""

    number: int
    source: str
    status: int | None = None


class ResourceRow(ResponseModel):
    """One resource the mutation-gated setup pass created, sanitized."""

    resource: str
    create_method: str
    create_path: str
    read_method: str
    read_path: str
    status: str = "created"
    via_ai: bool = False
    cleanup: str = "none"
    source: str = "created"
    attempts: list[ResourceAttemptRow] = []


class MutationRequestRow(ResponseModel):
    """Sanitized request metadata for one trace.

    ``json_body`` is the redacted payload the scanner sent. It is retained where
    a response body is only sampled, because it is data we generated rather than
    the target's — and reading it beside the response is what answers "why was
    this rejected".
    """

    headers: dict[str, str] = {}
    query_fields: list[str] = []
    json_shape: Any = None
    json_body: str = ""
    content_bytes: int = 0


class MutationResponseRow(ResponseModel):
    """Sanitized response metadata for one request trace.

    ``body`` is the redacted, truncated response text — enough to read why a
    write was accepted or rejected, but with secrets/PII masked and cut at the
    trace limit so a scan cannot accumulate target data. It is empty when
    ``body_omitted``: the response was not text, or the run had already spent
    its body budget. ``truncated`` means the retained text was cut short.
    """

    status: int | None = None
    headers: dict[str, str] = {}
    content_type: str = ""
    body_bytes: int = 0
    body: str = ""
    truncated: bool = False
    body_omitted: bool = False
    json_shape: Any = None


class MutationRow(ResponseModel):
    """One request/response trace (read and write).

    Values are redacted, not absent: both bodies are masked by known secret,
    sensitive field name and PII shape before they are stored. ``identity`` is
    the credential whose headers went out — the fact a reviewer needs to read an
    authorization finding, and the one the redacted Authorization header hides.
    ``pass_`` says which pass made the call (``engine`` or ``discovery``); it is
    serialized as ``pass``, which is a Python keyword.
    """

    sequence: int
    method: str
    route: str
    identity: str = "anonymous"
    pass_: str = Field(default="engine", alias="pass")
    elapsed_ms: float | None = None
    # Transport failure class ("ReadTimeout", "ConnectError") when no response
    # came back; null on a row that got one, and on rows archived before it.
    error: str | None = None
    check: str
    request: MutationRequestRow = Field(default_factory=MutationRequestRow)
    response: MutationResponseRow = Field(default_factory=MutationResponseRow)


class RunGaps(ResponseModel):
    """What a run was asked to do and did not.

    ``not_run`` names requested adjunct tools that never ran; ``budget_exhausted``
    says the request cap refused later requests. The diff counts findings those
    gaps could have hidden as not re-tested, never as fixed.
    """

    not_run: list[str] = []
    budget_exhausted: bool = False
    # Identities a server run had to leave out (local-only, or a secret no
    # vault key opens): their authorization findings are not re-tested.
    identities_missing: list[str] = []
    # Engine checks the run skipped as inapplicable: never looked, so not fixed.
    skipped_checks: list[str] = []
    # Engine checks that raised before finishing (a transport timeout, a bug):
    # they did not look everywhere, so not fixed either.
    failed_checks: list[str] = []


class ScanRunOut(ResponseModel):
    manifest: dict[str, Any] = Field(default_factory=dict)
    """One past execution of a scan, with its archived findings.

    ``mutations`` is deliberately **not** included here. A run's request trace is
    hundreds of rows with body samples, and this endpoint returns every run a
    scan has ever had — sending them all would put megabytes on the wire for a
    page that shows a summary. ``trace_count`` says how many rows exist; fetch
    them a page at a time from ``/scans/{id}/runs/{n}/trace``.
    """
    model_config = ConfigDict(from_attributes=True)
    id: uuid.UUID
    run_number: int
    status: str
    started_at: datetime
    finished_at: datetime | None = None
    findings_count: int = 0
    requests: int = 0
    findings_snapshot: list[RunFindingOut] = []
    coverage: list[CoverageRow] = []
    plan: list[PlanRow] = []
    adaptive: AdaptiveHistory = Field(default_factory=AdaptiveHistory)
    security_review: SecurityReview = Field(default_factory=SecurityReview)
    resources: list[ResourceRow] = []
    # The run options this run executed with; empty for runs recorded before
    # options were archived.
    options: dict[str, Any] = {}
    # Who executed this run: empty ({}) is the server's own worker, while
    # {"kind": "local_runner", ...} is a scan run on the CLI machine.
    executor: dict[str, Any] = {}
    # Where the settings came from: {path, digest, commit} for a project file,
    # empty ({}) for the web.
    config_source: dict[str, Any] = {}
    # What the run was asked to do and did not. Empty when it did everything.
    gaps: RunGaps = Field(default_factory=lambda: RunGaps())
    trace_count: int = 0

    @model_validator(mode="after")
    def settle_a_lost_review(self) -> ScanRunOut:
        """A review still "running" long after its run ended was lost, not slow.

        A local run's review is settled by a separate worker; if that worker
        died or its message was lost, nothing else would ever settle it.
        """
        from app.core.config import settings

        if (
            self.security_review.status == "running"
            and self.finished_at is not None
            and datetime.now(UTC) - self.finished_at
            > timedelta(seconds=settings.ai_timeout_seconds + 120)
        ):
            self.security_review = self.security_review.model_copy(
                update={"status": "unavailable", "suggestions": []}
            )
        return self


class RunTraceOut(ResponseModel):
    """One page of a run's request trace."""

    run_number: int
    total: int
    offset: int
    rows: list[MutationRow] = []


class RunAccepted(ResponseModel):
    scan_id: uuid.UUID
    status: ScanStatus


class RunRequest(BaseModel):
    seed: int | None = Field(default=None, ge=0, lt=2**31, strict=True)
    # Safety gate: the caller must affirm authorization to test the target.
    authorized: bool = Field(description="I own or am authorized to security-test this target.")
    # How hard the run looks (app/scans/run_levels.py). Expands into the flags
    # below before any gate runs, and only ever turns flags on. Never implies
    # ``mutate``: writes stay their own explicit act at every level.
    level: ScanLevel | None = None
    # The AI switch: turns on the token-spending passes that fit the level and
    # the lane. Off by default; no level ever turns it on.
    ai: bool = False
    # Opt-in AI cascade — costs tokens, so it's off by default.
    adjudicate: bool = False
    # Static DeepSeek comparison of OpenAPI and optional configured DB metadata.
    security_review: bool = False
    # Opt-in OWASP ZAP pass — heavier, runs outside the engine request budget.
    zap: bool = False
    # Opt-in Kali adjunct pass (nuclei templates + endpoint discovery) — heavier,
    # runs outside the engine request budget, needs the kali service configured.
    kali: bool = False
    # Opt-in write testing (BOLA/BFLA-on-write): the engine MUTATES the target to
    # confirm a write persisted across identities. Off by default — changes state.
    mutate: bool = False
    # Opt-in confirmation tools (sqlmap/dalfox/commix/tplmap) that re-test the
    # engine's leads. Heavy and slow; off by default so a normal scan finishes
    # fast. Bounded by the shared adjunct wall-clock budget.
    confirm: bool = False
    # Opt-in testssl.sh deep TLS audit (HTTPS targets, needs TESTSSL_BIN). Takes
    # minutes, so the Deep level turns it on rather than every run.
    testssl: bool = False
    # Opt-in AI pre-scan plan: the planner ranks operations by risk so the request
    # budget hits the likeliest-vulnerable endpoints first. Costs tokens.
    plan: bool = False
    # Opt-in AI payload design: DeepSeek proposes extra reflection-payload variants
    # that enrich the rotation pool. Spends tokens; advisory like ``plan``.
    genai_payloads: bool = False
    # Opt-in schema-driven fuzzing (Schemathesis): generate boundary/negative
    # inputs from the spec and flag 5xx (unhandled input). Off by default.
    fuzz: bool = False
    # Opt-in heavy-lane bounded whitebox agent (CLI local runner only): a small,
    # capped pass that drives sandboxed tools to confirm/widen the engine's
    # leads. A no-op on the server fast lane. Off by default.
    agent: bool = False
    # Opt-in premium tier: run the paid checks (host-header probing, spec design
    # review, sustained rate-limit, and the confirmation-tier scanners). Off by
    # default; a non-premium tenant is refused at run time.
    premium: bool = False
    # Premium adaptive validation loop; independently opt-in and bounded.
    adaptive: bool = False
    adaptive_attempts: int = Field(default=3, ge=2, le=3)
    # Premium, mutation-gated fixture loop: refine rejected create bodies with AI.
    resource_refine: bool = False
    resource_attempts: int = Field(default=3, ge=2, le=3)
    # Optional resource-name -> id map, e.g. {"merchant": "merchant_123"}.
    # The grammar is declared on the types rather than checked only in a
    # validator, so the published OpenAPI describes what this endpoint actually
    # accepts. It used to advertise a bare object and reject most of it, which
    # made every generated request a 422 against a schema promising 202.
    predefined_resource_ids: dict[ResourceName, ResourceId] = Field(
        default_factory=dict,
        max_length=50,
        # ``patternProperties`` alone still permits any key that does *not*
        # match, which is precisely the hole this is closing: a generated client
        # would keep producing names the endpoint rejects.
        json_schema_extra={"additionalProperties": False},
    )
    # Optional first-run/override value. Omission preserves the scan's saved
    # configuration; the worker also applies the deployment-wide ceiling.
    requests_per_second: int | None = Field(default=None, ge=1, le=100)
    # Optional engine-check scope, e.g. ["security_headers"]. Empty runs every
    # check. It only narrows: a selected write check still needs ``mutate``.
    # The enum is published, not only validated, so a client generating from the
    # schema cannot produce a key the endpoint refuses (see predefined_resource_ids).
    checks: list[str] = Field(
        default_factory=list, max_length=64, json_schema_extra=_check_key_enum
    )
    # Set by the CLI when a project file supplied this run's settings; archived
    # on the run, never an option — it records where settings came from, it
    # does not change what the run does.
    config_source: ConfigSource | None = None

    @field_validator("checks")
    @classmethod
    def _known_checks(cls, value: list[str]) -> list[str]:
        """Reject keys the registry does not know; keep registry (run) order."""
        from app.engine.checks import ALL_CHECKS

        order = [c.key for c in ALL_CHECKS]
        unknown = sorted(set(value) - set(order))
        if unknown:
            raise ValueError(f"unknown checks: {', '.join(unknown)}")
        chosen = set(value)
        return [key for key in order if key in chosen]

    def resolved(self, *, entitled: bool, lane: Lane) -> Self:
        """This request with ``level`` and ``ai`` expanded into plain run flags.

        Every path that starts scans resolves first, so the gates that follow
        (authorization, entitlement, the local-lane refusals) judge the flags
        that will actually run. Expansion only adds flags: an explicit ``true``
        is kept and still answers its gate, while an explicit ``false`` is not
        an opt-out — a level turns that pass on anyway (the web sends every
        flag as an explicit ``false``).
        """
        added = expand(
            self.level, ai=self.ai, writes=self.mutate, entitled=entitled, lane=lane
        )
        return self.model_copy(update=dict.fromkeys(added, True))

    def to_options(self) -> RunOptions:
        """The opt-in passes, as the value object the worker and engine take.

        ``authorized`` is deliberately not carried over: it gates whether a run
        may start, it does not configure one.
        """
        return RunOptions(
            seed=self.seed,
            adjudicate=self.adjudicate,
            security_review=self.security_review,
            zap=self.zap,
            kali=self.kali,
            mutate=self.mutate,
            confirm=self.confirm,
            testssl=self.testssl,
            plan=self.plan,
            genai_payloads=self.genai_payloads,
            fuzz=self.fuzz,
            agent=self.agent,
            premium=self.premium,
            adaptive=self.adaptive,
            adaptive_attempts=self.adaptive_attempts,
            resource_refine=self.resource_refine,
            resource_attempts=self.resource_attempts,
            predefined_resource_ids=self.predefined_resource_ids,
            checks=tuple(self.checks),
        )

    @field_validator("predefined_resource_ids", mode="before")
    @classmethod
    def _normalize_predefined_resource_ids(cls, value: Any) -> Any:
        """Trim names and ids before the declared grammar is applied.

        ``mode="before"`` on purpose: it runs ahead of the type constraints, so
        the pattern is checked against the trimmed value and a hand-typed
        ``{" merchant_id ": " existing-42 "}`` is still accepted. Padding is
        therefore *tolerated* but not *described* — the published schema states
        the trimmed grammar, which is a subset of what is accepted, so a client
        generating from the schema can never produce something this rejects.
        """
        if not isinstance(value, dict):
            return value
        return {
            (k.strip() if isinstance(k, str) else k): (v.strip() if isinstance(v, str) else v)
            for k, v in value.items()
        }


class ScheduleRequest(RunRequest):
    """Enable or clear a recurring schedule.

    Carries the run's own flags because a schedule *is* a standing run request:
    enabling one saves these options for every scheduled run and answers the
    same authorization gate. Clearing (``minutes`` null/0) starts nothing, so
    ``authorized`` defaults to false here rather than being required.
    """

    # Re-run every N minutes; null/0 disables the schedule.
    minutes: int | None = Field(default=None, ge=0, le=100000)
    authorized: bool = Field(
        default=False,
        description=(
            "Must be true to enable a schedule: I own or am authorized to "
            "security-test this target."
        ),
    )
