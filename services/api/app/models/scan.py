"""Core scan spine: a Scan and its enumerated Operations.

This is the phase-0 baseline. Later phases add credential_profiles, test_runs,
findings, token_ledger, and scan_events (see the execution plan §3).
"""
from __future__ import annotations

import enum
import uuid
from datetime import datetime

from sqlalchemy import Boolean, CheckConstraint, DateTime, Enum, ForeignKey, String, Text, true
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.models.base import Base, created_at_col, uuid_pk


class ScanStatus(str, enum.Enum):
    draft = "draft"
    queued = "queued"
    running = "running"
    completed = "completed"
    failed = "failed"
    cancelled = "cancelled"


class Scan(Base):
    __tablename__ = "scans"
    __table_args__ = (
        CheckConstraint(
            "requests_per_second BETWEEN 1 AND 100",
            name="ck_scans_requests_per_second",
        ),
    )

    id: Mapped[uuid.UUID] = uuid_pk()
    tenant_id: Mapped[str] = mapped_column(String(120), default="default", index=True)
    target_base_url: Mapped[str] = mapped_column(String(2048))
    status: Mapped[ScanStatus] = mapped_column(
        Enum(ScanStatus, name="scan_status"), default=ScanStatus.draft
    )
    # Cost in integer cents; populated from the token ledger as AI phases run.
    cost_cents: Mapped[int] = mapped_column(default=0)
    # 0-100, updated as the async job runs.
    progress: Mapped[int] = mapped_column(default=0)
    # Saved traffic cadence used by manual and scheduled runs. The deployment
    # setting remains an upper ceiling when the worker builds its transport.
    requests_per_second: Mapped[int] = mapped_column(default=10, server_default="10")
    # Cooperative cancel: the runner checks this between checks.
    cancel_requested: Mapped[bool] = mapped_column(default=False)
    # Why the latest run failed, redacted and short. A failed scan with no reason
    # leaves the user nothing to act on; cleared when a run starts.
    failure_reason: Mapped[str | None] = mapped_column(Text, default=None)
    # Liveness: stamped when the scan is queued, when a worker claims it, and on
    # a timer while it runs. The reaper fails a scan whose stamp goes stale, so a
    # crashed worker cannot leave it `running` — undeletable, un-rerunnable and
    # skipped by its schedule — forever.
    heartbeat_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    # Queue latency is measured from these two columns. heartbeat_at is
    # overwritten at claim, so it cannot answer "how long did this wait?".
    queued_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    claimed_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    # Optional recurring schedule: re-run every N minutes, due at next_run_at.
    schedule_minutes: Mapped[int | None] = mapped_column(nullable=True)
    next_run_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True, index=True
    )
    # The RunOptions a scheduled run is launched with, saved when someone sets
    # the schedule (and affirms authorization). Empty means a default read-only
    # scan — a schedule never widens what it was authorized to do.
    schedule_options: Mapped[dict] = mapped_column(
        JSONB, default=dict, server_default="{}"
    )
    # Raw uploaded spec text, kept so the UI can prefill the spec editor.
    # Null for scans created before this column existed.
    spec_text: Mapped[str | None] = mapped_column(Text, nullable=True)
    # Real uploaded OpenAPI/Swagger versus a HAR/Postman-derived contract.
    # Legacy rows retain unknown provenance.
    spec_origin: Mapped[str] = mapped_column(
        String(16), default="unknown", server_default="unknown"
    )
    # When the current spec was last successfully ingested. Setup timing starts
    # at created_at; a scan created before this column existed has None.
    spec_uploaded_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    # Human triage that must outlive a re-run: finding fingerprint → verdict.
    # Written when someone confirms or dismisses a finding, re-applied after the
    # next run records its findings. Without it a dismissed false positive comes
    # back unreviewed every time and nobody trusts the list.
    triage: Mapped[dict] = mapped_column(JSONB, default=dict, server_default="{}")
    # Which settings a project file (aidetector.yml) owns, set by the CLI each
    # time it runs from one: {path, digest, commit, fields, identities,
    # updated_at}. Empty means the web owns everything. The web marks these
    # settings read-only; nothing server-side refuses an edit, because the CLI
    # applies the file through the same API.
    managed_config: Mapped[dict] = mapped_column(JSONB, default=dict, server_default="{}")
    created_at: Mapped[datetime] = created_at_col()

    operations: Mapped[list[Operation]] = relationship(
        back_populates="scan", cascade="all, delete-orphan"
    )
    runs: Mapped[list[ScanRun]] = relationship(
        back_populates="scan",
        cascade="all, delete-orphan",
        order_by="ScanRun.started_at",
    )
    credential_profiles = relationship(
        "CredentialProfile",
        back_populates="scan",
        cascade="all, delete-orphan",
    )
    findings = relationship(
        "Finding",
        back_populates="scan",
        cascade="all, delete-orphan",
    )
    events = relationship(
        "ScanEvent",
        back_populates="scan",
        cascade="all, delete-orphan",
        order_by="ScanEvent.created_at",
    )
    ledger = relationship(
        "TokenLedger",
        back_populates="scan",
        # Deleting a scan archives no refund: the tenant keeps the spend. The
        # row's scan_id is nulled by the database (ON DELETE SET NULL) rather
        # than cascading the ledger away with the scan.
        passive_deletes=True,
    )
    adjudication_cache = relationship(
        "AdjudicationCache",
        back_populates="scan",
        cascade="all, delete-orphan",
    )

    @property
    def cost_usd(self) -> float:
        return sum(entry.cost_micros for entry in self.ledger) / 1_000_000


class ScanRun(Base):
    """One execution of a scan — the re-run history.

    Re-running a scan replaces its live findings/events, so each run archives
    a findings snapshot here to keep past results inspectable.
    """

    __tablename__ = "scan_runs"

    id: Mapped[uuid.UUID] = uuid_pk()
    scan_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("scans.id", ondelete="CASCADE"), index=True
    )
    run_number: Mapped[int] = mapped_column(default=1)
    status: Mapped[str] = mapped_column(String(20), default="running")
    started_at: Mapped[datetime] = created_at_col()
    #: The queue/claim moments this run inherited from the scan, archived so
    #: history keeps the delay even after the scan row is reused.
    queued_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    claimed_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    finished_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    findings_count: Mapped[int] = mapped_column(default=0)
    # The RunOptions this run executed with. A diff needs it: a finding only an
    # opt-in pass can produce is "not re-tested", not "fixed", when the newer
    # run left that pass off. Empty for runs recorded before this column.
    options: Mapped[dict] = mapped_column(JSONB, default=dict, server_default="{}")
    # HTTP requests the engine probe made during this run.
    requests: Mapped[int] = mapped_column(default=0)
    # Archived minimal finding payloads (check/severity/title/verdict).
    findings_snapshot: Mapped[list] = mapped_column(JSONB, default=list)
    # Per-operation activity: one row per operation with the requests fired, the
    # checks that touched it, and its finding count — "what we did to each endpoint".
    coverage: Mapped[list] = mapped_column(JSONB, default=list)
    manifest: Mapped[dict] = mapped_column(JSONB, default=dict, server_default="{}")
    #: Per-check wall time and request count, for the operator's slow-check view.
    check_timings: Mapped[dict] = mapped_column(
        JSONB, default=dict, server_default="{}"
    )
    # What this run was asked to do and did not: ``not_run`` names adjunct tools
    # that were requested but unavailable or out of time, ``budget_exhausted``
    # says the request cap was hit. ``options`` stays the request; this is the
    # outcome, and the diff reads both so a pass that never ran cannot "fix" a
    # finding.
    gaps: Mapped[dict] = mapped_column(JSONB, default=dict, server_default="{}")
    # Optional AI pre-scan plan: per-operation risk priority + rationale used to
    # order the scan (empty unless the run used plan:true).
    plan: Mapped[list] = mapped_column(JSONB, default=list)
    # Sanitized adaptive validation timeline and bounded run totals.
    adaptive: Mapped[dict] = mapped_column(JSONB, default=dict, server_default="{}")
    # Advisory AI design suggestions are not detected vulnerabilities.
    security_review: Mapped[dict] = mapped_column(JSONB, default=dict, server_default="{}")
    # Resources the mutation-gated setup pass created, for the run report:
    # resource name, create/read routes, status. No ids or target values.
    resources: Mapped[list] = mapped_column(JSONB, default=list, server_default="[]")
    # Request/response trace of every probe call (read and write): header names,
    # safe operational values, and a redacted/truncated response body sample.
    mutations: Mapped[list] = mapped_column(JSONB, default=list, server_default="[]")
    # Who executed this run. Empty ({}) means the server's own Celery worker — the
    # default and only path before the local runner. A locally-run scan records
    # {"kind": "local_runner", "version": "...", "engine_digest": "..."} so a
    # reader (and the diff) can tell a client-run result from a server one.
    executor: Mapped[dict] = mapped_column(JSONB, default=dict, server_default="{}")
    # Where this run's settings came from: {path, digest, commit} when the CLI
    # ran from a project file, empty ({}) when they came from the web. The diff
    # compares path + digest, so a changed file reads as a partial comparison.
    config_source: Mapped[dict] = mapped_column(JSONB, default=dict, server_default="{}")
    # Database schema context a *local* run read on the CLI machine:
    # {status, reason, captured_at, tables, warnings}. Structure only — names,
    # types, nullability, lengths, keys; never values. Empty ({}) when the run
    # did not try. The server never connects to the database itself; later
    # runs of the scan reuse the newest available snapshot
    # (``app.db_schema.snapshot.latest_snapshot``).
    schema_context: Mapped[dict] = mapped_column(JSONB, default=dict, server_default="{}")
    # SHA-256 of the per-run bearer token a local runner must present to post
    # events/results to this run. Set at claim, cleared when the run ends, so a
    # late upload after complete/fail/cancel/reap is refused. Null for server runs.
    run_token_hash: Mapped[str | None] = mapped_column(
        String(64), nullable=True, index=True
    )

    scan: Mapped[Scan] = relationship(back_populates="runs")


class Operation(Base):
    __tablename__ = "operations"

    id: Mapped[uuid.UUID] = uuid_pk()
    scan_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("scans.id", ondelete="CASCADE"), index=True
    )
    method: Mapped[str] = mapped_column(String(10))
    path: Mapped[str] = mapped_column(String(2048))
    params: Mapped[list] = mapped_column(JSONB, default=list)
    auth_scope: Mapped[str | None] = mapped_column(String(255), nullable=True)
    # Per-operation opt-out: unchecking an endpoint in the UI excludes it from
    # the run without deleting it. Defaults on so existing rows stay in scope.
    enabled: Mapped[bool] = mapped_column(
        Boolean, default=True, server_default=true(), nullable=False
    )

    scan: Mapped[Scan] = relationship(back_populates="operations")
