"""Scan orchestration: resolve a scan into a context, run the stages, record the run.

This module is the sequence and nothing else. :func:`_stages` *is* the scan
lifecycle — read it top to bottom — and the work each stage does lives next door:

- ``engine/checks/`` — the engine tier, bounded by the request budget
- ``engine/adjuncts.py`` — external tools, bounded by a wall-clock budget
- ``engine/ai_phases.py`` — the two opt-in AI steps
- ``engine/run_record.py`` — findings, the run archive, per-endpoint coverage

Everything the run reports goes through a :class:`~app.engine.journal.RunJournal`
— findings, progress events, whether a cancel has landed — so the stage sequence
can be exercised against a list-backed fake instead of Postgres. Resource
lifetimes (the HTTP transport, the OAST session) are held by an ``ExitStack``
rather than a hand-written ``finally`` that closed two unrelated things.

Invariants worth preserving: a check that raises is isolated so one failure
never aborts a scan; the request budget is a hard safety ceiling; cancellation
is cooperative and lands at stage boundaries, never inside one; and every
optional tier (AI, OOB, ZAP, Kali, confirmation) degrades to a skip event rather
than failing the run.
"""

from __future__ import annotations

import functools
import logging
import secrets
from collections.abc import Callable, Iterator
from contextlib import ExitStack, contextmanager
from dataclasses import dataclass
from typing import Any, cast

from sqlalchemy.orm import Session

from app.core.pinning import PinPolicy, url_host
from app.core.redact import Redactor
from app.core.vault import UndecryptableSecret, decrypt
from app.engine import adjuncts, ai_phases
from app.engine.adaptive.contracts import AdaptiveSettings
from app.engine.adaptive.runner import run_adaptive
from app.engine.base import (
    DEFAULT_MAX_REQUESTS as DEFAULT_MAX_REQUESTS,
)
from app.engine.base import (
    HttpClient,
    HttpProbe,
    ResolvedCredential,
    ScanContext,
    TargetOperation,
    render_path,
)
from app.engine.execution import (
    _cleanup_provisioned_resources,
    _run_discovery_probe,
    _run_engine_checks,
    announce_missing_identity_pair,
    prepare_credentials,
)
from app.engine.journal import RunRecorder
from app.engine.oob import InteractshClient, NullOobClient, OobClient
from app.engine.transport import AsyncHttpClientBridge
from app.models.finding import Finding
from app.models.scan import Scan, ScanRun
from app.scans.operations import retarget_operations
from app.scans.policy import require_target_allowed
from app.scans.run_options import RunOptions

log = logging.getLogger("aidetector.engine")


def _build_oob_client() -> OobClient:
    """Construct an OAST client from settings, or a Null (inactive) one.

    Never raises: a misconfigured or unreachable OAST server degrades to
    ``NullOobClient`` so OOB problems can never fail a scan.
    """
    from app.core.config import settings

    if not settings.oast_server:
        return NullOobClient()
    try:
        return InteractshClient(
            settings.oast_server,
            token=settings.oast_token or None,
            binary=settings.oast_client_binary,
        )
    except Exception:  # noqa: BLE001 — OOB is optional; never fail a scan
        log.warning("OAST client init failed; OOB disabled", exc_info=True)
        return NullOobClient()


def _parse_spec_safe(spec_text: str | None) -> dict[str, Any] | None:
    """Parse the stored spec text to a dict for schema fuzzing; None on failure."""
    if not spec_text:
        return None
    try:
        from app.specs.parser import load_spec

        return load_spec(spec_text)
    except Exception:  # noqa: BLE001 — fuzzing is best-effort; bad spec → skip it
        return None


def _resolve_credentials(scan: Scan) -> tuple[list[ResolvedCredential], list[str]]:
    """Decrypt the scan's credentials; also return the roles that would not open.

    A secret saved under a different VAULT_KEY used to raise out of the run
    before any event existed, so the scan went ``failed`` with nothing saying
    why. Dropping that identity with a named reason matches how a grant that
    fails to mint is handled.
    """
    resolved: list[ResolvedCredential] = []
    unreadable: list[str] = []
    for c in scan.credential_profiles:
        if c.local_only:
            # No secret on the server; run_scan names it in an event.
            continue
        try:
            secret = decrypt(c.secret_ref)
            refresh_secret = decrypt(c.refresh_secret_ref) if c.refresh_secret_ref else None
        except UndecryptableSecret:
            unreadable.append(c.role)
            continue
        resolved.append(
            ResolvedCredential(
                name=c.name,
                role=c.role,
                privilege=c.privilege,
                tenant=c.tenant,
                auth_type=c.auth_type,
                header_name=c.header_name,
                secret=secret,
                refresh_url=c.refresh_url,
                refresh_secret=refresh_secret,
                refresh_token_field=c.refresh_token_field,
                access_token_field=c.access_token_field,
                grant_type=c.grant_type,
                token_url=c.token_url,
                grant_params=dict(c.grant_params or {}),
            )
        )
    return resolved, unreadable


def _target_operations(scan: Scan) -> list[TargetOperation]:
    return [
        TargetOperation(
            id=str(op.id),
            method=op.method,
            path=op.path,
            params=op.params or [],
            auth_scope=op.auth_scope,
        )
        for op in scan.operations
        if op.enabled
    ]


# ---- the sequence -------------------------------------------------------------


@dataclass(frozen=True)
class Stage:
    """One unit of a run.

    Cancellation is checked *between* stages, never inside one: a stage owns its
    own work and must be allowed to finish it — the write oracles restore what
    they changed, and stopping mid-stage would leave a target dirty.
    """

    name: str
    run: Callable[[], None]
    enabled: bool = True


@dataclass
class _Deps:
    """The collaborators a run was constructed with (tests inject their own)."""

    cascade: Any = None
    planner: Any = None
    concurrency: int = 1


def _engine_stage(ctx: ScanContext, journal: RunRecorder, deps: _Deps) -> None:
    """The engine tier, then the gaps its skipped and failed checks leave in the run."""
    _run_engine_checks(ctx, journal, max_workers=deps.concurrency, planner=deps.planner)
    if ctx.skipped_checks:
        journal.note_skipped(ctx.skipped_checks)
    if ctx.failed_checks:
        journal.note_failed(ctx.failed_checks)


def _run_adaptive_stage(
    ctx: ScanContext, journal: RunRecorder, deps: _Deps, opts: RunOptions
) -> None:
    """Run the Premium validation loop and archive only sanitized trace data."""
    from app.ai.planner import OpusPlanner
    from app.core.config import settings
    planner = deps.planner
    if planner is None:
        try:
            planner = OpusPlanner()
        except Exception:  # pragma: no cover - constructor is side-effect free
            planner = None
    if planner is not None:
        from app.ai.budget import require_budget
        from app.engine.ai_phases import MeteredPlanner

        if (
            require_budget(
                journal.db,
                journal.scan,
                journal.event,
                "AI adaptive refinement",
            )
            is None
        ):
            planner = None
        else:
            # Each refine call claims its own budget and is metered there.
            planner = MeteredPlanner(
                planner, journal.db, journal.scan, journal.event, "AI adaptive refinement"
            )
    history_settings = AdaptiveSettings(
        attempts=cast(Any, opts.adaptive_attempts),
        endpoints=settings.adaptive_endpoints,
        requests=settings.adaptive_requests,
        seconds=settings.adaptive_seconds,
        tokens=settings.adaptive_tokens,
        cost_micros=settings.adaptive_cost_micros,
    )
    findings, history = run_adaptive(
        ctx,
        planner=planner,
        settings=history_settings,
        emit=journal.event,
        cancelled=journal.cancelled,
        # MeteredPlanner has already written each call's ledger row.
        on_ai_usage=None,
    )
    for finding in findings:
        journal.record(finding)
    journal.run_row.adaptive = history
    journal.db.commit()


def _stages(
    ctx: ScanContext, opts: RunOptions, journal: RunRecorder, deps: _Deps
) -> list[Stage]:
    """The run, in order. This list is the scan lifecycle.

    Every optional stage is off by default, and that is a safety property rather
    than a convenience: ``mutate`` writes to the target, ``zap``/``kali``/
    ``confirm`` fire far more traffic than the budget allows, and ``plan``/
    ``adjudicate`` spend tokens.
    """
    from app.engine.security_review import review_security_design

    stages = [
        # Before the engine: reorder operations so the request budget meets the
        # riskiest endpoints first. Advisory only — it never changes what runs.
        Stage(
            "plan",
            lambda: ai_phases.plan_operations(
                journal.db, journal.scan, ctx, journal.run_row, deps.planner, journal.event
            ),
            enabled=opts.plan,
        ),
        # Before the engine: AI proposes extra reflection-payload variants that
        # deepen the rotation pool. Advisory only — it never changes what runs or
        # which findings can exist. Off by default; spends tokens.
        Stage(
            "genai_payloads",
            lambda: ai_phases.generate_payloads(
                journal.db, journal.scan, ctx, journal.run_row, deps.planner, journal.event
            ),
            enabled=opts.genai_payloads,
        ),
        Stage(
            "engine",
            lambda: _engine_stage(ctx, journal, deps),
        ),
        Stage("adjuncts", lambda: _run_adjunct_phase(ctx, opts, journal)),
        # Feed discovery back into the engine: the core checks against the shadow
        # paths the adjuncts just found, on their own separate budget.
        Stage("discovery", lambda: _run_discovery_probe(ctx, journal), enabled=opts.kali),
        Stage(
            "adjudicate",
            lambda: ai_phases.adjudicate_findings(
                journal.db, journal.scan, deps.cascade, journal.event, premium=ctx.premium
            ),
            enabled=opts.adjudicate,
        ),
        Stage(
            "security_review",
            lambda: review_security_design(ctx, journal, deps.planner),
            enabled=opts.security_review,
        ),
        # Last, so a human's verdict outranks the model's on a finding both have
        # judged. Findings are replaced each run; triage is not.
        Stage("triage", journal.apply_triage),
    ]
    if opts.adaptive:
        # Right after the engine tier (by name, so adding a pre-engine stage such
        # as genai_payloads cannot shift it in front of the engine).
        after_engine = next(i for i, s in enumerate(stages) if s.name == "engine") + 1
        stages.insert(
            after_engine,
            Stage(
                "adaptive",
                lambda: _run_adaptive_stage(ctx, journal, deps, opts),
                enabled=ctx.premium,
            ),
        )
    return stages


@contextmanager
def _open_run(
    stack: ExitStack,
    db: Session,
    scan: Scan,
    opts: RunOptions,
    *,
    client: HttpClient | None,
    max_requests: int,
    oob: OobClient | None,
    config_source: dict[str, Any] | None = None,
) -> Iterator[tuple[ScanContext, RunRecorder]]:
    """Build everything a run needs, and register what has to be closed after.

    The transport and the OAST session go on ``stack`` rather than into a
    hand-written ``finally`` that tore down two unrelated resources and reached
    for ``getattr(client, "close", None)`` to do one of them.
    """
    from app.core.config import settings
    from app.scans.domains import clear_target
    from app.scans.journal import SqlRunJournal

    # Re-check on the worker immediately before opening a socket. The API gate
    # may have run minutes earlier, and queued work must not trust stale DNS or
    # a target edited/imported outside the normal route. A public target's
    # ownership proof is repeated here, against the address the run will pin.
    clearance = clear_target(db, scan.tenant_id, scan.target_base_url)
    # One policy for the transport and for the checks that open raw sockets.
    pins = clearance.pin_policy()
    transport = client if client is not None else _open_transport(stack, scan, pins)

    run = _new_run_row(scan, opts, config_source)
    # Routes are composed from the spec *and* the target. Re-derive them before
    # a request goes out, so a route stored under an older target or parser
    # cannot send the whole run to a path that does not exist.
    route_notes: list[tuple[str, str]] = []
    retarget_operations(scan, scan.target_base_url, notes=route_notes)
    target_ops = _target_operations(scan)
    resolved_creds, unreadable_roles = _resolve_credentials(scan)
    # Keep both grant inputs and resulting tokens in the redaction vocabulary.
    # A client secret/password is sensitive even though it must never become a
    # scan credential, and minted tokens are not necessarily pattern-shaped.
    sensitive_values = [
        value for cred in resolved_creds for value in (cred.secret, cred.refresh_secret) if value
    ]
    pending_events = [*route_notes, *_record_left_out_identities(scan, run, unreadable_roles)]

    # Credential grant/refresh URLs are independent egress destinations. Check
    # them before minting and before the probe is constructed.
    ready_creds, cred_events = prepare_credentials(
        resolved_creds,
        allowed=require_target_allowed,
        transport=transport,
        on_secret=sensitive_values.append,
    )
    pending_events.extend(cred_events)
    spec_data = _parse_spec_safe(scan.spec_text)
    pending_events.extend(_spec_events(spec_data, scan.target_base_url))

    # The redactor now knows every secret the scan may send, including minted
    # access tokens/session cookies. Refreshes add their new token dynamically
    # through HttpProbe/ReauthPolicy.
    redactor = Redactor(sensitive_values)
    probe = HttpProbe(
        transport,
        max_requests=max_requests,
        operations=target_ops,
        credentials=ready_creds,
        redact=redactor,
    )
    journal = SqlRunJournal(db, scan, run, redactor, probe)
    journal.begin()
    db.flush()
    journal.event("start", 0, f"scanning {len(target_ops)} operations")
    for stage, message in pending_events:
        journal.event(stage, 0, message)

    if oob is None:
        oob = _build_oob_client()
        stack.callback(functools.partial(_close_oob, oob))

    ctx = ScanContext(
        base_url=scan.target_base_url,
        operations=target_ops,
        credentials=ready_creds,
        probe=probe,
        # New seed each run → rotating payload selection.
        seed=opts.seed if opts.seed is not None else secrets.randbelow(2**31),
        confirm=opts.confirm,
        oob=oob,
        allow_mutation=opts.mutate,
        premium=opts.premium,
        spec=spec_data,
        spec_text=scan.spec_text,
        fuzz_cases=settings.schemathesis_cases_per_scan if opts.fuzz else 0,
        predefined_resource_ids=dict(opts.predefined_resource_ids),
        resource_refine=bool(opts.resource_refine and opts.premium and opts.mutate),
        resource_attempts=opts.resource_attempts,
        check_scope=frozenset(opts.checks),
        redact=redactor,
        pins=pins if client is None else None,
    )

    from app.engine.methodology import build_manifest
    from app.monitoring.correlation import configure_probe

    probe.manifest = build_manifest(ctx, opts.to_dict())
    configure_probe(db, scan, probe)
    run.manifest = probe.manifest

    announce_missing_identity_pair(
        ctx, journal, local_only=sum(1 for c in scan.credential_profiles if c.local_only)
    )
    # Only the AI passes read schema context, so a run without one never looks.
    if opts.adaptive or ctx.resource_refine or opts.security_review:
        _attach_schema_snapshot(db, scan, ctx, journal)

    yield ctx, journal


def _open_transport(stack: ExitStack, scan: Scan, pins: PinPolicy) -> HttpClient:
    """The production transport: rate-limited, pinned, closed with the run."""
    from app.core.config import settings
    from app.core.pinning import PinnedAsyncTransport

    bridge = AsyncHttpClientBridge(
        scan.target_base_url,
        timeout=10.0,
        requests_per_second=min(
            settings.engine_requests_per_second, float(scan.requests_per_second)
        ),
        # Connect to the address the clearance judged, never a later lookup.
        transport=PinnedAsyncTransport(pins),
        url_validator=require_target_allowed,
    )
    stack.callback(bridge.close)
    return cast(HttpClient, bridge)


def _new_run_row(
    scan: Scan, opts: RunOptions, config_source: dict[str, Any] | None
) -> ScanRun:
    """The history row: past runs stay inspectable after findings are replaced.

    It archives which passes ran (the diff needs it) but not the user's resource
    ids: those are target identifiers, and run history is returned by the API.
    """
    archived_options = {k: v for k, v in opts.to_dict().items() if k != "predefined_resource_ids"}
    run = ScanRun(
        run_number=len(scan.runs) + 1,
        options=archived_options,
        config_source=dict(config_source or {}),
        queued_at=scan.queued_at,
        claimed_at=scan.claimed_at,
    )
    scan.runs.append(run)
    return run


def _record_left_out_identities(
    scan: Scan, run: ScanRun, unreadable_roles: list[str]
) -> list[tuple[str, str]]:
    """Record on the run each identity this server run cannot use; return the
    events that name them.

    The record is what makes the diff count the missing identities' findings as
    not re-tested rather than fixed.
    """
    events = [
        (
            "credential_unreadable",
            f"credential '{role}' could not be decrypted: it was saved under a different "
            "VAULT_KEY (the api and worker must share one); that identity was removed "
            "from this run",
        )
        for role in unreadable_roles
    ] + [
        (
            "credential_local_only",
            f"identity '{c.name}' is local-only: its secret stays on the machine that runs "
            "`runpentests run` (every CLI run is local), so this server run left it out",
        )
        for c in scan.credential_profiles
        if c.local_only
    ]
    left_out = sorted(
        c.name
        for c in scan.credential_profiles
        if c.local_only or c.role in unreadable_roles
    )
    if left_out:
        run.gaps = {**(run.gaps or {}), "identities_missing": left_out}
    return events


def _spec_events(spec_data: dict[str, Any] | None, base_url: str) -> list[tuple[str, str]]:
    """The spec's warnings, as events of the run that acts on them.

    They are emitted per run rather than relied on from spec-upload time:
    ``journal.begin`` clears events by design (an event belongs to one run),
    which would otherwise drop a routing warning out of the very log that
    explains why the run 404'd.
    """
    if spec_data is None:
        return []
    from app.specs.parser import routing_warnings, spec_warnings

    return [
        ("spec_warning", warning)
        for warning in (*spec_warnings(spec_data), *routing_warnings(spec_data, base_url))
    ]


def _attach_schema_snapshot(
    db: Session, scan: Scan, ctx: ScanContext, journal: RunRecorder
) -> None:
    """Give the run the newest schema snapshot a local run uploaded, once.

    The server never connects to the target database: schema context is read by
    a CLI run (every one is local) on the CLI machine. Say which snapshot is in use, or
    that there is none, so a review "without schema" is never a silent default.
    """
    from app.db_schema.snapshots import latest_snapshot
    from app.scans.workspace import is_premium

    # Schema context is a premium input; the passes reviewing the spec alone
    # still run for everyone else, exactly as before it moved to local runs.
    if not is_premium(db, scan.tenant_id):
        return
    snap = latest_snapshot(db, scan.id)
    if snap is None:
        journal.event(
            "schema_context_unavailable",
            0,
            "no schema snapshot on this scan — add a schema: block to runpentests.yml "
            "and run `runpentests` from the CLI to give the AI passes table structure",
        )
        return
    ctx.schema_context = snap.context
    tables = len(snap.context["tables"])
    journal.event(
        "schema_context",
        0,
        f"using the schema snapshot from local run #{snap.run_number} "
        f"({tables} table{'' if tables == 1 else 's'}, read {snap.captured_at[:10]})",
    )


def _close_oob(client: OobClient) -> None:
    """Tear down a persistent OAST session. Never raises."""
    close = getattr(client, "close", None)
    if not callable(close):
        return
    try:
        close()
    except Exception:  # noqa: BLE001 — cleanup must never mask a result
        log.warning("OOB client close failed", exc_info=True)


def _record_cleanup_gaps(ctx: ScanContext, journal: RunRecorder) -> None:
    """Keep cleanup failures in the run archive, not only in the event log."""
    run_row = getattr(journal, "run_row", None)
    if run_row is None or not ctx.cleanup_failures:
        return
    gaps = dict(run_row.gaps or {})
    gaps["cleanup_failed"] = [
        *gaps.get("cleanup_failed", []),
        *ctx.cleanup_failures,
    ]
    run_row.gaps = gaps


def _archive_diagnostics(ctx: ScanContext, journal: RunRecorder) -> None:
    run_row = getattr(journal, "run_row", None)
    if run_row is None:
        return
    run_row.check_timings = {
        key: dict(value) for key, value in ctx.check_timings.items()
    }


def run_scan(
    db: Session,
    scan: Scan,
    *,
    options: RunOptions | None = None,
    client: HttpClient | None = None,
    max_requests: int = DEFAULT_MAX_REQUESTS,
    cascade: Any = None,
    planner: Any = None,
    oob: OobClient | None = None,
    config_source: dict[str, Any] | None = None,
) -> list[Finding]:
    """Run every check against the scan's target and persist findings.

    ``options`` selects the opt-in passes; every flag defaults to off, so a bare
    call performs a read-only engine scan and nothing else. ``client`` lets tests
    inject an in-process app client; in production it is a real rate-limited
    httpx client bound to the target. ``cascade``/``planner``/``oob`` are
    injection seams for tests. ``config_source`` records where the settings came
    from (a project file) on the run; it never changes what the run does.
    """
    from app.core.config import settings

    opts = options or RunOptions()
    deps = _Deps(
        cascade=cascade,
        planner=planner,
        # An injected client is a sync in-process app: run checks serially so the
        # event order is deterministic and the client is not shared across threads.
        concurrency=settings.engine_concurrency if client is None else 1,
    )

    with ExitStack() as stack:
        with _open_run(
            stack,
            db,
            scan,
            opts,
            client=client,
            max_requests=max_requests,
            oob=oob,
            config_source=config_source,
        ) as (ctx, journal):
            try:
                for stage in _stages(ctx, opts, journal, deps):
                    if not stage.enabled:
                        continue
                    if journal.cancelled():
                        _archive_diagnostics(ctx, journal)
                        return journal.cancel()
                    try:
                        stage.run()
                    finally:
                        for failure in ctx.cleanup_failures:
                            journal.event("cleanup_failed", journal.progress, failure)
                        _record_cleanup_gaps(ctx, journal)
                        ctx.cleanup_failures.clear()
                        journal.note_budget()
            except Exception as exc:
                _archive_diagnostics(ctx, journal)
                journal.fail(exc)
                raise
            finally:
                _cleanup_provisioned_resources(ctx, journal)
                for failure in ctx.cleanup_failures:
                    journal.event("cleanup_failed", journal.progress, failure)
                _record_cleanup_gaps(ctx, journal)
                ctx.cleanup_failures.clear()
            _archive_diagnostics(ctx, journal)
            return journal.complete()


# ---- what each stage does -----------------------------------------------------


def _target_drift(ctx: ScanContext) -> Callable[[], str | None] | None:
    """The adjunct tools resolve the target themselves and cannot be pinned, so
    each runs only while a fresh lookup still agrees with the run's pin."""
    pins = ctx.pins
    if pins is None:
        return None
    host = url_host(ctx.base_url)
    return lambda: pins.drift(host)


def _run_adjunct_phase(ctx: ScanContext, opts: RunOptions, journal: RunRecorder) -> None:
    """Queue and run the enabled external passes under one wall-clock budget.

    These tools manage their own requests, so the phase can only stop at a pass
    boundary — the budget and the cancel check live *between* passes, inside
    :class:`adjuncts.AdjunctPhase`.
    """
    from app.core.config import settings

    db, scan, redactor, emit = journal.db, journal.scan, journal.redactor, journal.event
    phase = adjuncts.AdjunctPhase(
        scan,
        emit,
        budget_seconds=settings.adjunct_budget_seconds,
        cancelled=journal.cancelled,
        drift=_target_drift(ctx),
    )
    # Rendered URLs of the enabled operations: an API's base URL usually links
    # to nothing, so ZAP/Kali need the spec's paths to reach the documented
    # endpoints instead of scanning only the root.
    spec_urls = [
        scan.target_base_url.rstrip("/") + render_path(op.path, {}) for op in ctx.operations
    ]

    if opts.zap:
        phase.add("zap", lambda: adjuncts.run_zap(db, scan, emit, redactor, spec_urls))
    if opts.confirm:
        for name, fn in adjuncts.confirm_passes(
            db,
            scan,
            emit,
            deadline=phase.deadline,
            should_stop=journal.cancelled,
            redactor=redactor,
            independent_targets=ctx.confirmation_targets,
        ):
            phase.add(name, fn)
    if opts.testssl:
        phase.add("testssl", lambda: adjuncts.run_testssl(db, scan, emit, redactor))
    if opts.kali:
        phase.add(
            "kali",
            lambda: adjuncts.run_kali(
                db,
                scan,
                emit,
                redactor,
                spec_urls,
                rate_limit=max(
                    1,
                    int(
                        min(
                            settings.engine_requests_per_second,
                            float(scan.requests_per_second),
                        )
                    ),
                ),
                should_stop=journal.cancelled,
            ),
        )

    phase.run()


