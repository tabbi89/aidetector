"""The DB-free core of a run: engine-tier checks and the discovery probe.

Split out of ``runner.py`` so a run's check execution can be driven without a
database — the same code the server uses, reused by the local runner that
executes a scan on the CLI machine and uploads results. Everything here works
through ``ScanContext`` and the ``RunJournal`` protocol; nothing imports
SQLAlchemy, ``app.models`` or a session, which ``tests/test_layering.py``
enforces. The one persistence touch — writing the AI token ledger during
resource setup — is a function-local import so the module stays pure.
"""
from __future__ import annotations

import functools
import logging
import time
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Any

from app.core.redact import Redactor
from app.core.target_guard import TargetNotAllowed
from app.domain.enums import AuthType, GrantType
from app.engine.checks import ALL_CHECKS
from app.engine.context import ScanContext
from app.engine.contracts import inapplicable, runs_serially
from app.engine.credentials import ResolvedCredential
from app.engine.http_types import HttpClient
from app.engine.journal import RunJournal
from app.engine.probe import HttpProbe

log = logging.getLogger("aidetector.engine.execution")


def prepare_credentials(
    creds: list[ResolvedCredential],
    *,
    allowed: Callable[[str], object],
    transport: HttpClient,
    on_secret: Callable[[str], None],
) -> tuple[list[ResolvedCredential], list[tuple[str, str]]]:
    """Egress-check and mint a run's identities; return the usable ones and events.

    Both lanes — the server worker and the local runner — run this, so the
    credential half of the egress guard cannot drift between them. Grant and
    refresh URLs are egress destinations of their own: ``allowed`` (which raises
    ``TargetNotAllowed``) is answered for each before anything is minted, and a
    refused URL is dropped (``egress_blocked``). A grant that fails to mint
    leaves that identity out of the run (``auth_grant_failed``) rather than
    failing it. ``on_secret`` receives every token a usable identity will send,
    so the caller's redactor knows it before the first request.
    """
    events: list[tuple[str, str]] = []
    for cred in creds:
        for label in ("token_url", "refresh_url"):
            url = getattr(cred, label)
            if not url:
                continue
            try:
                allowed(url)
            except TargetNotAllowed as exc:
                events.append(
                    ("egress_blocked", f"credential '{cred.role}' {label} blocked: {exc}")
                )
                setattr(cred, label, None)

    ready: list[ResolvedCredential] = []
    for cred in creds:
        if cred.grant_type == GrantType.static or cred.mint(transport):
            ready.append(cred)
            if cred.secret:
                on_secret(cred.secret)
            continue
        events.append(
            (
                "auth_grant_failed",
                f"could not mint a token for '{cred.role}' ({cred.grant_type.value}); "
                "that identity was removed from this run",
            )
        )
        # Defence in depth: even if a future caller accidentally keeps this
        # object, the grant's sensitive input cannot become an auth header.
        cred.auth_type = AuthType.none
        cred.secret = ""
    return ready, events


def _run_resource_setup(ctx: ScanContext, journal: RunJournal, planner: Any = None) -> None:
    """Create spec-shaped prerequisite resources for dependent read probes.

    A supplied planner (or a lazily-constructed one) is the J1 fallback: when the
    deterministic seed fails validation, the planner proposes a spec-valid body.
    """
    from app.engine.resource_bootstrap import provision

    if planner is None and ctx.resource_refine:
        try:
            from app.ai.planner import OpusPlanner

            planner = OpusPlanner()
        except Exception:  # pragma: no cover - constructor is side-effect free
            planner = None

    metered = False
    db = getattr(journal, "db", None)
    scan = getattr(journal, "scan", None)
    if ctx.resource_refine and db is not None and scan is not None:
        # Function-local: budget imports SQLAlchemy and the models, which must
        # not reach this module's import graph (see test_layering.py).
        from app.ai.budget import require_budget

        if require_budget(db, scan, journal.event, "AI resource refinement") is None:
            planner = None
        elif planner is not None:
            from app.engine.ai_phases import MeteredPlanner

            # Each proposal claims its own budget and is metered there.
            planner = MeteredPlanner(
                planner, db, scan, journal.event, "AI resource refinement"
            )
            metered = True
    journal.event("resource_setup", journal.progress, "analyzing resource dependencies")

    def record_ai_usage(usages: list[Any]) -> None:
        scan = getattr(journal, "scan", None)
        # A planner wrapped above has already metered each of its calls.
        if scan is not None and not metered:
            # Function-local: ai_phases pulls in SQLAlchemy and the models, which
            # must not reach this module's import graph (see test_layering.py).
            from app.engine.ai_phases import write_ledger

            write_ledger(scan, usages)

    try:
        notes = provision(
            ctx,
            planner,
            schema_context=ctx.schema_context,
            on_ai_usage=record_ai_usage,
        )
    except Exception:  # noqa: BLE001 — setup is best-effort; checks still run
        log.exception("resource setup failed")
        journal.event("resource_setup_skipped", journal.progress, "resource setup unavailable")
        return
    for note in notes:
        journal.event("resource_setup_note", journal.progress, note)
    # A journal without a run row (the list-backed test fake) simply does not
    # archive the created-resource list — the records are a report nicety.
    run_row = getattr(journal, "run_row", None)
    if run_row is not None:
        run_row.resources = list(ctx.created_resources)


def _run_id_seed(ctx: ScanContext, journal: RunJournal) -> None:
    """Resolve path ids from the target's own collection reads, read-only.

    Best-effort like resource setup: a failure leaves checks on spec-valid
    placeholder ids, exactly as before the seed existed.
    """
    from app.engine.id_seed import seed_read_only_ids

    ctx.probe.check_context = "id_seed"
    try:
        notes = seed_read_only_ids(ctx)
    except Exception:  # noqa: BLE001 — seeding is best-effort; checks still run
        log.exception("read-only id seeding failed")
        notes = ["read-only id seeding unavailable"]
    finally:
        ctx.probe.check_context = None
    if notes:
        # One event per run: the seed is setup, not a stage worth a line per id.
        journal.event("id_seed", journal.progress, "; ".join(notes))


def _cleanup_provisioned_resources(ctx: ScanContext, journal: RunJournal) -> None:
    """Tear down resources created by setup after all dependent checks finish."""
    from app.engine.cleanup import cleanup_request

    for delete, path, credential, row in reversed(ctx.resource_cleanups):
        deleted = cleanup_request(ctx, delete, path, headers=credential.headers())
        row["cleanup"] = "deleted" if deleted else "failed"
    ctx.resource_cleanups.clear()
    run_row = getattr(journal, "run_row", None)
    if run_row is not None:
        run_row.resources = list(ctx.created_resources)

def announce_missing_identity_pair(
    ctx: ScanContext, journal: RunJournal, *, local_only: int = 0
) -> None:
    """A cross-identity oracle needs two identities. Say so once, up front:
    otherwise a run where those checks could not execute is indistinguishable
    from one where they executed and found nothing.

    ``local_only`` counts identities a server run left out because their secret
    lives with the local runner; the fix then differs — they exist, just not here.
    """
    if ctx.identity_pair() is not None:
        return
    if ctx.tenants_declared() and len(ctx.credentials) >= 2:
        journal.event(
            "identities_unavailable",
            0,
            f"no cross-tenant pair: {ctx.pair_gap()} — BOLA, seeded BOLA and BOLA on "
            "write cannot run",
        )
        return
    supplied = len(ctx.credentials)
    remedy = (
        f"{local_only} local-only identit{'y' if local_only == 1 else 'ies'} "
        "can only be used by a CLI run (`runpentests run`)"
        if local_only
        else "add a second credential"
    )
    journal.event(
        "identities_unavailable",
        0,
        f"only {supplied} usable identit{'y' if supplied == 1 else 'ies'} supplied — "
        f"verified BFLA, BOLA/BFLA on write, and seeded BOLA cannot run; {remedy}",
    )


def check_failed_message(ctx: ScanContext, key: str, exc: BaseException) -> str:
    """``"bola did not finish: ReadTimeout on GET /users/{id}"``.

    The exception's class and the route template only — never its message,
    which can carry a target URL, a header value or a token. The route comes
    from the spec, but goes through the run's redactor all the same.
    """
    site = ctx.probe.failure_site(key, exc)
    where = f" on {(ctx.redact or Redactor()).text(site)}" if site else ""
    return f"{key} did not finish: {type(exc).__name__}{where}"


def _invoke_check(check: Any, ctx: ScanContext) -> list[Any]:
    key = getattr(check, "key", "?")
    ctx.probe.check_context = key
    return list(check.run(ctx))


def _run_discovery_probe(ctx: ScanContext, journal: RunJournal) -> None:
    """Second engine pass over discovered (undocumented) endpoints — API9.

    Runs only if the adjuncts actually found some. Uses a fresh probe on its own
    budget (``settings.discovery_probe_budget``) sharing the live transport, so
    it never draws down the main 750. Never mutates: a shadow path has no spec
    pairing to restore, so ``allow_mutation`` is forced off regardless of the
    run flag. Every failure is isolated — this is an enhancement, never a way to
    fail a scan.
    """
    from app.core.config import settings
    from app.engine.discovery_probe import relevant_checks, synthetic_operations

    # The local runner's journal carries no scan row; discovery is server-only,
    # but the signature stays honest rather than assuming the ORM.
    scan = getattr(journal, "scan", None)
    existing = list(scan.findings) if scan is not None else []
    ops = synthetic_operations(existing, ctx.operations)
    if not ops:
        return
    checks = [
        c
        for c in relevant_checks(list(ALL_CHECKS), ops)
        if not ctx.check_scope or getattr(c, "key", None) in ctx.check_scope
    ]
    if not checks:
        return

    probe = HttpProbe(
        ctx.probe.client,
        max_requests=settings.discovery_probe_budget,
        operations=ops,
        credentials=ctx.credentials,
        # The same secret-aware redactor the main probe uses. Without it this
        # pass would fall back to pattern-only redaction on the one set of
        # endpoints the spec never declared.
        redact=ctx.redact,
    )
    dctx = ScanContext(
        base_url=ctx.base_url,
        operations=ops,
        credentials=ctx.credentials,
        probe=probe,
        seed=ctx.seed,
        oob=ctx.oob,
        allow_mutation=False,  # shadow paths have no restore path — never write
        spec=None,
        fuzz_cases=0,
        redact=ctx.redact,
        pins=ctx.pins,
    )
    journal.event("discovery_probe", journal.progress, f"probing {len(ops)} discovered endpoint(s)")
    failed: list[str] = []
    for check in checks:
        if journal.cancelled():
            break
        key = getattr(check, "key", "?")
        try:
            reason = inapplicable(check, dctx)
            if reason is not None:
                journal.event(
                    "check_skipped",
                    journal.progress,
                    f"discovery {key} did not run: {reason}",
                )
                continue
            probe.check_context = key
            for ef in check.run(dctx):
                # Synthetic op ids are not rows in the operations table, so a
                # discovered finding is not tied to one (FK would reject it).
                ef.operation_id = None
                journal.record(ef)
        except Exception as exc:  # noqa: BLE001 — isolate a failing discovery check
            log.exception("discovery check %s failed", key)
            failed.append(str(key))
            journal.event(
                "check_failed",
                journal.progress,
                f"discovery {check_failed_message(dctx, key, exc)}",
            )
    if failed:
        # The same gap as a main-pass failure: a discovery finding from this
        # check was not re-tested, so the diff must not call it fixed. The
        # verb is on the recorder, not the narrow port; discovery is server-only.
        ctx.failed_checks.extend(k for k in failed if k not in ctx.failed_checks)
        note_failed = getattr(journal, "note_failed", None)
        if callable(note_failed):
            note_failed(failed)
    # One request log for the run: fold this pass's trace into the probe the
    # archive is built from, tagged so a reader can tell the passes apart.
    ctx.probe.absorb(probe, label="discovery")
    journal.event(
        "discovery_probed",
        journal.progress,
        f"discovery probe used {probe.count} requests over {len(ops)} endpoint(s)",
    )


def _run_engine_checks(
    ctx: ScanContext, journal: RunJournal, *, max_workers: int, planner: Any = None
) -> None:
    """Run read-only checks concurrently; serialize every state-changing oracle.

    Which is which is a property of the check, declared on the check
    (``mutates`` / ``serial_when_mutating``) and read through
    ``base.runs_serially``. The runner used to keep it as two sets of strings
    here, where the author of a new check had no reason to look.

    A cancel stops dispatching further checks and returns; the run then ends at
    the stage boundary, like a cancel landing anywhere else.

    A check that declares itself inapplicable (``base.inapplicable``) is skipped
    with an event saying why. Skipping is not the point — the event is: a check
    with nothing to work against returns nothing, which is exactly what a clean
    result looks like, and a report that cannot tell those apart is a report
    that hides its own blind spots.
    """
    if ctx.confirm and (not ctx.check_scope or "reflected_injection" in ctx.check_scope):
        from app.core.config import settings
        from app.engine.independent_injection import sample_sql_targets

        if settings.sqlmap_bin:
            ctx.confirmation_targets = sample_sql_targets(ctx, min(2, settings.sqlmap_max_targets))
    if ctx.allow_mutation or ctx.predefined_resource_ids:
        _run_resource_setup(ctx, journal, planner)
    # After setup, so a fixture it created or an id the user supplied wins;
    # the read-only seed only fills path resources still unresolved.
    _run_id_seed(ctx, journal)
    in_scope = [
        c for c in ALL_CHECKS if not ctx.check_scope or getattr(c, "key", None) in ctx.check_scope
    ]
    if ctx.check_scope:
        # One event rather than a check_skipped per excluded check: the user chose
        # the scope, so the report states it instead of listing what they left out.
        journal.event(
            "scope",
            journal.progress,
            f"scoped to {len(in_scope)} of {len(ALL_CHECKS)} checks: "
            + ", ".join(getattr(c, "key", "?") for c in in_scope),
        )
    checks = []
    for check in in_scope:
        reason = inapplicable(check, ctx)
        if reason is None:
            checks.append(check)
            continue
        ctx.skipped_checks.append(str(getattr(check, "key", "?")))
        journal.event(
            "check_skipped",
            journal.progress,
            f"{getattr(check, 'key', '?')} did not run: {reason}",
        )
    parallel = [c for c in checks if not runs_serially(c, allow_mutation=ctx.allow_mutation)]
    serial = [c for c in checks if runs_serially(c, allow_mutation=ctx.allow_mutation)]
    completed = 0
    total = max(1, len(checks))

    def advance() -> int:
        nonlocal completed
        completed += 1
        return int(completed / total * 85)

    def persist(check: Any, findings: list[Any]) -> None:
        key = getattr(check, "key", "?")
        for ef in findings:
            journal.record(ef)
        journal.event(key, advance(), f"completed {key}")

    def run_isolated(check: Any, produce: Callable[[], list[Any]]) -> None:
        """Persist a check's findings, or report that it did not finish.

        A check that raised has not "completed with nothing": whatever it would
        have found is unknown. It gets its own event and a gap on the run, so
        the diff calls its older findings not re-tested instead of fixed.
        """
        key = getattr(check, "key", "?")
        started = time.monotonic()
        before = ctx.probe.count
        try:
            persist(check, produce())
        except Exception as exc:  # noqa: BLE001 — isolate a failing check
            log.exception("check %s failed", key)
            ctx.failed_checks.append(str(key))
            journal.event("check_failed", advance(), check_failed_message(ctx, key, exc))
        finally:
            ctx.check_timings[key] = {
                "ms": int((time.monotonic() - started) * 1000),
                "requests": ctx.probe.count - before,
            }

    if max_workers <= 1:
        for check in parallel:
            if journal.cancelled():
                return
            run_isolated(check, functools.partial(_invoke_check, check, ctx))
    else:
        with ThreadPoolExecutor(max_workers=max(1, max_workers)) as pool:
            futures = {pool.submit(_invoke_check, check, ctx): check for check in parallel}
            for future in as_completed(futures):
                if journal.cancelled():
                    for pending in futures:
                        pending.cancel()
                    return
                run_isolated(futures[future], future.result)

    for check in serial:
        if journal.cancelled():
            return
        run_isolated(check, functools.partial(_invoke_check, check, ctx))
    announce_target_health(ctx, journal)


def announce_target_health(ctx: ScanContext, journal: RunJournal) -> None:
    """Say so when the trace shows the run never reached the API (see
    ``engine.target_health``): otherwise a run against a missing route or with
    a rejected key ends looking like a clean one."""
    from app.engine.target_health import diagnose

    rows = list(ctx.probe.mutations)
    for stage, note in diagnose(ctx.base_url, rows, [cred.name for cred in ctx.credentials]):
        journal.event(stage, journal.progress, note)
