"""The local runner — execute a claimed scan here, upload the result.

Every CLI run (``aidetector run``, ``aidetector URL``) claims a scan from the
server (the authorization gate, the request budget and the per-run token are
all answered there), then starts
this process in a throwaway container on the CLI machine. The scan traffic
therefore originates where that machine can reach, and the server never has to.

What it is: the server's own engine tier, run without a database. The checks
only ever needed a ``ScanContext`` and a ``RunJournal``; ``app.engine.execution``
holds that DB-free core, and this module supplies an HTTP-backed journal.
``tests/test_layering.py`` imports it with SQLAlchemy blocked, so it can never
quietly grow a database dependency.

Trust boundaries, deliberately:

- **Secrets arrive on stdin and nowhere else.** Never argv or the environment
  (both are visible to ``ps`` / ``docker inspect``). They are bound to the
  claimed credential *shapes* by role and never sent to the server.
- **Redaction happens here**, before anything leaves the machine — this process
  holds the secrets, the server does not. The server runs a second, pattern-only
  pass over what arrives.
- **The runner holds no API key**, only the per-run token, which is scoped to
  this one run and dies when it ends.
- **The budget and cadence are the server's.** The runner cannot raise them, and
  the server refuses an upload that reports more requests than it issued.
- **``target_guard`` runs with ``allow_private=True``** — reaching internal hosts
  is the point — but cloud-metadata addresses are refused regardless, including
  IPv6 forms that embed an IPv4 one.
- **The target is pinned to what this machine resolved** (``_target_pins``). A
  target the server cleared as private must stay private here, and a verified
  public one must serve the workspace's token from the pinned address, so an
  edited ``/etc/hosts`` cannot point an exempt run at someone else's server.

Only the engine tier runs here in v1. The AI phases need a database session and
the adjuncts need server-side services, so the server refuses them at claim.
"""
from __future__ import annotations

import dataclasses
import json
import logging
import secrets as _secrets
import signal
import sys
import threading
import time
from collections import Counter
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any, TextIO
from urllib.parse import urlsplit

import httpx

from app.core.config import settings
from app.core.ownership import check_http_token
from app.core.pinning import PinnedAsyncTransport, PinPolicy, url_host
from app.core.redact import Redactor
from app.core.target_guard import check_target_allowed, resolve_host
from app.domain.enums import AuthType, GrantType
from app.engine import adjunct_run
from app.engine.base import (
    EngineFinding,
    HttpProbe,
    ResolvedCredential,
    ScanContext,
    TargetOperation,
)
from app.engine.execution import (
    _cleanup_provisioned_resources,
    _run_engine_checks,
    announce_missing_identity_pair,
    prepare_credentials,
)
from app.engine.journal import describe_failure
from app.engine.methodology import finish_manifest, source_digest
from app.engine.oob import InteractshClient, NullOobClient, OobClient
from app.engine.operations import render_path
from app.engine.probe import budget_exhausted_message
from app.engine.transport import AsyncHttpClientBridge
from app.runner.schema import read_local_schema
from app.scans.run_options import RunOptions
from app.specs.parser import load_spec

log = logging.getLogger("aidetector.runner")

#: Events are sent in batches; this is the size at which one is sent early.
_FLUSH_EVERY = 20
#: Seconds between heartbeats. The server's reaper fails a run silent for far
#: longer (``scan_stale_seconds``), so this leaves a wide margin.
_HEARTBEAT_SECONDS = 10.0
_UPLOAD_ATTEMPTS = 3
#: Events held while the server is unreachable. A long outage drops the oldest
#: (progress lines) rather than growing without bound.
_MAX_BUFFERED_EVENTS = 2000
#: Tries the end-of-run drain makes: nothing flushes after it.
_DRAIN_ATTEMPTS = 3
# Preserve routing through already-deployed proxies during the product rename.
RUNNER_USER_AGENT = "aidetector-cli/runner runpentests-cli/runner"

#: Exit codes. The CLI reads the scan's status from the server; these are for a
#: human running the container by hand.
EXIT_OK = 0
EXIT_FAILED = 1
EXIT_BAD_INPUT = 2
EXIT_CANCELLED = 3


class ServerLink:
    """The runner's connection to the server — the per-run token, never an API key."""

    def __init__(self, server: str, run_id: str, token: str, client: httpx.Client | None = None):
        self._client = client or httpx.Client(base_url=server.rstrip("/"), timeout=30.0)
        self._owns_client = client is None
        self._prefix = f"/runner/runs/{run_id}"
        # The hosted proxy sends root-path requests to the API only for an
        # runpentests-cli/ User-Agent (deploy/caddy/Caddyfile); httpx's default
        # lands on the web app, whose 404 reads as a lost run.
        self._headers = {"X-Run-Token": token, "User-Agent": RUNNER_USER_AGENT}

    def post(
        self, path: str, payload: dict[str, Any], *, timeout: float | None = None
    ) -> httpx.Response:
        extra: dict[str, Any] = {} if timeout is None else {"timeout": timeout}
        return self._client.post(
            self._prefix + path, json=payload, headers=self._headers, **extra
        )

    def get(self, path: str) -> httpx.Response:
        return self._client.get(self._prefix + path, headers=self._headers)

    def close(self) -> None:
        if self._owns_client:
            self._client.close()


class HttpRunJournal:
    """``RunJournal`` over the ingest API: events stream up, findings are held.

    Findings are redacted as they are recorded and uploaded once, at the end, in
    the completion bundle — the server persists them through its own
    ``append_finding``, so identity and remediation are the server's.
    """

    def __init__(self, link: ServerLink, redactor: Redactor, out: TextIO | None = None):
        self._link = link
        self._redactor = redactor
        self._out = out if out is not None else sys.stderr
        self._lock = threading.Lock()
        # One flush at a time, so a batch put back after a failed send cannot be
        # overtaken by a later one and the server's log stays in order.
        self._flush_lock = threading.Lock()
        self._events: list[dict[str, Any]] = []
        self.findings: list[dict[str, Any]] = []
        self._progress = 0
        self._cancel = threading.Event()
        #: Set when the server refused us (the run ended or was reaped): there is
        #: nothing left to upload to.
        self.lost = False
        #: Why a stop was requested: "server" (a web cancel) or "signal".
        self.cancel_reason = ""

    # -- RunJournal ----------------------------------------------------------
    @property
    def progress(self) -> int:
        return self._progress

    def event(self, stage: str, pct: int, message: str) -> None:
        message = self._redactor.text(message)
        self._progress = pct
        # "!" marks a check that raised part-way, so it cannot scroll past
        # looking like a completion (the CLI's server-run printer does the same).
        mark = "!" if stage == "check_failed" else " "
        print(f"{mark} {pct:3d}%  {message}", file=self._out, flush=True)
        with self._lock:
            self._events.append({"stage": stage[:60], "pct": pct, "message": message[:2000]})
            full = len(self._events) >= _FLUSH_EVERY
        if full:
            self.flush()

    def record(self, finding: EngineFinding) -> None:
        payload = {
            "check": finding.check,
            "owasp_id": finding.owasp_id,
            "severity": finding.severity.value,
            "confidence": finding.confidence.value,
            "title": self._redactor.text(finding.title)[:255],
            "description": self._redactor.text(finding.description)[:20000],
            "evidence": self._redactor.evidence(finding.evidence),
            "operation_id": finding.operation_id,
            "remediation": (finding.remediation or "")[:4000],
        }
        # Evidence is JSON on the server too; anything exotic becomes its repr.
        with self._lock:
            self.findings.append(json.loads(json.dumps(payload, default=str)))

    def cancelled(self) -> bool:
        return self._cancel.is_set()

    # -- liveness --------------------------------------------------------------
    def request_cancel(self, reason: str) -> None:
        self.cancel_reason = self.cancel_reason or reason
        self._cancel.set()

    def flush(self) -> bool:
        """Send buffered events; the answer carries the cancel flag.

        A batch the server never acknowledged goes back to the front of the
        buffer for the next flush. It used to be dropped, so one timeout lost
        the lines that say what limited the run. A timeout can also mean the
        server stored it, so a retry may repeat a line — a repeated line beats
        a lost one. Returns False only when the send failed.
        """
        with self._flush_lock:
            with self._lock:
                batch, self._events = self._events[:100], self._events[100:]
            if not batch:
                return True
            if self._send("/events", {"events": batch}):
                return True
            with self._lock:
                self._events[:0] = batch
                overflow = len(self._events) - _MAX_BUFFERED_EVENTS
                if overflow > 0:
                    del self._events[:overflow]
            return False

    def drain(self) -> bool:
        """Flush until the buffer is empty, a few tries at most (end of run)."""
        failures = 0
        while failures < _DRAIN_ATTEMPTS:
            with self._lock:
                if not self._events:
                    return True
            if not self.flush():
                failures += 1
                if self.lost:
                    return False
        with self._lock:
            return not self._events

    def heartbeat(self) -> None:
        self.flush()
        self._send("/heartbeat", {})

    def _send(self, path: str, payload: dict[str, Any]) -> bool:
        """Post to the server; False when it should be retried (no answer, or the
        proxy could not reach the API)."""
        try:
            response = self._link.post(path, payload)
        except httpx.HTTPError as exc:
            # A blip must not kill a long scan; the next beat tries again.
            log.warning("could not reach the server (%s): %s", path, type(exc).__name__)
            return False
        if response.status_code in (502, 503, 504):
            # The proxy could not reach the API (a deploy, a restart): retry.
            log.warning("the server was unavailable (%s): HTTP %s", path, response.status_code)
            return False
        if response.status_code >= 500:
            # The API answered and failed on this payload. Resending the same
            # batch would fail the same way and hold back every later event.
            log.warning("the server could not store %s: HTTP %s", path, response.status_code)
            return True
        if response.status_code in (401, 404, 409):
            # The run ended, was reaped, or its token was revoked.
            self.lost = True
            self.request_cancel("lost")
        elif response.status_code == 200 and response.json().get("cancel"):
            self.request_cancel("server")
        return True


def _apply_plan(
    link: ServerLink, journal: HttpRunJournal, operations: list[TargetOperation]
) -> None:
    """Ask the server for the AI pre-scan plan and put the riskiest operations first.

    The server holds the AI runtime and the budget; the runner only reorders what
    it already has. Advisory, like a server run's plan: any failure is a
    ``plan_skipped`` event and the spec order, never a failed run.
    """
    try:
        response = link.post("/plan", {}, timeout=settings.ai_timeout_seconds + 60.0)
    except httpx.HTTPError as exc:
        journal.event(
            "plan_skipped",
            journal.progress,
            f"AI planning unavailable: could not reach the server ({type(exc).__name__})",
        )
        return
    if response.status_code != 200:
        journal.event(
            "plan_skipped",
            journal.progress,
            f"AI planning unavailable: the server answered {response.status_code}",
        )
        return
    body = response.json()
    for ev in body.get("events") or []:
        journal.event(str(ev.get("stage", "plan")), journal.progress, str(ev.get("message", "")))
    rank = {str(op_id): n for n, op_id in enumerate(body.get("operation_ids") or [])}
    # Stable: an operation the plan does not name keeps its spec position, last.
    operations.sort(key=lambda op: rank.get(str(op.id), len(rank)))


def _operations(run: dict[str, Any]) -> list[TargetOperation]:
    return [
        TargetOperation(
            id=str(op["id"]),
            method=op["method"],
            path=op["path"],
            params=op.get("params") or [],
            auth_scope=op.get("auth_scope"),
        )
        for op in run.get("operations") or []
    ]


def _bind_credentials(
    run: dict[str, Any], supplied: dict[str, Any]
) -> tuple[list[ResolvedCredential], list[tuple[str, str]], list[str]]:
    """Attach locally-held secrets to the claimed credential shapes, by name.

    The config map is keyed by credential name, so two identities that share a
    role keep separate secrets. A role-keyed entry is still accepted when that
    role is unique in the claim: it is the shape older CLI configs used. If a
    role is shared, a role key cannot say which identity it belongs to, so the
    affected identities are dropped with a named event rather than one user's
    secret being sent as the other.

    Returns the identities, events to emit once the journal exists, and every
    secret value (for the redactor). An identity whose secret was not supplied
    is dropped with a named reason — the same rule the server applies to a
    secret it cannot decrypt — rather than failing the scan.
    """
    creds: list[ResolvedCredential] = []
    events: list[tuple[str, str]] = []
    sensitive: list[str] = []
    shapes = run.get("credentials") or []
    role_counts = Counter(shape.get("role") or "" for shape in shapes)
    # A name always owns its key. This set makes that rule global: `user` below
    # is both a role and another identity's name, and the named identity's
    # secret must not be handed to the identity that merely has that role.
    names = {shape.get("name") or shape.get("role") or "" for shape in shapes}
    for shape in shapes:
        role = shape.get("role") or ""
        name = shape.get("name") or role
        auth_type = AuthType(shape["auth_type"])
        given = supplied.get(name)
        if given is None and role_counts[role] == 1 and role not in names:
            given = supplied.get(role)
        elif (
            given is None
            and role in supplied
            and role not in names
            and auth_type != AuthType.none
        ):
            events.append((
                "credential_ambiguous",
                f"the supplied secret is keyed by role '{role}', which more than one "
                f"identity uses; key it by name so '{name}' keeps its own secret",
            ))
            continue
        if isinstance(given, str):
            given = {"secret": given}
        if given is None and auth_type != AuthType.none:
            events.append((
                "credential_missing",
                f"no secret was supplied for credential '{name}'; that identity was "
                "removed from this run",
            ))
            continue
        given = given or {}
        secret = given.get("secret") or ""
        refresh_secret = given.get("refresh_secret") or None
        sensitive.extend(v for v in (secret, refresh_secret) if v)
        creds.append(
            ResolvedCredential(
                name=name,
                role=role,
                privilege=shape.get("privilege"),
                tenant=shape.get("tenant"),
                auth_type=auth_type,
                header_name=shape.get("header_name"),
                secret=secret,
                refresh_url=shape.get("refresh_url"),
                refresh_secret=refresh_secret,
                refresh_token_field=shape.get("refresh_token_field") or "refresh_token",
                access_token_field=shape.get("access_token_field") or "access_token",
                grant_type=GrantType(shape.get("grant_type") or "static"),
                token_url=shape.get("token_url"),
                grant_params=dict(shape.get("grant_params") or {}),
            )
        )
    return creds, events, sensitive


def _allowed(url: str) -> None:
    """The runner's egress rule: private hosts are fine, cloud metadata never is."""
    check_target_allowed(url, allow_private=True, allowlist=[])


def _target_pins(run: dict[str, Any], target: str) -> PinPolicy:
    """Re-establish the server's clearance of the target from this machine.

    The server judged the target with *its* resolver; this process resolves the
    name with the user's, and an edited ``/etc/hosts`` can make ``localhost``
    mean a public machine. So the target is resolved once here and pinned, a
    target cleared as private must stay private, and a verified public target
    must serve this workspace's token from the address pinned here.
    """
    policy_in = run.get("target_policy") or {}
    host = (urlsplit(target).hostname or "").lower().rstrip(".")
    pins = PinPolicy(
        allow_private=True,
        private_only=[host] if policy_in.get("private_only") else [],
    )
    # A name this machine cannot resolve is left to the transport, which
    # resolves and judges it on first use; the token check below cannot pass.
    address = pins.address_for(host) if resolve_host(host) else None
    token = policy_in.get("verification_token")
    if token:
        check_http_token(
            target,
            str(token),
            address=address,
            timeout=settings.domain_verification_timeout_seconds,
        )
    return pins


def build_coverage(ctx: ScanContext, findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """One row per operation: what the engine did to it. DB-free ``build_coverage``."""
    per_op: dict[str, int] = {}
    for f in findings:
        if f.get("operation_id"):
            per_op[str(f["operation_id"])] = per_op.get(str(f["operation_id"]), 0) + 1
    rows = []
    for op in ctx.operations:
        per_check = ctx.probe.coverage.get(str(op.id), {})
        outcome = ctx.probe.coverage_outcomes.get(str(op.id), {})
        ok = outcome.get("ok", 0)
        rows.append({
            "operation_id": str(op.id),
            "method": op.method,
            "path": op.path,
            "enabled": True,
            "requests": sum(per_check.values()),
            "responses": outcome.get("responses", 0),
            "ok": ok,
            "exercised": ok > 0,
            "checks": sorted(per_check),
            "findings": per_op.get(str(op.id), 0),
        })
    return rows


def _upload(link: ServerLink, bundle: dict[str, Any]) -> tuple[bool, str]:
    """Post the result, retrying a transient failure: losing findings is the worst outcome."""
    detail = ""
    for attempt in range(1, _UPLOAD_ATTEMPTS + 1):
        try:
            response = link.post("/complete", bundle)
        except httpx.HTTPError as exc:
            detail = f"could not reach the server: {type(exc).__name__}"
        else:
            if response.status_code == 200:
                return True, ""
            try:
                detail = str(response.json().get("detail", ""))
            except ValueError:
                detail = ""
            detail = f"server answered {response.status_code}: {detail}"
            if response.status_code < 500:
                return False, detail  # a refusal will not change on retry
        time.sleep(min(2.0 * attempt, 5.0))
    return False, detail


def execute(cfg: dict[str, Any], link: ServerLink, out: TextIO | None = None) -> int:
    """Run the claimed scan and upload the result. Returns an exit code."""
    out = out if out is not None else sys.stderr
    run = cfg["run"]
    target = run["target_base_url"]
    opts = RunOptions.from_dict(run.get("options") or {})
    operations = _operations(run)
    creds, pending, sensitive = _bind_credentials(run, cfg.get("secrets") or {})
    sensitive.append(run["token"])
    left_out = _left_out(run, creds)

    redactor = Redactor(sensitive)
    journal = HttpRunJournal(link, redactor, out)
    bridge: AsyncHttpClientBridge | None = None
    oob: OobClient | None = None
    stop_beat = threading.Event()
    beat: threading.Thread | None = None
    probe: HttpProbe | None = None
    ctx: ScanContext | None = None
    #: What the schema read reported, uploaded with the results; None when the
    #: project configures no ``schema:`` block.
    schema_record: dict[str, Any] | None = None
    #: Producing-tool names (``kali``/``sqlmap``) the agent could not run, so the
    #: server diff reads their findings as not-retested rather than resolved.
    agent_not_run: set[str] = set()
    source_audit_complete = False
    _cancel_on_signal(journal)

    try:
        # The first thing, before a socket is opened to the target.
        _allowed(target)
        pins = _target_pins(run, target)
        bridge = AsyncHttpClientBridge(
            target,
            timeout=10.0,
            requests_per_second=float(run["requests_per_second"]),
            transport=PinnedAsyncTransport(pins),
            url_validator=_allowed,
        )
        # Grant/refresh URLs are independent egress destinations: checked
        # before minting by the same code the server runs.
        ready, cred_events = prepare_credentials(
            creds, allowed=_allowed, transport=bridge, on_secret=redactor.add_secret
        )
        pending.extend(cred_events)

        # Schema context (aidetector.yml ``schema:``): read here, on this
        # machine, and nowhere else — the server never connects to the database.
        schema_context: dict[str, Any] | None = None
        if cfg.get("schema") is not None:
            schema_record, schema_context = read_local_schema(cfg["schema"], redactor)
            pending.extend(_schema_events(schema_record))

        oob = _oob_client(run, redactor, pending)
        probe = HttpProbe(
            bridge,
            max_requests=int(run["max_requests"]),
            operations=operations,
            credentials=ready,
            redact=redactor,
        )
        spec_text = run.get("spec_text")
        ctx = ScanContext(
            base_url=target,
            operations=operations,
            credentials=ready,
            probe=probe,
            seed=opts.seed if opts.seed is not None else _secrets.randbelow(2**31),
            allow_mutation=opts.mutate,
            premium=opts.premium,
            spec=_load_spec_safe(spec_text),
            spec_text=spec_text,
            fuzz_cases=settings.schemathesis_cases_per_scan if opts.fuzz else 0,
            check_scope=frozenset(opts.checks),
            redact=redactor,
            schema_context=schema_context,
            pins=pins,
            oob=oob,
        )

        journal.event("start", 0, f"scanning {len(operations)} operations from the local runner")
        for stage, message in pending:
            journal.event(stage, 0, message)
        announce_missing_identity_pair(ctx, journal)

        beat = _start_heartbeat(journal, stop_beat)
        # After the beat starts: the plan is one AI call that can outlast the
        # reaper's silence limit, and the heartbeats keep the run alive meanwhile.
        if opts.plan:
            _apply_plan(link, journal, ctx.operations)

        # The in-loop AI passes run their planner calls on the service (no AI
        # runtime or keys here); each is priced and capped there.
        ai_planner = (
            _RemotePlanner(link)
            if (opts.resource_refine or opts.genai_payloads or opts.adaptive)
            else None
        )
        # genai_payloads deepens the reflection pool before the engine runs.
        if opts.genai_payloads and ai_planner is not None:
            from app.engine.payloads import apply_ai_payloads

            apply_ai_payloads(ctx, ai_planner, journal.event)
        try:
            _run_engine_checks(
                ctx, journal, max_workers=settings.engine_concurrency,
                planner=ai_planner if opts.resource_refine else None,
            )
            # adaptive: bounded validation variants after the engine tier.
            if opts.adaptive and ai_planner is not None:
                _run_adaptive(ctx, journal, ai_planner, opts.adaptive_attempts)
            # External tools the CLI started as siblings (ZAP/Kali) or that the
            # runner image carries (confirm/testssl). They run *before* cleanup,
            # as on the server, so they still see the engine's provisioned
            # resources; their traffic leaves this machine.
            agent_not_run.update(_run_adjuncts(cfg, run, ctx, journal, opts, redactor))
        finally:
            _clean_up_provisioned(ctx, journal)
        if cfg.get("source_dir") and not journal.cancelled():
            source_audit_complete = _audit_source(cfg["source_dir"], journal)
        source_index = _annotate_with_source(cfg.get("source_dir"), journal, redactor)
        # Heavy-lane bounded agent: a small, capped pass driving sandboxed tools
        # to confirm/widen the engine's leads. Off unless opts.agent; it never
        # relaxes a safety gate (no writes, allowlisted tools only) and its
        # findings are graded by the engine, not the agent.
        if opts.agent:
            recalls = _recall_memory(link, journal)
            agent_not_run.update(_run_agent(ctx, journal, source_index, recalls))

        if probe.refused:
            journal.event("budget_exhausted", journal.progress, budget_exhausted_message(probe))
        journal.drain()
    except Exception as exc:  # noqa: BLE001 — report any failure to the server, then stop
        reason = describe_failure(exc, redactor)
        print(f"error: {reason}", file=out, flush=True)
        stop_beat.set()
        _finish(link, {"reason": reason})
        return EXIT_FAILED
    finally:
        stop_beat.set()
        if beat is not None:
            beat.join(timeout=2)
        if bridge is not None:
            bridge.close()
        close_oob = getattr(oob, "close", None)
        if callable(close_oob):
            close_oob()

    if journal.lost:
        print("the server no longer accepts this run (ended, reaped or revoked)", file=out)
        return EXIT_CANCELLED
    if journal.cancelled():
        _finish(link, {"reason": "", "cancelled": True})
        print("cancelled", file=out, flush=True)
        return EXIT_CANCELLED

    assert probe is not None and ctx is not None
    bundle = _result_bundle(
        cfg,
        ctx,
        journal,
        gaps={
            "not_run": sorted(agent_not_run),
            "budget_exhausted": bool(probe.refused),
            "identities_missing": left_out,
            "skipped_checks": sorted(set(ctx.skipped_checks)),
            "failed_checks": sorted(set(ctx.failed_checks)),
            "source_audit_complete": source_audit_complete,
        },
    )
    if schema_record is not None:
        bundle["schema_context"] = schema_record
    ok, detail = _upload(link, bundle)
    if not ok:
        print(f"upload failed: {detail}", file=out, flush=True)
        _finish(link, {"reason": f"the runner could not upload its results: {detail}"[:2000]})
        return EXIT_FAILED
    summary = {
        "status": "completed",
        "findings": len(journal.findings),
        "requests": bundle["requests"],
    }
    print(json.dumps(summary), file=sys.stdout, flush=True)
    return EXIT_OK


def _oob_client(
    run: dict[str, Any], redactor: Redactor, pending: list[tuple[str, str]]
) -> OobClient:
    """The out-of-band collector the service named in the claim, or an inactive one.

    The collector's token is masked in everything this run uploads. A collector
    that cannot start (no ``interactsh-client`` in the image, the domain
    unreachable from here) is said out loud: the OOB checks then report
    themselves skipped, never clean.
    """
    oast = run.get("oast") or {}
    server = str(oast.get("server") or "")
    if not server:
        return NullOobClient()
    token = str(oast.get("token") or "") or None
    if token:
        redactor.add_secret(token)
    try:
        client: OobClient = InteractshClient(
            server, token=token, binary=settings.oast_client_binary
        )
    except Exception:  # noqa: BLE001 — OOB is optional; never fail a run
        client = NullOobClient()
    if not getattr(client, "active", False):
        pending.append((
            "oast_unavailable",
            f"the out-of-band collector {server} could not be started on this machine; "
            "the callback checks are skipped",
        ))
        return NullOobClient()
    pending.append(("oast", f"out-of-band callbacks go to {server}"))
    return client


#: Adjunct tools a CLI run can perform (ZAP and Kali run from sibling containers;
#: the confirm tools and testssl need the runner image's binaries, a later slice).
_RUNNER_ADJUNCTS = frozenset(
    {"zap", "kali", "sqlmap", "dalfox", "commix", "tplmap", "testssl"}
)


@dataclass
class _JournalSink:
    """An ``adjunct_run.AdjunctSink`` over the runner's upload journal.

    Findings are recorded through the journal (uploaded at the end); events
    stream up live. ``skipped`` collects the per-tool ``<tool>_skipped`` events
    so the caller can record them in ``gaps.not_run`` — a tool that did not run
    must never read as a clean result.
    """

    journal: HttpRunJournal
    ctx: ScanContext
    skipped: set[str] = dataclasses.field(default_factory=set)

    @property
    def progress(self) -> int:
        return self.journal.progress

    @property
    def target_base_url(self) -> str:
        return self.ctx.base_url

    @property
    def operations(self) -> Sequence[TargetOperation]:
        return self.ctx.operations

    @property
    def findings(self) -> Sequence[Any]:
        # The confirm tools select their leads from the engine's findings; the
        # selectors read the plain upload dicts the journal holds.
        return self.journal.findings

    @property
    def redactor(self) -> Redactor | None:
        return self.ctx.redact

    def record(self, findings: Sequence[EngineFinding]) -> None:
        for ef in findings:
            self.journal.record(ef)

    def event(self, stage: str, pct: int, message: str) -> None:
        if stage.endswith("_skipped"):
            tool = stage[: -len("_skipped")]
            if tool in _RUNNER_ADJUNCTS:
                self.skipped.add(tool)
        self.journal.event(stage, pct, message)


def _adjunct_drift(ctx: ScanContext) -> Callable[[], str | None] | None:
    """The adjunct tools resolve the target themselves and cannot be pinned, so
    each runs only while a fresh lookup still agrees with the run's pin."""
    pins = ctx.pins
    if pins is None:
        return None
    host = url_host(ctx.base_url)
    return lambda: pins.drift(host)


def _run_adaptive(
    ctx: ScanContext, journal: HttpRunJournal, planner: Any, attempts: Any
) -> None:
    """Premium adaptive validation after the engine tier, DB-free.

    Mirrors the server's stage without the DB-backed MeteredPlanner: the
    planner here is remote (the service prices each ``refine`` call), so usage
    metering is the service's and ``on_ai_usage`` is None. Findings flow back
    through the journal; the per-run history is not archived in the runner.
    """
    from app.engine.adaptive.contracts import AdaptiveSettings
    from app.engine.adaptive.runner import run_adaptive

    history_settings = AdaptiveSettings(
        attempts=attempts,
        endpoints=settings.adaptive_endpoints,
        requests=settings.adaptive_requests,
        seconds=settings.adaptive_seconds,
        tokens=settings.adaptive_tokens,
        cost_micros=settings.adaptive_cost_micros,
    )
    findings, _history = run_adaptive(
        ctx,
        planner=planner,
        settings=history_settings,
        emit=journal.event,
        cancelled=journal.cancelled,
        on_ai_usage=None,
    )
    for finding in findings:
        journal.record(finding)


def _run_adjuncts(
    cfg: dict[str, Any],
    run: dict[str, Any],
    ctx: ScanContext,
    journal: HttpRunJournal,
    opts: RunOptions,
    redactor: Redactor,
) -> set[str]:
    """Run the external tools the CLI started as siblings, under one budget.

    The CLI puts each sibling's URL (and per-run API key) in ``cfg['adjuncts']``;
    the keys came in on stdin, never the claim. Returns the tool names that did
    not run, for ``gaps.not_run``.
    """
    if not (opts.zap or opts.kali or opts.confirm or opts.testssl):
        return set()
    adj = cfg.get("adjuncts") or {}
    zap = adj.get("zap") or {}
    kali = adj.get("kali") or {}
    # The pure passes read these from settings, as the server lane does; this is
    # a one-shot process, so setting them here is the runner's env.
    if zap.get("base_url"):
        settings.zap_base_url = str(zap["base_url"])
        settings.zap_api_key = str(zap.get("api_key") or "")
    if kali.get("base_url"):
        settings.kali_base_url = str(kali["base_url"])
        settings.kali_api_key = str(kali.get("api_key") or "")
    # The confirm tools and testssl are binaries baked into the runner image;
    # point settings at them so their passes are queued when present on PATH.
    _enable_local_binaries(opts)
    budget = float(adj.get("budget_seconds") or run.get("adjunct_budget_seconds") or 0)
    sink = _JournalSink(journal, ctx)
    spec_urls = [
        ctx.base_url.rstrip("/") + render_path(op.path, {}) for op in ctx.operations
    ]
    phase = adjunct_run.AdjunctPhase(
        sink,
        budget_seconds=budget,
        cancelled=journal.cancelled,
        drift=_adjunct_drift(ctx),
    )
    if opts.zap:
        phase.add("zap", lambda: adjunct_run.run_zap(sink, spec_urls=spec_urls))
    if opts.kali:
        rate = max(1, int(run.get("requests_per_second") or 10))
        phase.add("kali", lambda: adjunct_run.run_kali(
            sink, spec_urls=spec_urls, rate_limit=rate, should_stop=journal.cancelled,
        ))
    if opts.confirm:
        for name, fn in adjunct_run.confirm_passes(
            sink, deadline=phase.deadline, should_stop=journal.cancelled,
        ):
            phase.add(name, fn)
    if opts.testssl:
        phase.add("testssl", lambda: adjunct_run.run_testssl(sink))
    phase.run()
    return sink.skipped


def _enable_local_binaries(opts: RunOptions) -> None:
    """Point settings at the confirm/testssl binaries the runner image carries.

    The passes gate on ``settings.*_bin``; the server sets them from env, and in
    the runner the binaries are on PATH, so set each to its tool name when
    present. A binary that is not in the image stays unset and its pass reports
    itself skipped rather than running.
    """
    import shutil

    if opts.confirm:
        for tool in ("sqlmap", "dalfox", "commix", "tplmap"):
            if shutil.which(tool) and not getattr(settings, f"{tool}_bin"):
                setattr(settings, f"{tool}_bin", tool)
    if opts.testssl and not settings.testssl_bin:
        for name in ("testssl.sh", "testssl"):
            if shutil.which(name):
                settings.testssl_bin = name
                break


def _left_out(run: dict[str, Any], bound: list[ResolvedCredential]) -> list[str]:
    """Identities dropped for want of a secret: the diff must treat their
    authorization findings as not re-tested, as a server run does."""
    names = {c.name for c in bound}
    return sorted(
        str(c.get("name"))
        for c in run.get("credentials") or []
        if isinstance(c, dict) and c.get("name") not in names
    )


def _cancel_on_signal(journal: HttpRunJournal) -> None:
    """SIGTERM/SIGINT become a cooperative cancel, landing at a check boundary."""

    def on_signal(signum: int, _frame: Any) -> None:
        journal.request_cancel("signal")

    try:
        signal.signal(signal.SIGTERM, on_signal)
        signal.signal(signal.SIGINT, on_signal)
    except ValueError:  # not the main thread (tests); the server-side cancel still works
        pass


def _load_spec_safe(spec_text: str | None) -> dict[str, Any] | None:
    if not spec_text:
        return None
    try:
        return load_spec(spec_text)
    except Exception:  # noqa: BLE001 — spec-driven checks are best-effort
        return None


def _start_heartbeat(journal: HttpRunJournal, stop: threading.Event) -> threading.Thread:
    def beat() -> None:
        while not stop.wait(_HEARTBEAT_SECONDS):
            journal.heartbeat()

    thread = threading.Thread(target=beat, name="runner-heartbeat", daemon=True)
    thread.start()
    return thread


class _RemotePlanner:
    """A planner whose calls run on the service, for a local run's in-loop AI.

    The runner holds no AI runtime or keys; it sends the mode and the redacted,
    evidence-shaped payload to the service, which runs the real planner, prices
    it and caps it. Only the methods a wired pass uses are implemented;
    everything degrades to an empty result so a failure never fails the run.
    """

    def __init__(self, link: ServerLink) -> None:
        self._link = link

    def propose_resource(self, payload: dict[str, Any]) -> tuple[dict[str, Any], list[Any]]:
        try:
            r = self._link.post("/ai", {"mode": "propose_resource", "payload": payload})
            if r.status_code != 200:
                return {}, []
            proposal = (r.json().get("result") or {}).get("proposal") or {}
        except Exception:  # noqa: BLE001 — AI is optional; degrade to no proposal
            return {}, []
        # The service already priced the call; the runner meters nothing.
        return (proposal if isinstance(proposal, dict) else {}), []

    def generate_payloads(self, families: Any) -> tuple[dict[str, Any], list[Any]]:
        try:
            r = self._link.post("/ai", {"mode": "payloads", "payload": {"families": families}})
            if r.status_code != 200:
                return {}, []
            payloads = (r.json().get("result") or {}).get("payloads") or {}
        except Exception:  # noqa: BLE001 — AI optional; fall back to the corpus
            return {}, []
        return (payloads if isinstance(payloads, dict) else {}), []

    def refine(self, payload: dict[str, Any]) -> tuple[dict[str, Any], list[Any]]:
        try:
            r = self._link.post("/ai", {"mode": "adaptive", "payload": payload})
            if r.status_code != 200:
                return {}, []
            proposal = (r.json().get("result") or {}).get("proposal") or {}
        except Exception:  # noqa: BLE001 — AI optional; keep the deterministic variant
            return {}, []
        return (proposal if isinstance(proposal, dict) else {}), []


def _clean_up_provisioned(ctx: ScanContext, journal: HttpRunJournal) -> None:
    """Tear down what the engine created and record any cleanup failures.

    Runs after the adjunct phase (the server's order), so the external tools
    still see the provisioned resources, and runs even when a check raised.
    """
    _cleanup_provisioned_resources(ctx, journal)
    for failure in ctx.cleanup_failures:
        journal.event("cleanup_failed", journal.progress, failure)
    ctx.cleanup_failures.clear()


def _annotate_with_source(source_dir: Any, journal: HttpRunJournal, redactor: Redactor) -> Any:
    """Whitebox: if the project was mounted read-only, point each finding at
    the code that serves it. Evidence enrichment only — never identity (a
    `source` key is not a fingerprint key), and a failure is a skipped event,
    never a failed scan. Returns the index for the agent, or None."""
    source_index = _build_source_index(source_dir, journal)
    if source_index is not None:
        annotated = source_index.annotate_findings(journal.findings, redactor=redactor)
        journal.event(
            "whitebox_source",
            journal.progress,
            f"indexed {source_index.file_count} source file(s); "
            f"added file:line to {annotated} finding(s)",
        )
    return source_index


def _audit_source(source_dir: str, journal: HttpRunJournal) -> bool:
    try:
        from app.runner.source_audit import audit

        findings, complete = audit(
            source_dir, emit=lambda stage, message: journal.event(stage, journal.progress, message),
            cancelled=journal.cancelled,
        )
        for finding in findings:
            journal.record(finding)
        return complete
    except Exception as exc:  # noqa: BLE001 — advisory access cannot fail an API scan
        journal.event("source_audit_gap", journal.progress,
                      f"source advisory checks unavailable: {type(exc).__name__}")
        return False


def _result_bundle(
    cfg: dict[str, Any], ctx: ScanContext, journal: HttpRunJournal, *, gaps: dict[str, Any]
) -> dict[str, Any]:
    """What the server ingests: findings, coverage, the trace, gaps and provenance."""
    engine_dir = Path(__file__).resolve().parents[1] / "engine"
    return {
        "requests": ctx.probe.count + ctx.probe.secondary_requests,
        "findings": journal.findings,
        "coverage": build_coverage(ctx, journal.findings),
        # Every request the run made, redacted here by the probe as it recorded
        # them; the server redacts again before storing them as the run's trace.
        "trace": list(ctx.probe.mutations),
        "manifest": finish_manifest(ctx.probe),
        "gaps": gaps,
        "runner_version": str(cfg.get("runner_version") or "")[:100],
        "engine_digest": source_digest(engine_dir, ("*.py",))[:100],
    }


def _schema_events(record: dict[str, Any]) -> list[tuple[str, str]]:
    """Say what the schema read did, so "no schema" never reads as a default."""
    if record.get("status") != "available":
        return [(
            "schema_context_unavailable",
            f"schema context unavailable on this machine: {record.get('reason') or 'unavailable'}"
            " — the run continues without it",
        )]
    tables = len(record.get("tables") or [])
    events = [(
        "schema_context",
        f"read schema structure for {tables} table{'' if tables == 1 else 's'} on this machine "
        "(names, types and keys only; uploaded with the results)",
    )]
    if "privileged_account" in (record.get("warnings") or []):
        events.append((
            "schema_privileged_account",
            "the schema account has more than metadata privileges; only fixed read-only "
            "catalog queries ran, but a dedicated metadata role limits exposure",
        ))
    return events


def _build_source_index(source_dir: Any, journal: HttpRunJournal) -> Any:
    """Index a mounted source tree for whitebox analysis, or None.

    Best-effort and bounded (see ``app.agent.source``). An absent or empty mount
    emits a ``whitebox_skipped`` event rather than silently reading as clean;
    any failure returns None — whitebox context is an enhancement, never a
    requirement. The import is function-local so ``app.runner.main`` stays pure.
    """
    if not source_dir:
        return None
    try:
        from app.agent.source import SourceIndex

        index = SourceIndex.build(str(source_dir))
        if index is None:
            journal.event(
                "whitebox_skipped",
                journal.progress,
                f"no indexable source at the mounted path {source_dir}",
            )
        return index
    except Exception as exc:  # noqa: BLE001 — never fail a scan on whitebox
        journal.event(
            "whitebox_skipped",
            journal.progress,
            f"whitebox source analysis unavailable: {type(exc).__name__}",
        )
        return None


def _recall_memory(link: ServerLink, journal: HttpRunJournal) -> list[dict]:
    """Ask the server what prior heavy runs found on this target. Best-effort.

    Episodic memory steers the agent and never gates it: any failure returns no
    recalls and the agent runs its deterministic plan unchanged.
    """
    try:
        response = link.get("/memory")
    except httpx.HTTPError:
        return []
    if response.status_code != 200:
        return []
    try:
        rows = response.json().get("memories") or []
    except ValueError:
        return []
    if rows:
        journal.event(
            "agent_memory",
            journal.progress,
            f"recalled {len(rows)} prior finding(s) on this target from earlier heavy runs",
        )
    return [r for r in rows if isinstance(r, dict)]


def _run_agent(
    ctx: ScanContext,
    journal: HttpRunJournal,
    source_index: Any,
    recalls: list[dict],
) -> set[str]:
    """Run the bounded whitebox agent. Returns producing-tool names it could not run.

    Entirely best-effort: a sandbox that is disabled (the default — it needs
    ``AGENT_SANDBOX_ENABLED`` and Docker) makes the loop a clean no-op, and any
    failure is swallowed so the agent can never fail a scan. Imports are
    function-local so ``app.runner.main`` stays DB-free in ``test_layering``.
    """
    try:
        from app.agent.loop import AgentLoop
        from app.agent.sandbox import SANDBOX_TOOLS, Sandbox
        from app.scans.run_options import producing_tool

        # No planner in the local lane: the runner has no database, so a paid
        # call here could neither claim the workspace's AI budget nor reach its
        # ledger, and the claim refuses every AI pass (_LOCAL_REFUSED) for that
        # reason. The loop runs its deterministic order, as it does whenever
        # the planner is absent.
        planner = None

        sandbox = Sandbox()
        outcome = AgentLoop(
            ctx, journal, sandbox, source=source_index, planner=planner, recalls=recalls
        ).run()
        not_run: set[str] = set()
        for tool in outcome.tools_unavailable:
            spec = SANDBOX_TOOLS.get(tool)
            if spec is not None:
                mapped = producing_tool(spec.check_key)
                if mapped:
                    not_run.add(mapped)
        return not_run
    except Exception as exc:  # noqa: BLE001 — the agent never fails a scan
        journal.event(
            "agent_skipped",
            journal.progress,
            f"heavy-lane agent unavailable: {type(exc).__name__}",
        )
        return set()


def _finish(link: ServerLink, payload: dict[str, Any]) -> None:
    """Tell the server the run ended without results. Best-effort."""
    try:
        link.post("/fail", payload)
    except httpx.HTTPError:
        pass  # the reaper will close the run when its heartbeat goes quiet


def _read_config(stream: TextIO) -> dict[str, Any]:
    cfg = json.load(stream)
    run = cfg.get("run")
    needed = ("run_id", "token", "target_base_url", "max_requests", "requests_per_second")
    if not isinstance(cfg.get("server"), str) or not isinstance(run, dict):
        raise ValueError("config needs `server` and `run`")
    missing = [k for k in needed if run.get(k) in (None, "")]
    if missing:
        raise ValueError(f"run is missing: {', '.join(missing)}")
    return cfg


def main(stdin: TextIO | None = None) -> int:
    """Read the claim (and secrets) from stdin, run the scan, upload the result."""
    logging.basicConfig(level=logging.WARNING, format="%(levelname)s %(name)s: %(message)s")
    try:
        cfg = _read_config(stdin if stdin is not None else sys.stdin)
    except (ValueError, json.JSONDecodeError) as exc:
        print(f"error: bad runner config on stdin: {exc}", file=sys.stderr)
        return EXIT_BAD_INPUT
    run = cfg["run"]
    link = ServerLink(cfg["server"], str(run["run_id"]), run["token"])
    try:
        return execute(cfg, link)
    finally:
        link.close()


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())

