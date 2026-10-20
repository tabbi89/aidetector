"""The adjunct phase, free of the database.

External tools (ZAP, the four lead-confirmation tools, testssl, Kali) run
outside the engine's request budget and share one wall-clock deadline. Their
lifecycle and sequencing live here and depend on nothing in the ORM, so both
lanes reuse them: the server wraps a database sink (``app/engine/adjuncts.py``)
and the local runner wraps its journal.

Everything a pass needs from its lane goes through :class:`AdjunctSink`:
findings are *recorded* through it (the server appends to the scan and commits;
the runner uploads), events are emitted through it, and the few scan facts a
pass reads (the target URL, the operations, the engine findings a confirm tool
re-tests) are read from it. No pass imports SQLAlchemy or a model, which
``tests/test_layering.py`` enforces.
"""
from __future__ import annotations

import logging
import shutil
import time
from collections.abc import Callable, Iterator, Sequence
from typing import Any, Protocol, cast
from urllib.parse import urlparse

import httpx

from app.core.redact import Redactor
from app.engine.base import EngineFinding
from app.engine.operations import TargetOperation

#: Tool endpoints one Kali run calls; all of them failing means the service is down.
KALI_PASSES = 6

log = logging.getLogger("aidetector.engine")

#: Emits a progress event: (stage, pct, message).
Emit = Callable[[str, int, str], None]
#: Produces an adjunct's findings, or raises.
Produce = Callable[[], list[EngineFinding]]


class AdjunctSink(Protocol):
    """What an adjunct pass needs from its lane, with no database in sight.

    The server implementation records into the scan and commits; the runner's
    records through its upload journal. ``findings`` is the engine's findings so
    far, which a confirm tool re-tests — ORM rows on the server, and the
    runner's own representation in the runner (the confirm tools stay
    server-only until that representation is shared).
    """

    @property
    def progress(self) -> int: ...

    @property
    def target_base_url(self) -> str: ...

    @property
    def operations(self) -> Sequence[TargetOperation]: ...

    @property
    def findings(self) -> Sequence[Any]: ...

    @property
    def redactor(self) -> Redactor | None: ...

    def record(self, findings: Sequence[EngineFinding]) -> None: ...

    def event(self, stage: str, pct: int, message: str) -> None: ...


class AdjunctUnavailable(RuntimeError):
    """A tool that failed to run, as opposed to one that ran and found nothing.

    The scanners degrade to ``[]`` so a scan never fails on them; a pass raises
    this when the scanner reports why, so the phase says the tool did not run
    instead of "added 0 findings" — which reads as a clean result.
    """


def _reported(scanner: object, found: list[EngineFinding]) -> list[EngineFinding]:
    error = getattr(scanner, "error", None)
    if error:
        raise AdjunctUnavailable(error)
    return found


def run_adjunct(
    sink: AdjunctSink,
    *,
    tool: str,
    start_message: str,
    produce: Produce,
    done_message: Callable[[int], str] | None = None,
) -> None:
    """Run one adjunct pass and record whatever it found.

    Never raises: any failure is logged, reported as ``<tool>_skipped``, and the
    scan continues with its engine findings intact.
    """
    sink.event(tool, sink.progress, start_message)
    try:
        efs = produce()
    except Exception as exc:  # noqa: BLE001 — an optional tool never fails a scan
        log.exception("%s pass failed", tool)
        from app.engine.journal import describe_failure

        reason = describe_failure(exc, sink.redactor).removeprefix("AdjunctUnavailable: ")
        sink.event(
            f"{tool}_skipped",
            sink.progress,
            f"{tool} did not run — {reason}; "
            "its checks were not performed, so no findings is not a clean result",
        )
        return

    sink.record(efs)
    message = (
        done_message(len(efs))
        if done_message is not None
        else f"{tool} added {len(efs)} findings"
    )
    sink.event(f"{tool}_done", sink.progress, message)


def require_binary(sink: AdjunctSink, tool: str, bin_path: str) -> bool:
    """True when ``bin_path`` resolves; otherwise emit a skip and return False."""
    if shutil.which(bin_path) is None:
        sink.event(f"{tool}_skipped", sink.progress, f"{tool} not installed")
        return False
    return True


class AdjunctPhase:
    """Sequences the adjunct passes under one shared wall-clock budget.

    The budget and the cancellation check live *between* passes, not inside
    them: these tools manage their own requests, so the phase can only stop at
    a pass boundary. Once the deadline is spent the remaining passes are
    skipped with a single ``adjuncts_skipped`` event.
    """

    def __init__(
        self,
        sink: AdjunctSink,
        *,
        budget_seconds: float,
        cancelled: Callable[[], bool],
        drift: Callable[[], str | None] | None = None,
    ) -> None:
        self._sink = sink
        self._cancelled = cancelled
        # Why the target no longer resolves to what the run cleared, checked
        # before each pass: these tools do their own DNS and are not pinned.
        self._drift = drift
        self.deadline = time.monotonic() + budget_seconds
        self._passes: list[tuple[str, Callable[[], None]]] = []

    def add(self, name: str, fn: Callable[[], None]) -> None:
        self._passes.append((name, fn))

    @property
    def expired(self) -> bool:
        return time.monotonic() > self.deadline

    def run(self) -> bool:
        """Run the queued passes. Returns False if a cancel landed mid-phase."""
        sink = self._sink
        for index, (name, fn) in enumerate(self._passes):
            if self._cancelled():
                return False
            if self.expired:
                sink.event(
                    "adjuncts_skipped",
                    sink.progress,
                    f"adjunct budget spent — skipping {name} and later passes",
                )
                # One line per tool as well, so the run records each one as not
                # run and a later diff cannot count its findings as fixed.
                for skipped, _ in self._passes[index:]:
                    sink.event(f"{skipped}_skipped", sink.progress,
                               f"{skipped} did not run — the adjunct time budget was spent")
                break
            moved = self._drift() if self._drift is not None else None
            if moved:
                sink.event(
                    "adjuncts_skipped",
                    sink.progress,
                    f"target address changed — skipping {name} and later passes: {moved}",
                )
                for skipped, _ in self._passes[index:]:
                    sink.event(f"{skipped}_skipped", sink.progress,
                               f"{skipped} did not run — the target's address changed "
                               "since it was cleared")
                break
            fn()
        return True


# ---- individual passes --------------------------------------------------------


def run_zap(sink: AdjunctSink, *, spec_urls: Sequence[str] = ()) -> None:
    """OWASP ZAP spider + active scan, seeded with the scan's operation URLs.

    An API's base URL usually links to nothing, so ZAP needs the spec's paths to
    reach the documented endpoints instead of scanning only the root.
    """
    from app.core.config import settings
    from app.engine.zap import ZapHttp, ZapScanner

    if not settings.zap_base_url:
        sink.event("zap_skipped", sink.progress, "ZAP not configured")
        return

    def produce() -> list[EngineFinding]:
        zap_http = httpx.Client(timeout=30.0)
        try:
            scanner = ZapScanner(
                settings.zap_base_url,
                api_key=settings.zap_api_key,
                http=cast(ZapHttp, zap_http),
                timeout_seconds=settings.zap_timeout_seconds,
                poll_seconds=settings.zap_poll_seconds,
            )
            return _reported(scanner, scanner.run(sink.target_base_url, spec_urls=spec_urls))
        finally:
            zap_http.close()

    run_adjunct(
        sink,
        tool="zap",
        start_message="OWASP ZAP scanning (outside request budget)",
        produce=produce,
        done_message=lambda n: f"ZAP added {n} findings",
    )


def run_testssl(sink: AdjunctSink) -> None:
    """Deep TLS audit via testssl.sh. HTTPS targets only.

    Runs only when the run asked for it (the ``testssl`` pass), so an unset
    ``TESTSSL_BIN`` is reported as skipped rather than read as a clean audit. A
    plaintext target is skipped silently — the built-in ``tls_config`` check
    already flags it, and there is no TLS for testssl to audit.
    """
    from app.core.config import settings
    from app.engine.testssl_scan import TestsslScanner

    if not settings.testssl_bin:
        sink.event("testssl_skipped", sink.progress, "testssl.sh not configured (TESTSSL_BIN)")
        return
    if urlparse(sink.target_base_url).scheme != "https":
        return
    if not require_binary(sink, "testssl", settings.testssl_bin):
        return

    def produce() -> list[EngineFinding]:
        scanner = TestsslScanner(
            settings.testssl_bin, timeout_seconds=settings.testssl_timeout_seconds
        )
        return _reported(scanner, scanner.run(sink.target_base_url))

    run_adjunct(
        sink,
        tool="testssl",
        start_message="testssl.sh deep TLS audit",
        produce=produce,
        done_message=lambda n: f"testssl added {n} findings",
    )


def run_kali(
    sink: AdjunctSink,
    *,
    spec_urls: Sequence[str] = (),
    rate_limit: int = 10,
    should_stop: Callable[[], bool] | None = None,
) -> None:
    """Kali adjunct service: nuclei templates plus endpoint discovery.

    ``spec_paths`` (from the sink's operations) lets discovery drop
    already-documented endpoints; ``spec_urls`` gives the scanner passes the API
    paths to actually scan.
    """
    from app.core.config import settings
    from app.engine.kali import KaliHttp, KaliScanner

    if not settings.kali_base_url:
        sink.event("kali_skipped", sink.progress, "Kali service not configured")
        return

    def produce() -> list[EngineFinding]:
        kali_http = httpx.Client(timeout=settings.kali_timeout_seconds + 60)
        try:
            scanner = KaliScanner(
                settings.kali_base_url,
                api_key=settings.kali_api_key,
                http=cast(KaliHttp, kali_http),
                timeout_seconds=settings.kali_timeout_seconds,
                rate_limit=rate_limit,
            )
            found = _reported(scanner, scanner.run(
                sink.target_base_url,
                spec_paths=[op.path for op in sink.operations],
                spec_urls=spec_urls,
                should_stop=should_stop,
            ))
        finally:
            kali_http.close()
        if len(scanner.failed_passes) >= KALI_PASSES:
            raise AdjunctUnavailable("no Kali tool answered — is the kali service running?")
        if scanner.failed_passes:
            sink.event(
                "kali_partial",
                sink.progress,
                "Kali tools that did not answer: " + ", ".join(scanner.failed_passes),
            )
        return found

    run_adjunct(
        sink,
        tool="kali",
        start_message="Kali adjuncts scanning (outside request budget)",
        produce=produce,
        done_message=lambda n: f"Kali added {n} findings",
    )


# ---- lead confirmation --------------------------------------------------------


def _confirm_pass(
    sink: AdjunctSink,
    *,
    tool: str,
    bin_path: str,
    confirmer: Any,
    targets: list[dict[str, Any]],
    deadline: float | None,
    should_stop: Callable[[], bool] | None,
) -> None:
    """Re-test the engine's leads for one family with its dedicated tool."""
    if not targets:
        return
    if not require_binary(sink, tool, bin_path):
        return
    run_adjunct(
        sink,
        tool=tool,
        start_message=(
            f"{tool} confirming {len(targets)} lead(s) — outside request budget"
        ),
        produce=lambda: confirmer.run(
            sink.target_base_url, targets, deadline=deadline, should_stop=should_stop
        ),
        done_message=lambda n: f"{tool} confirmed {n} lead(s)",
    )


def confirm_passes(
    sink: AdjunctSink,
    *,
    deadline: float | None,
    should_stop: Callable[[], bool],
    independent_targets: list[dict[str, Any]] | None = None,
) -> Iterator[tuple[str, Callable[[], None]]]:
    """Yield the (name, run) pair for each configured confirmation tool.

    Each is env-gated on its own ``*_BIN``: unset means the pass is not even
    queued, so an unconfigured tool costs nothing and emits nothing.
    """
    from app.core.config import settings
    from app.engine.commix_confirm import CommixConfirmer, select_cmdi_targets
    from app.engine.dalfox_confirm import DalfoxConfirmer, select_xss_targets
    from app.engine.sqlmap_confirm import SqlmapConfirmer, select_sqli_targets
    from app.engine.tplmap_confirm import TplmapConfirmer, select_ssti_targets

    specs = [
        ("sqlmap", settings.sqlmap_bin, settings.sqlmap_timeout_seconds,
         settings.sqlmap_max_targets, SqlmapConfirmer, select_sqli_targets),
        ("dalfox", settings.dalfox_bin, settings.dalfox_timeout_seconds,
         settings.dalfox_max_targets, DalfoxConfirmer, select_xss_targets),
        ("commix", settings.commix_bin, settings.commix_timeout_seconds,
         settings.commix_max_targets, CommixConfirmer, select_cmdi_targets),
        ("tplmap", settings.tplmap_bin, settings.tplmap_timeout_seconds,
         settings.tplmap_max_targets, TplmapConfirmer, select_ssti_targets),
    ]

    for tool, bin_path, timeout, max_targets, confirmer_cls, select in specs:
        if not bin_path:
            continue

        def make(
            tool: str = tool,
            bin_path: str = bin_path,
            timeout: int = timeout,
            max_targets: int = max_targets,
            confirmer_cls: Any = confirmer_cls,
            select: Any = select,
        ) -> Callable[[], None]:
            def run() -> None:
                # Targets are selected at run time: earlier passes in this phase
                # may have added findings this tool should also look at.
                targets = select(sink.findings, max_targets=max_targets)
                if tool == "sqlmap" and independent_targets:
                    sample = independent_targets[:max_targets]
                    seen = {(t["path"], t["param"]) for t in sample}
                    targets = (sample + [t for t in targets
                                         if (t["path"], t["param"]) not in seen])[:max_targets]
                _confirm_pass(
                    sink,
                    tool=tool,
                    bin_path=bin_path,
                    confirmer=confirmer_cls(bin_path, timeout_seconds=timeout),
                    targets=targets,
                    deadline=deadline,
                    should_stop=should_stop,
                )

            return run

        yield tool, make()
