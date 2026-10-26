"""The two opt-in AI phases: pre-scan planning and post-scan adjudication.

Both are off by default, both are metered into the token ledger, and both
degrade gracefully — an AI failure emits a skip event and leaves the scan with
its engine findings intact. Never let a problem here fail a scan.
"""
from __future__ import annotations

import logging
from collections.abc import Callable
from typing import Any, TypeVar

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.ai import pricing
from app.ai.budget import (
    BudgetExhausted,
    load_budget,
    release,
    reserve,
)
from app.ai.cascade import Cascade, build_payload
from app.ai.types import HYBRID_CHECKS, Usage
from app.domain.enums import Verdict
from app.engine.base import ScanContext
from app.models.finding import Finding
from app.models.ledger import TokenLedger
from app.models.scan import Scan, ScanRun

log = logging.getLogger("runpentests.engine")

T = TypeVar("T")


def metered_call(
    db: Session,
    scan: Scan,
    phase: str,
    request: dict[str, Any],
    call: Callable[[], tuple[T, list[Usage]]],
    *,
    mode: str | None = None,
    before_call: Callable[[], None] | None = None,
) -> tuple[T, list[Usage]] | None:
    """Every paid AI call goes through here: claim, call, meter — in that order.

    Returns ``None`` when the budget cannot cover the call's worst case, and no
    call is made. Otherwise the provider's answer is metered and committed
    *before* the caller reads it, so output that turns out to be malformed is
    still paid for exactly once and leaves no claim behind. A call that raises
    releases its claim and re-raises.
    """
    reservation = reserve(db, scan, phase, request=request, mode=mode)
    if reservation is None:
        return None
    if before_call is not None:
        before_call()
    try:
        result, usages = call()
    except Exception as exc:
        settle_failed_call(db, scan, phase, reservation, exc)
        raise
    write_ledger(scan, usages, reservation=reservation, db=db)
    db.commit()
    return result, usages


def settle_failed_call(
    db: Session, scan: Scan, phase: str, reservation: Any, exc: BaseException
) -> None:
    """Close the claim of a call that raised.

    A call that failed before anything was sent (``PlannerNotStarted``) cost
    nothing, so its claim is simply released. Any other failure — a timeout, a
    runtime that crashed after its completion, unreadable output — may have
    been paid for without reporting usage. Its full claim is charged as an
    ``unmetered`` ledger row: handing the claim back would let a loop of
    failing calls spend without limit against caps that never see it.
    """
    from app.ai.planner import PlannerNotStarted

    micros = int(getattr(reservation, "micros", 0) or 0)
    if micros and not isinstance(exc, PlannerNotStarted):
        scan.ledger.append(
            TokenLedger(
                tenant_slug=getattr(scan, "tenant_id", "") or "",
                phase=phase[:20],
                model="unmetered",
                tokens_in=0,
                tokens_out=0,
                cost_micros=micros,
            )
        )
        scan.cost_cents = round(
            sum(int(entry.cost_micros or 0) for entry in scan.ledger) / 10_000
        )
    release(db, reservation)
    db.commit()


class MeteredPlanner:
    """A planner whose refinement calls each claim budget at the call itself.

    The adaptive and resource-refinement loops make many small paid calls from
    DB-free engine code; one check before the loop cannot see what the loop
    then spends, nor what a concurrent caller has claimed meanwhile. The first
    refusal stops every later call without a round trip: the loops read the
    raised error as "no proposal" and carry on deterministically.
    """

    def __init__(self, inner: Any, db: Session, scan: Scan, emit, label: str) -> None:
        self._inner = inner
        self._db = db
        self._scan = scan
        self._emit = emit
        self._label = label
        self._refused = False

    def refine(self, payload: dict) -> tuple[Any, list[Usage]]:
        return self._call("adaptive", "refine", payload)

    def propose_resource(self, payload: dict) -> tuple[Any, list[Usage]]:
        return self._call("propose_resource", "propose_resource", payload)

    def _call(self, mode: str, method: str, payload: dict) -> tuple[Any, list[Usage]]:
        if self._refused:
            raise BudgetExhausted("AI")
        fn = getattr(self._inner, method)

        def call() -> tuple[Any, list[Usage]]:
            value = fn(payload)
            # Minimal test doubles return the bare proposal.
            if not isinstance(value, tuple):
                return value, []
            raw = value[1] if len(value) > 1 else []
            return value[0], [u for u in _as_list(raw) if isinstance(u, Usage)]

        called = metered_call(self._db, self._scan, mode, {"payload": payload}, call, mode=mode)
        if called is None:
            self._refused = True
            self._emit(
                "ai_budget_exhausted",
                self._scan.progress,
                f"{self._label} stopped: AI budget cannot cover the next call",
            )
            raise BudgetExhausted("AI")
        return called


def _refuse(scan: Scan, emit, phase: str) -> None:
    emit(
        "ai_budget_exhausted",
        scan.progress,
        f"{phase} skipped: AI budget cannot cover the next call",
    )


def plan_operations(db: Session, scan: Scan, ctx: ScanContext, run: ScanRun, planner, emit) -> None:
    """AI pre-scan plan: prioritise operations so the budget hits risk first.

    Reorders ``ctx.operations`` in place (high→low), writes the plan cost to the
    ledger (phase ``plan``), and persists the plan on the run. Degrades
    gracefully: any failure leaves the spec order and the scan proceeds.
    """
    plan_order(db, scan, ctx.operations, run, planner, emit)


def plan_order(db: Session, scan: Scan, ops: list, run: ScanRun, planner, emit) -> None:
    """``plan_operations`` over a bare operation list, reordered in place.

    A local run has no ``ScanContext`` on the server: the claim's operations
    are planned here and the runner receives them in this order.
    """
    from app.ai.cascade import AICascade, build_plan_payload  # local: SDK optional

    if not ops:
        return
    plan_payload = build_plan_payload(ops)
    try:
        called = metered_call(
            db,
            scan,
            "plan",
            {"operations": plan_payload},
            lambda: (planner or AICascade()).plan(plan_payload),
            before_call=lambda: emit(
                "plan", scan.progress, f"AI planning {len(ops)} operations"
            ),
        )
    except Exception:  # noqa: BLE001 — never fail the scan on AI problems
        log.exception("planning failed; running in spec order")
        emit("plan_skipped", scan.progress, "AI planning unavailable")
        return
    if called is None:
        _refuse(scan, emit, "AI planning")
        return
    try:
        ordered, rows = _read_plan(ops, called[0])
    except Exception:  # noqa: BLE001 — unusable output is a skip, never a failure
        log.exception("unusable plan; running in spec order")
        emit("plan_skipped", scan.progress, "AI plan output unusable")
        return
    ops[:] = ordered
    run.plan = rows
    db.commit()
    highs = sum(1 for r in run.plan if r["priority"] == "high")
    emit(
        "planned",
        scan.progress,
        f"AI prioritised {len(ops)} operations ({highs} high-risk first)",
    )


def _as_list(value: object) -> list:
    return value if isinstance(value, list) else []


def _read_plan(ops: list, plan: object) -> tuple[list, list[dict]]:
    """The operations in the model's priority order, and the plan to archive.

    The model's output is untrusted: anything that is not an object in a list
    is read as no advice for that operation, so it keeps its spec position.
    """
    rank = {"high": 0, "medium": 1, "low": 2}
    by_id = {
        str(p.get("operation_id")): p for p in _as_list(plan) if isinstance(p, dict)
    }

    def _prio(op) -> str:
        return str(by_id.get(str(op.id), {}).get("priority", "medium")).lower()

    ordered = sorted(ops, key=lambda o: rank.get(_prio(o), 1))
    known = {str(p.id) for p in ordered}
    rows = [
        {
            "operation_id": o.id,
            "method": o.method,
            "path": o.path,
            "priority": _prio(o),
            "rationale": str(by_id.get(str(o.id), {}).get("rationale", ""))[:300],
            "resource_dependencies": [
                {
                    "parameter": str(dep.get("parameter", ""))[:80],
                    "producer_operation_id": str(dep.get("producer_operation_id", "")),
                    "strategy": str(dep.get("strategy", "read_collection")),
                    "rationale": str(dep.get("rationale", ""))[:300],
                }
                for dep in _as_list(by_id.get(str(o.id), {}).get("resource_dependencies"))
                if isinstance(dep, dict)
                and str(dep.get("producer_operation_id", "")) in known
                and str(dep.get("parameter", "")) in o.path_params
                and str(dep.get("strategy", "read_collection"))
                in {"read_collection", "create_resource"}
            ],
        }
        for o in ordered
    ]
    return ordered, rows


def generate_payloads(
    db: Session, scan: Scan, ctx: ScanContext, run: ScanRun, planner, emit
) -> None:
    """AI payload design: DeepSeek proposes extra reflection-payload variants.

    Installs an augmented payload provider on ``ctx`` so the reflection check
    rotates over a deeper pool, writes the cost to the ledger (phase
    ``payloads``), and degrades gracefully — any failure, or no usable variant,
    leaves the curated + vendored-corpus rotation and the scan proceeds. Every
    proposed string is re-validated (marker, metacharacter, no control chars,
    length) before it can reach the target, so a malformed or hostile model
    response cannot inject an unchecked payload.
    """
    from app.ai.cascade import AICascade  # local: SDK optional
    from app.engine.payload_corpus import sanitize_family_map
    from app.engine.payloads import FAMILIES, augmented_provider, build_families_payload

    families_payload = build_families_payload()
    try:
        called = metered_call(
            db,
            scan,
            "payloads",
            {"families": families_payload},
            lambda: (planner or AICascade()).generate_payloads(families_payload),
            before_call=lambda: emit(
                "genai_payloads", scan.progress, "AI designing payload variants"
            ),
        )
    except Exception:  # noqa: BLE001 — never fail the scan on AI problems
        log.exception("payload generation failed; using curated + corpus payloads")
        emit("genai_payloads_skipped", scan.progress, "AI payload design unavailable")
        return
    if called is None:
        _refuse(scan, emit, "AI payload design")
        return
    # Already metered, once: a provider that answered with unusable variants
    # was still paid for, and a usable answer is not paid for twice.
    try:
        variants = sanitize_family_map(called[0], allowed=frozenset(FAMILIES))
    except Exception:  # noqa: BLE001 — unusable output is a skip
        variants = {}
    if not variants:
        emit("genai_payloads_skipped", scan.progress, "no usable AI payload variants")
        return
    ctx.payload_provider = augmented_provider(variants)
    added = sum(len(v) for v in variants.values())
    emit(
        "genai_payloads_ready",
        scan.progress,
        f"AI added {added} payload variants across {len(variants)} families",
    )


def adjudicate_findings(
    db: Session, scan: Scan, cascade: Cascade | None, emit, *, premium: bool = False
) -> None:
    """Run the AI cascade over findings; apply verdicts + write the ledger.

    Without ``premium`` only the judgment-heavy HYBRID checks are reviewed; with
    ``premium`` every finding is, so each carries a written verdict + rationale.

    A durable per-scan cache (``AdjudicationCache``) short-circuits findings whose
    fingerprint was already adjudicated, so re-running a scan does not re-spend
    tokens on unchanged findings. Degrades gracefully: any failure (planner
    unavailable, network, bad output) leaves engine findings intact and the scan
    still completes.

    The cache uses a digest of the complete review input, model configuration
    and prompt/runtime version. Human triage continues using the stable finding
    fingerprint; changed evidence must invalidate a cached AI dismissal.
    """
    from app.ai.cascade import AICascade  # local import: SDK is optional
    from app.models.adjudication import AdjudicationCache

    targets = (
        list(scan.findings)
        if premium
        else [f for f in scan.findings if f.check in HYBRID_CHECKS]
    )
    if not targets:
        return

    cached = {
        (row.review_key or row.fingerprint): row
        for row in db.execute(
            select(AdjudicationCache).where(AdjudicationCache.scan_id == scan.id)
        ).scalars()
    }
    cached_by_fingerprint = {row.fingerprint: row for row in cached.values() if row.fingerprint}
    # A finding recorded before the fingerprint column existed has none. It is
    # still adjudicated — it just cannot be cached, because an empty key would
    # collide with every other such finding under the (scan_id, fingerprint)
    # unique constraint.
    from app.engine.methodology import adjudication_key

    fp = {id(f): adjudication_key(f, premium=premium) if f.fingerprint else "" for f in targets}

    from_cache = 0
    to_review: list[Finding] = []
    for f in targets:
        review_key = fp[id(f)]
        row = cached.get(review_key)
        # Reflection probes rotate payload families and therefore their
        # response shape, while the finding identity remains the route and
        # parameter. Reuse that stable identity when the only difference is
        # generated probe evidence.
        if row is None and f.check in {"reflected_injection", "signature_injection"}:
            row = cached_by_fingerprint.get(f.fingerprint)
        if row is not None:
            f.verdict = row.verdict
            f.ai_rationale = row.rationale or None
            if row.remediation:
                f.remediation = row.remediation
            from_cache += 1
        else:
            to_review.append(f)

    if not to_review:
        emit(
            "adjudicated",
            scan.progress,
            f"AI adjudicated {from_cache} findings (all from cache)",
        )
        return

    emit(
        "adjudicate",
        scan.progress,
        f"AI reviewing {len(to_review)} findings"
        + (f" ({from_cache} from cache)" if from_cache else ""),
    )
    payload = build_payload(to_review)
    try:
        called = metered_call(
            db,
            scan,
            "adjudicate",
            {"findings": payload},
            lambda: (cascade or AICascade()).run(payload),
        )
    except Exception:  # noqa: BLE001 — never fail the scan on AI problems
        log.exception("adjudication failed; leaving findings unreviewed")
        emit("ai_skipped", scan.progress, "AI adjudication unavailable")
        return
    if called is None:
        _refuse(scan, emit, "AI adjudication")
        return
    verdicts = [v for v in _as_list(called[0]) if isinstance(v, dict)]

    by_id = {str(f.id): f for f in to_review}
    written = set(cached)
    applied = 0
    for v in verdicts:
        f = by_id.get(str(v.get("id")))
        if f is None:
            continue
        raw = str(v.get("verdict", "")).lower()
        if raw not in ("confirmed", "dismissed"):
            continue
        rationale = str(v.get("rationale", ""))[:2000]
        f.verdict = Verdict(raw)
        f.ai_rationale = rationale
        # A confirmed finding may carry an evidence-specific fix that beats the
        # static catalogue line. Only on confirm — a dismissed finding needs no
        # remediation, and we never let the model blank a real one.
        remediation = ""
        if raw == "confirmed":
            raw_fix = v.get("remediation")
            candidate = raw_fix.strip()[:2000] if isinstance(raw_fix, str) else ""
            if candidate:
                f.remediation = candidate
                remediation = candidate
        applied += 1
        fingerprint = fp[id(f)]
        if fingerprint and fingerprint not in written:
            scan.adjudication_cache.append(
                AdjudicationCache(
                    fingerprint=f.fingerprint or "",
                    review_key=fingerprint,
                    verdict=Verdict(raw),
                    rationale=rationale,
                    remediation=remediation,
                )
            )
            written.add(fingerprint)

    emit(
        "adjudicated",
        scan.progress,
        f"AI adjudicated {applied + from_cache} findings"
        + (f" ({from_cache} from cache)" if from_cache else ""),
    )


def write_ledger(
    scan: Scan,
    usages: list[Usage],
    *,
    reservation: object | None = None,
    db: Session | None = None,
) -> None:
    """Aggregate per (model, phase) into ledger rows and update scan cost.

    ``reservation`` (a :class:`app.ai.budget.Reservation`) is released here,
    because this is the moment its worst-case claim is replaced by the call's
    actual cost.
    """
    agg: dict[tuple[str, str], list[int]] = {}
    for u in usages:
        acc = agg.setdefault((u.model, u.phase), [0, 0, 0, 0])
        acc[0] += u.tokens_in
        acc[1] += u.tokens_out
        acc[2] += getattr(u, "cache_read_tokens", 0) or 0
        acc[3] += getattr(u, "cache_write_tokens", 0) or 0
    for (model, phase), (tin, tout, cread, cwrite) in agg.items():
        micros = pricing.cost_micros(
            model, tin, tout, cache_read=cread, cache_write=cwrite
        )
        scan.ledger.append(
            TokenLedger(
                # The minimal phase-test doubles carry no tenant; a real scan
                # always does.
                tenant_slug=getattr(scan, "tenant_id", "") or "",
                phase=phase,
                model=model,
                tokens_in=tin,
                tokens_out=tout,
                cache_read_tokens=cread,
                cache_write_tokens=cwrite,
                cost_micros=micros,
            )
        )
    # A scan may use more than one AI phase (plan, resource refinement,
    # adjudication). Keep the summary cumulative instead of letting the latest
    # phase overwrite costs already represented by ledger rows.
    scan.cost_cents = round(
        sum(int(entry.cost_micros or 0) for entry in scan.ledger) / 10_000
    )
    release(db, reservation)  # type: ignore[arg-type]


def answer_question(
    db: Session, scan: Scan, question: str, cascade: Cascade | None
) -> str:
    """Answer a natural-language question about the scan's findings.

    Premium: the route gates access. The AI failure surfaces as an exception the
    route maps to 502 — this is request-path Q&A, not a scan stage, so there is no
    skip event to emit.
    """
    from app.ai.cascade import AICascade

    payload = build_payload(scan.findings)
    called = metered_call(
        db,
        scan,
        "qa",
        {"findings": payload, "question": question},
        lambda: (cascade or AICascade()).answer(payload, question),
    )
    if called is None:
        raise BudgetExhausted(load_budget(db, scan).exhausted() or "AI")
    answer = str(called[0])
    return answer
