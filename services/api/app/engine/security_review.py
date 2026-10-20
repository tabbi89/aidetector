"""Optional static DeepSeek review; never changes findings or target state."""
from __future__ import annotations

from app.ai.budget import reserve
from app.ai.security_review import (
    SecurityReview,
    build_review_payload,
    redact_structure,
    validate_suggestions,
)
from app.core.config import settings
from app.core.redact import Redactor
from app.engine.ai_phases import settle_failed_call, write_ledger


def review_security_design(ctx, journal, planner=None) -> None:
    from app.ai.planner import OpusPlanner

    review = SecurityReview(status="running", model=settings.executor_model)
    journal.run_row.security_review = review.model_dump()
    journal.event("security_review", journal.scan.progress, "AI reviewing security design")
    journal.db.commit()
    budget_refused = False
    try:
        if not ctx.spec or not ctx.spec.get("paths"):
            raise ValueError("no spec")
        # Schema context is whatever a local run read on the CLI machine; with
        # none, the review is of the OpenAPI document alone and says so.
        database = ctx.schema_context
        if database is not None:
            review.schema_status = "available"
        if journal.cancelled():
            raise ValueError("cancelled")
        redactor = ctx.redact or Redactor()
        payload = build_review_payload(ctx.spec, database, review.schema_status)
        payload = redact_structure(payload, redactor)
        reservation = reserve(
            journal.db,
            journal.scan,
            "security_review",
            request={"payload": payload},
        )
        if reservation is None:
            budget_refused = True
            raise ValueError("budget")
        try:
            raw, usages = (planner or OpusPlanner()).review_security(payload)
        except Exception as exc:
            settle_failed_call(
                journal.db, journal.scan, "security_review", reservation, exc
            )
            raise
        # Meter completed calls even if the model's JSON/references are rejected.
        write_ledger(
            journal.scan, usages, reservation=reservation, db=journal.db
        )
        if journal.cancelled():
            raise ValueError("cancelled")
        review.suggestions = validate_suggestions(redactor.value(raw), payload)
        review.status = "completed"
    except Exception:
        # Never expose driver errors, raw model text, or schema data in logs.
        review.status = "unavailable"
        review.suggestions = []
    journal.run_row.security_review = review.model_dump()
    journal.db.commit()
    if review.status == "completed":
        message = f"AI security design review: {len(review.suggestions)} suggestions"
    elif budget_refused:
        message = "AI security design review skipped: AI budget cannot cover the call"
    else:
        message = "AI security design review unavailable"
    journal.event(
        "security_review_done" if review.status == "completed" else "security_review_skipped",
        journal.scan.progress,
        message,
    )
