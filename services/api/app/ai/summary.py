"""Aggregate a scan's token ledger into a per-model AI usage summary.

The ledger records one row per AI call (phase + model + tokens + cost). This
rolls those up by model so a scan summary can answer "what AI was used" — which
models, in which phases, how many calls, and at what cost. Pure: no I/O.
"""
from __future__ import annotations

from collections.abc import Iterable
from typing import Any


def summarize_models(ledger: Iterable[Any]) -> list[dict]:
    """Distinct models used, aggregated. Ordered by first use (ledger order)."""
    by_model: dict[str, dict] = {}
    for e in ledger:
        m = by_model.get(e.model)
        if m is None:
            m = by_model[e.model] = {
                "model": e.model,
                "phases": [],
                "calls": 0,
                "tokens_in": 0,
                "tokens_out": 0,
                "cost_micros": 0,
            }
        if e.phase not in m["phases"]:
            m["phases"].append(e.phase)
        m["calls"] += 1
        m["tokens_in"] += e.tokens_in
        m["tokens_out"] += e.tokens_out
        m["cost_micros"] += e.cost_micros
    return [
        {
            "model": m["model"],
            "phases": m["phases"],
            "calls": m["calls"],
            "tokens_in": m["tokens_in"],
            "tokens_out": m["tokens_out"],
            "cost_usd": round(m["cost_micros"] / 1_000_000, 6),
        }
        for m in by_model.values()
    ]
