"""Token/cost ledger and the ask-the-scan Q&A."""

from __future__ import annotations

import uuid

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
)

from app.api.schemas.common import ResponseModel


class LedgerEntryOut(ResponseModel):
    model_config = ConfigDict(from_attributes=True)
    phase: str
    model: str
    tokens_in: int
    tokens_out: int
    cost_micros: int


class AiModelUsage(ResponseModel):
    """One model the scan used, aggregated across its calls."""

    model: str
    phases: list[str] = []
    calls: int = 0
    tokens_in: int = 0
    tokens_out: int = 0
    cost_usd: float = 0.0


class CostOut(ResponseModel):
    scan_id: uuid.UUID
    total_usd: float
    entries: list[LedgerEntryOut]
    # Distinct models used, aggregated — "what AI was used" for the scan summary.
    models: list[AiModelUsage] = []


class AskRequest(BaseModel):
    question: str = Field(min_length=1, max_length=1000)


class AskOut(ResponseModel):
    answer: str
