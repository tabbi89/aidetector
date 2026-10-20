"""Validated adaptive settings and value-free run history."""
from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field


class AdaptiveSettings(BaseModel):
    model_config = ConfigDict(extra="forbid", json_schema_serialization_defaults_required=True)
    attempts: Literal[2, 3] = 3
    endpoints: int = Field(default=5, ge=1, le=20, strict=True)
    requests: int = Field(default=40, ge=4, le=100, strict=True)
    seconds: int = Field(default=90, ge=10, le=300, strict=True)
    tokens: int = Field(default=12000, ge=500, le=100000, strict=True)
    cost_micros: int = Field(default=100000, ge=1000, le=5000000, strict=True)


class Attempt(BaseModel):
    model_config = ConfigDict(json_schema_serialization_defaults_required=True)
    number: int
    variant: str
    status: int | None = None
    outcome: str = "inconclusive"
    assessment: str = "not_requested"
    tokens: int = 0
    cost_micros: int = 0
    cost_estimated: bool = False
    persisted: bool = False
    cleanup: str = "not_needed"


class TestTrace(BaseModel):
    model_config = ConfigDict(json_schema_serialization_defaults_required=True)
    operation_id: str | None = None
    method: str
    route: str
    field: str = ""
    location: str = ""
    rule: str = ""
    priority: int = 0
    rationale: str = "No supported safe test"
    outcome: str = "skipped"
    stop_reason: str = "unsupported"
    schema_status: str = "not_configured"
    schema_facts: list[str] = []
    attempts: list[Attempt] = []
    finding_fingerprint: str | None = None


class AdaptiveHistory(BaseModel):
    model_config = ConfigDict(json_schema_serialization_defaults_required=True)
    enabled: bool = False
    settings: AdaptiveSettings = Field(default_factory=AdaptiveSettings)
    tests: list[TestTrace] = []
    requests: int = 0
    elapsed_ms: int = 0
    tokens: int = 0
    cost_micros: int = 0
    cost_estimated: bool = False
    stop_reason: str = "disabled"
