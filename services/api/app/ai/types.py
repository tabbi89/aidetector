"""Shared types for the AI cascade."""
from __future__ import annotations

from dataclasses import dataclass


@dataclass
class Usage:
    model: str
    phase: str  # "execute" | "adjudicate" | "monitoring"
    tokens_in: int
    tokens_out: int
    # Prompt-cache traffic the provider reports beside ``tokens_in`` (the
    # Agent SDK path does; one-shot DeepSeek completions report none).
    cache_read_tokens: int = 0
    cache_write_tokens: int = 0


# Engine checks whose findings warrant AI adjudication (HYBRID tier).
# reflected_injection leads are judgment-heavy too: reflection proves input
# reaches the response, not that it executes, so the cascade can dismiss
# context-poor echoes (e.g. markers reflected only in error envelopes).
HYBRID_CHECKS = {"bola", "bfla", "ssrf", "reflected_injection"}
