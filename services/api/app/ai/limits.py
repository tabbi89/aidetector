"""The most one AI runtime call may cost, and the limits that make that true.

A budget reservation is only honest if it prices what the runtime is *allowed*
to do, not what a call usually does. So this module owns both halves: the
planner passes these ceilings to ``ai_runtime/plan_agent.py`` in the call's
config (output tokens per mode, agent turns, triage calls), and
:func:`worst_case_micros` prices exactly those requests. A ceiling raised in
one place is raised in the other.

Input is bounded in bytes, not characters: a byte-level BPE token covers at
least one byte, so a prompt's UTF-8 length is an upper bound on its tokens —
characters/4 is an average, not a bound.
"""
from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any

from app.ai.pricing import cost_micros
from app.core.config import settings

#: Every runtime system prompt is under this (``tests/test_ai_spend_bounds.py`` holds
#: ``plan_agent.py``'s ``*_SYSTEM`` strings and ``security_review_prompt.md`` to it).
SYSTEM_PROMPT_MAX_BYTES = 8192
#: The fixed text ``_prompt`` puts around the payload, plus chat-template tokens.
PROMPT_WRAPPER_BYTES = 512
#: Agent-mode (``planner_provider=anthropic``) bounds, passed to the runtime.
AGENT_MAX_TURNS = 8
AGENT_OUTPUT_TOKENS = 8000
#: What the Agent SDK adds to each turn beyond our system prompt: the one triage
#: tool's definition and the SDK's preamble. The runtime passes ``tools=[]`` so
#: no built-in tool definition is listed (tests pin that). Generous on
#: purpose: it is priced, never sent.
AGENT_OVERHEAD_TOKENS = 20_000
TRIAGE_MAX_CALLS = 12
#: The runtime cuts a triage tool's argument and its answer to these, so the
#: bound holds across the two models' different tokenizers.
TRIAGE_INPUT_MAX_BYTES = 16_000
TRIAGE_RESULT_MAX_BYTES = 8_000

#: Modes that are one direct DeepSeek completion whatever the provider.
_EXECUTOR_MODES = frozenset({"qa", "payloads", "security_review"})
#: Modes the anthropic provider runs as an agent with the triage tool.
_AGENT_MODES = frozenset({"plan", "adjudicate", "adaptive", "propose_resource"})


@dataclass(frozen=True)
class Request:
    """One bounded provider request: its model and its token ceilings."""

    model: str
    max_input_tokens: int
    max_output_tokens: int


def output_ceiling(mode: str) -> int:
    """The ``max_tokens`` the runtime sends for ``mode`` (never more)."""
    cap = settings.executor_max_tokens
    if mode in ("qa", "payloads"):
        return max(3000, cap)
    if mode == "security_review":
        return max(6000, cap)
    if mode in ("plan", "adjudicate"):
        return max(8000, cap)
    return max(4000, cap)


def runtime_limits(mode: str) -> dict[str, int]:
    """The config keys the runtime enforces for one call of ``mode``."""
    return {
        "max_output_tokens": output_ceiling(mode),
        "agent_max_turns": AGENT_MAX_TURNS,
        "agent_output_tokens": AGENT_OUTPUT_TOKENS,
        "triage_max_calls": TRIAGE_MAX_CALLS,
        "triage_output_tokens": settings.executor_max_tokens,
        "triage_input_max_bytes": TRIAGE_INPUT_MAX_BYTES,
        "triage_result_max_bytes": TRIAGE_RESULT_MAX_BYTES,
    }


def prompt_bytes(mode: str, request: dict[str, Any]) -> int:
    """UTF-8 length of the user prompt the runtime builds from ``request``.

    Mirrors ``_prompt`` and the executor modes: each pretty-prints its payload
    with ``indent=2``, which is larger than ``str(payload)``.
    """
    if mode == "qa":
        body = json.dumps(request.get("findings", []), indent=2)
        body += str(request.get("question", ""))
    elif mode == "plan":
        body = json.dumps(request.get("operations", []), indent=2)
    elif mode == "payloads":
        body = json.dumps(request.get("families", []), indent=2)
    elif mode == "adjudicate":
        body = json.dumps(request.get("findings", []), indent=2)
    else:
        body = json.dumps(request.get("payload", {}), indent=2, default=str)
    return len(body.encode()) + PROMPT_WRAPPER_BYTES


def requests_for(mode: str, request: dict[str, Any]) -> list[Request]:
    """Every provider request one runtime call of ``mode`` may make."""
    user = prompt_bytes(mode, request)
    single_input = SYSTEM_PROMPT_MAX_BYTES + user
    if mode in _EXECUTOR_MODES or settings.planner_provider == "deepseek":
        model = (
            settings.executor_model
            if mode in _EXECUTOR_MODES
            else settings.effective_planner_model()
        )
        return [Request(model, single_input, output_ceiling(mode))]
    if mode not in _AGENT_MODES:  # pragma: no cover - every mode is listed
        raise ValueError(f"unknown AI mode {mode!r}")
    # An agent turn re-sends the conversation so far: the opening prompt, every
    # earlier turn's output and every (byte-capped) triage answer it read.
    turn_input = (
        single_input
        + AGENT_OVERHEAD_TOKENS
        + AGENT_MAX_TURNS * AGENT_OUTPUT_TOKENS
        + TRIAGE_MAX_CALLS * TRIAGE_RESULT_MAX_BYTES
    )
    agent = [
        Request(settings.planner_model, turn_input, AGENT_OUTPUT_TOKENS)
        for _ in range(AGENT_MAX_TURNS)
    ]
    triage = [
        Request(
            settings.executor_model,
            SYSTEM_PROMPT_MAX_BYTES + TRIAGE_INPUT_MAX_BYTES,
            settings.executor_max_tokens,
        )
        for _ in range(TRIAGE_MAX_CALLS)
    ]
    return agent + triage


def worst_case_micros(mode: str, request: dict[str, Any]) -> int:
    """The price of the most expensive call ``mode`` is allowed to make."""
    requests = requests_for(mode, request)
    # Pricing rounds each ledger row to the nearest micro; never under-claim.
    return len(requests) + sum(_request_micros(r) for r in requests)


def _request_micros(request: Request) -> int:
    """The most one request can cost.

    An agent turn's input may be written to the prompt cache, which costs more
    than plain input (pricing.CACHE_WRITE_MULTIPLIER), so agent input is priced
    as a cache write. Direct completions report no cache traffic.
    """
    if request.model == settings.planner_model and settings.planner_provider == "anthropic":
        return cost_micros(
            request.model, 0, request.max_output_tokens, cache_write=request.max_input_tokens
        )
    return cost_micros(request.model, request.max_input_tokens, request.max_output_tokens)
