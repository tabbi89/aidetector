"""Model pricing → cost in micro-USD. Rates are USD per 1M tokens."""
from __future__ import annotations

# (input, output) USD per 1,000,000 tokens. Matched by substring so dated
# aliases (e.g. claude-opus-5) resolve without an exact-match table.
RATES: dict[str, tuple[float, float]] = {
    "claude-opus-5": (5.0, 25.0),
    "claude-opus": (5.0, 25.0),
    "claude-sonnet": (2.0, 10.0),
    "claude-haiku": (1.0, 5.0),
    "opus": (5.0, 25.0),
    "sonnet": (2.0, 10.0),
    "haiku": (1.0, 5.0),
    # DeepSeek V4-Flash (what deepseek-chat aliases to).
    "deepseek-chat": (0.14, 0.28),
    "deepseek-v4-flash": (0.14, 0.28),
    "deepseek-v4-pro": (0.435, 0.87),
    "deepseek": (0.14, 0.28),
}

_FALLBACK = (5.0, 25.0)


def rate_for(model: str) -> tuple[float, float]:
    m = model.lower()
    for key, rate in RATES.items():
        if key in m:
            return rate
    return _FALLBACK


#: Prompt-cache prices as multiples of the model's input rate: a cache read is
#: a tenth of an input token, a (five-minute) cache write a quarter more.
CACHE_READ_MULTIPLIER = 0.1
CACHE_WRITE_MULTIPLIER = 1.25


def cost_micros(
    model: str,
    tokens_in: int,
    tokens_out: int,
    *,
    cache_read: int = 0,
    cache_write: int = 0,
) -> int:
    """Cost of a call in integer micro-USD (1e-6 USD).

    ``tokens_in`` is uncached input; cache reads and writes are priced on top
    at their own multiples of the input rate.
    """
    rin, rout = rate_for(model)
    usd = (
        (tokens_in / 1_000_000) * rin
        + (tokens_out / 1_000_000) * rout
        + (cache_read / 1_000_000) * rin * CACHE_READ_MULTIPLIER
        + (cache_write / 1_000_000) * rin * CACHE_WRITE_MULTIPLIER
    )
    return round(usd * 1_000_000)
