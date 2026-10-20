"""Make a value storable in a PostgreSQL ``jsonb`` column.

``jsonb`` refuses the NUL character (``\\u0000 cannot be converted to text``),
and a scanner meets it all the time: a fuzzer invents query parameter names
with control bytes, a target echoes binary. One NUL anywhere in a run's trace
or a finding's evidence failed the whole upload with a 500 and lost the run.
"""
from __future__ import annotations

from typing import Any

#: What a NUL becomes: visible as "something was here", and storable.
REPLACEMENT = "�"


def jsonb_safe(value: Any) -> Any:
    """``value`` with every NUL in every string — keys included — replaced."""
    if isinstance(value, str):
        return value.replace("\x00", REPLACEMENT) if "\x00" in value else value
    if isinstance(value, dict):
        return {jsonb_safe(k): jsonb_safe(v) for k, v in value.items()}
    if isinstance(value, list | tuple):
        return [jsonb_safe(item) for item in value]
    return value
