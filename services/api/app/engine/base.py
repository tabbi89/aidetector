"""Compatibility facade for the engine's core contracts.

The primitives used to live in this one module. They now have focused homes:

- :mod:`app.engine.credentials` — decrypted credentials and auth headers
- :mod:`app.engine.operations` — operations and path rendering
- :mod:`app.engine.probe` — the request budget, retry policy and trace
- :mod:`app.engine.context` — the per-run ``ScanContext``
- :mod:`app.engine.contracts` — ``Check``, ``EngineFinding`` and check traits
- :mod:`app.engine.http_types` — transport-facing values

New code should import from the focused module. This facade re-exports the old
names so the many existing ``from app.engine.base import ...`` call sites keep
working without a flag day.
"""
from app.engine.context import IdentityPair, ScanContext
from app.engine.contracts import (
    Check,
    EngineFinding,
    inapplicable,
    mutates,
    needs_identities,
    premium,
    runs_serially,
    serial_when_mutating,
)
from app.engine.credentials import ResolvedCredential
from app.engine.http_types import HeaderSnapshot, HttpClient, ProbeResult
from app.engine.operations import TargetOperation, render_path
from app.engine.probe import (
    DEFAULT_MAX_REQUESTS,
    SAFE_METHODS,
    HttpProbe,
    method_is_allowed,
)

__all__ = [
    "DEFAULT_MAX_REQUESTS",
    "SAFE_METHODS",
    "Check",
    "EngineFinding",
    "HeaderSnapshot",
    "HttpClient",
    "HttpProbe",
    "IdentityPair",
    "ProbeResult",
    "ResolvedCredential",
    "ScanContext",
    "TargetOperation",
    "inapplicable",
    "method_is_allowed",
    "mutates",
    "needs_identities",
    "premium",
    "render_path",
    "runs_serially",
    "serial_when_mutating",
]
