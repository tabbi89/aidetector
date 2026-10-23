"""The environment an AI runtime subprocess may inherit from the worker.

The planner subprocess (``plan_agent.py``) sends data to an external model,
so it gets an allowlist rather than a copy of the worker's environment: enough to run and
reach TLS endpoints, never the vault key, database URL, broker URL or cloud
credentials. Callers add the one or two keys their agent actually needs.
"""
from __future__ import annotations

import os

INHERITED_ENV: tuple[str, ...] = (
    "PATH",
    "HOME",
    "LANG",
    "LC_ALL",
    "TMPDIR",
    "SSL_CERT_FILE",
    "SSL_CERT_DIR",
    "REQUESTS_CA_BUNDLE",
    "HTTPS_PROXY",
    "NO_PROXY",
)


def inherited_env(extra: tuple[str, ...] = ()) -> dict[str, str]:
    """The allowlisted variables (plus ``extra`` names) present in this process."""
    return {key: os.environ[key] for key in (*INHERITED_ENV, *extra) if key in os.environ}
