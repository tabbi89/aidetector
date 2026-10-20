"""The environment an AI runtime subprocess may inherit from the worker.

Both AI subprocesses (``planner`` → ``plan_agent.py``, ``provider`` →
``monitoring_agent.py``) send data to an external model, so they get an
allowlist rather than a copy of the worker's environment: enough to run and
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
