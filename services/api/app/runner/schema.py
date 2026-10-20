"""Read the project's database schema on the CLI machine — the only place it is read.

The CLI passes the ``schema:`` block of ``aidetector.yml`` on stdin, password
included; this module runs the bounded metadata adapter against it and returns
two things: the record uploaded with the run (structure or a fixed reason
code — never the password, a DSN or a driver message) and the context the run's
own consumers read. Any failure is a reason code, never a failed scan: schema
context is an enhancement.
"""
from __future__ import annotations

import asyncio
from typing import Any

from app.core.redact import Redactor


def read_local_schema(
    block: Any, redactor: Redactor
) -> tuple[dict[str, Any], dict[str, Any] | None]:
    """Return ``(upload_record, context)``; ``context`` is None when unavailable."""

    def unavailable(reason: str) -> tuple[dict[str, Any], None]:
        return {"status": "unavailable", "reason": reason}, None

    if not isinstance(block, dict):
        return unavailable("invalid_config")
    password = block.get("password")
    if not isinstance(password, str) or not password:
        return unavailable("password_missing")
    # Masked in every event and finding from here on, before anything can fail.
    redactor.add_secret(password)
    try:
        # Function-local and guarded: psycopg is only needed when a project
        # configures a schema, and a broken install degrades, never fails a run.
        from pydantic import ValidationError

        from app.db_schema import postgres
        from app.db_schema.contracts import LocalConnection, SchemaUnavailable
    except Exception:  # noqa: BLE001
        return unavailable("unavailable")
    try:
        config = LocalConnection.model_validate(block)
    except ValidationError:
        return unavailable("invalid_config")
    try:
        result = asyncio.run(
            postgres.read_schema(
                config,
                config.password.get_secret_value(),
                config.tables,
                sslrootcert=config.sslrootcert,
            )
        )
    except SchemaUnavailable as exc:
        return unavailable(exc.code)
    except Exception:  # noqa: BLE001 — the adapter maps its own failures; belt and braces
        return unavailable("unavailable")
    context = {
        "tables": list(result.get("tables") or []),
        "warnings": list(result.get("warnings") or []),
    }
    return {"status": "available", **context}, context
