"""Safety boundaries for the test harness, independently regression-testable."""
from __future__ import annotations

import os
import re

import pytest
from sqlalchemy import create_engine, text
from sqlalchemy.engine import Engine, make_url
from sqlalchemy.exc import OperationalError

from app.core.config import Settings, settings


def database_required() -> bool:
    return any(
        os.getenv(key, "").strip().lower() not in {"", "0", "false", "no"}
        for key in ("CI", "TEST_REQUIRE_DB")
    )


#: Set when the optional test database was unreachable and the DB-backed tests
#: were skipped. Read by the session-finish hook in ``conftest.py`` so a locally
#: green run that never exercised its DB tier cannot pass silently.
_db_skipped = False


def was_database_skipped() -> bool:
    """Whether any test in this session skipped because Postgres was absent."""
    return _db_skipped


def test_database_url(
    app_url: str, explicit: str | None = None, *, worker: str | None = None
) -> str:
    """Require a distinct disposable PostgreSQL database before any connection.

    Under pytest-xdist each worker (``gw0``, ``gw1``, …) gets its own database,
    ``<name>_gw0_test``, because every test truncates all tables; the name is
    derived *before* validation, so it answers the same rules.

    Reject the application's database name even on a different host: aliases,
    proxies and libpq configuration make host equality an unreliable safeguard.
    Routing query parameters are forbidden so they cannot override the checked
    URL. Credentials and harmless connection options never establish isolation.
    """
    app = make_url(app_url)
    if not app.database:
        raise ValueError("Application database must be named explicitly for test isolation")
    url = make_url(explicit) if explicit else app.set(database=f"{app.database}_test")
    if worker:
        if not re.fullmatch(r"gw[0-9]+", worker):
            raise ValueError("Unexpected pytest-xdist worker id")
        base = url.database or ""
        if base.endswith("_test"):
            url = url.set(database=f"{base[: -len('_test')]}_{worker}_test")
    name = url.database or ""
    if app.get_backend_name() != "postgresql" or url.get_backend_name() != "postgresql":
        raise ValueError("Tests require a disposable PostgreSQL database")
    if not re.fullmatch(r"[a-zA-Z_][a-zA-Z0-9_]*_test", name) or len(name) > 63:
        raise ValueError("Test database name must be an identifier ending in _test (max 63 bytes)")
    if name == app.database:
        raise ValueError("Test database must differ from the application database")
    allowed = {"sslmode", "sslrootcert", "sslcert", "sslkey", "application_name", "connect_timeout"}
    if (set(app.query) | set(url.query)) - allowed:
        raise ValueError("Test database URL contains unsupported connection options")
    return url.render_as_string(hide_password=False)


def open_test_database(
    app_url: str, explicit: str | None, *, required: bool, worker: str | None = None
) -> Engine:
    """Validate, create and connect; only optional local outages become skips."""
    url = make_url(test_database_url(app_url, explicit, worker=worker))
    engine = None
    try:
        admin = create_engine(
            url.set(database="postgres"), isolation_level="AUTOCOMMIT",
            connect_args={"connect_timeout": 3},
        )
        try:
            with admin.connect() as conn:
                exists = conn.execute(
                    text("SELECT 1 FROM pg_database WHERE datname = :n"), {"n": url.database}
                ).scalar()
                if not exists:
                    # The identifier was restricted to ASCII letters/digits/_ above.
                    conn.execute(text(f'CREATE DATABASE "{url.database}"'))
        finally:
            admin.dispose()
        engine = create_engine(url, pool_pre_ping=True, connect_args={"connect_timeout": 3})
        with engine.connect():
            pass
    except OperationalError:
        if engine is not None:
            engine.dispose()
        # Never echo a connection URL or driver exception containing credentials.
        if required:
            pytest.fail("Required test database is unavailable", pytrace=False)
        global _db_skipped
        _db_skipped = True
        pytest.skip("Optional test database is unavailable; set TEST_REQUIRE_DB=1 to require it")
    except Exception:
        if engine is not None:
            engine.dispose()
        raise
    return engine


def reset_settings(monkeypatch: pytest.MonkeyPatch) -> None:
    """Use declared defaults, ignoring .env and ambient service/credential config.

    Database routing stays explicit so developers and CI can choose a disposable
    server. Tests can override individual settings after this autouse baseline.
    """
    for name, field in Settings.model_fields.items():
        if name != "database_url":
            monkeypatch.setattr(settings, name, field.get_default())
