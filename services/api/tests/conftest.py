"""Shared fixtures. Optional local DB tests skip when Postgres is unreachable.

Tests run against a DEDICATED ``<db>_test`` database, never the app/dev database,
so schema resets and migrations can never clobber a running stack's data.
The test DB is auto-created if missing; override it entirely with
``TEST_DATABASE_URL`` (a distinct database ending in ``_test``).
CI or ``TEST_REQUIRE_DB=1`` makes database unavailability an error.

Every test starts from an empty database: :func:`_clean_database` truncates
before each test rather than after, so a test is isolated from its predecessors
no matter how they exited. Without it the schema was created once per session
and rows simply accumulated — tests saw each other's scans, and anything
asserting on a global count only passed because of the order it ran in.
"""
from __future__ import annotations

import json
import os
import socket
import subprocess
import sys
from collections.abc import Iterator

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import text
from sqlalchemy.engine import make_url
from sqlalchemy.orm import sessionmaker

import app.core.db as core_db
from app.core.config import settings
from app.core.db import get_db
from app.main import app
from app.models import Base
from app.workers.celery_app import celery
from tests.harness import database_required, open_test_database, reset_settings

# Run Celery tasks inline so enqueued scans execute within the request in tests.
celery.conf.task_always_eager = True
celery.conf.task_eager_propagates = True


@pytest.fixture(scope="session")
def db_engine():
    engine = open_test_database(
        settings.database_url,
        os.getenv("TEST_DATABASE_URL"),
        required=database_required(),
        worker=os.getenv("PYTEST_XDIST_WORKER"),
    )

    # Point the app's global session factory at the test DB so code paths that
    # use SessionLocal directly (the eager Celery worker) also stay isolated.
    previous_engine = core_db.engine
    previous_bind = core_db.SessionLocal.kw["bind"]
    core_db.engine = engine
    core_db.SessionLocal.configure(bind=engine)

    try:
        Base.metadata.drop_all(engine)
        # Build the schema exactly as deployments do; metadata-only creation
        # hides missing/broken migrations.
        from alembic import command
        from alembic.config import Config

        with engine.begin() as connection:
            connection.execute(text("DROP TABLE IF EXISTS alembic_version"))
            config = Config("alembic.ini")
            config.attributes["connection"] = connection
            command.upgrade(config, "head")
        yield engine
    finally:
        try:
            Base.metadata.drop_all(engine)
        finally:
            core_db.engine = previous_engine
            core_db.SessionLocal.configure(bind=previous_bind)
            engine.dispose()


@pytest.fixture(autouse=True)
def isolated_integrations(monkeypatch, request):
    """No ambient services, target sockets or tool processes in ordinary tests.

    ASGI/MockTransport traffic and event-loop Unix socketpairs remain available.
    PostgreSQL uses libpq; DNS is allowed only for the configured DB endpoint.
    The layering tests explicitly opt into their Python import subprocesses.
    """
    reset_settings(monkeypatch)

    def blocked(*_args, **_kwargs):
        pytest.fail("Unexpected external I/O: inject a fake transport or tool", pytrace=False)

    real_popen = subprocess.Popen

    def guarded_popen(args, *popen_args, **popen_kwargs):
        # The potential-secret detector is application code running in an
        # isolated same-interpreter worker, not an ambient external tool. Permit
        # only its exact fixed command; every caller-controlled or adjunct
        # subprocess remains forbidden in ordinary tests.
        if isinstance(args, list | tuple) and tuple(map(str, args)) == (
            sys.executable,
            "-m",
            "app.engine.secret_scan",
            "--worker",
        ):
            return real_popen(args, *popen_args, **popen_kwargs)
        return blocked()

    connect = socket.socket.connect
    connect_ex = socket.socket.connect_ex

    def guarded_connect(sock, address):
        if sock.family in (socket.AF_INET, socket.AF_INET6):
            blocked()
        return connect(sock, address)

    def guarded_connect_ex(sock, address):
        if sock.family in (socket.AF_INET, socket.AF_INET6):
            blocked()
        return connect_ex(sock, address)

    resolve = socket.getaddrinfo
    db_url = make_url(os.getenv("TEST_DATABASE_URL") or settings.database_url)

    def local_resolution(host, port, family=0, type=0, proto=0, flags=0):
        if host == db_url.host and str(port) == str(db_url.port or 5432):
            return resolve(host, port, family, type, proto, flags)
        # AI_NUMERICHOST forbids DNS; lab names are deterministically unresolved.
        return resolve(host, port, family, type, proto, flags | socket.AI_NUMERICHOST)

    monkeypatch.setattr(socket.socket, "connect", guarded_connect)
    monkeypatch.setattr(socket.socket, "connect_ex", guarded_connect_ex)
    monkeypatch.setattr(socket.socket, "sendto", blocked)
    monkeypatch.setattr(socket, "getaddrinfo", local_resolution)
    if not request.node.get_closest_marker("allow_subprocess"):
        monkeypatch.setattr(subprocess, "Popen", guarded_popen)
        monkeypatch.setattr(os, "system", blocked)


#: Fixtures that mean a test actually touches the database. Requesting the
#: engine for a test that needs none would make every test skip without
#: Postgres — including the pure ones, which is what used to happen.
_DB_FIXTURES = frozenset(
    {"db_engine", "db_session", "client", "make_scan", "seeded_scan",
     "new_scan", "scan_with_spec"}
)


@pytest.fixture(autouse=True)
def _clean_database(request):
    """Empty every table before each test that uses one.

    One ``TRUNCATE`` of all tables is far cheaper than recreating the schema,
    and ``CASCADE`` handles the FK graph without us ordering the deletes.
    Truncating *before* rather than after means a test that crashes mid-way
    can't leave rows behind for the next one.

    Tests that request no database fixture are left alone, so a pure unit test
    runs with no Postgres at all rather than skipping. That distinction matters:
    the run-level tests exist precisely so the runner's invariants stop being
    the ones that silently skip.
    """
    if not _DB_FIXTURES & set(request.fixturenames):
        yield
        return
    engine = request.getfixturevalue("db_engine")
    tables = ", ".join(f'"{t.name}"' for t in reversed(Base.metadata.sorted_tables))
    if tables:
        with engine.begin() as conn:
            conn.execute(text(f"TRUNCATE {tables} RESTART IDENTITY CASCADE"))
    yield


@pytest.fixture(autouse=True)
def _clean_vulnapp():
    """Reset the in-process target's mutable state before each test.

    ``tests/vulnapp.py`` keeps accounts, widgets and signups in module-level
    dicts, and the mutating checks (write oracle, mass assignment, enumeration)
    change them. Without this, a test's result depends on which tests ran first
    — the same reason the database is truncated above.
    """
    from tests.vulnapp import reset_state

    reset_state()
    yield


@pytest.fixture
def db_session(db_engine):
    Session = sessionmaker(bind=db_engine, autoflush=False, expire_on_commit=False)
    s = Session()
    try:
        yield s
    finally:
        s.close()


@pytest.fixture
def client(db_engine) -> Iterator[TestClient]:
    TestingSession = sessionmaker(bind=db_engine, autoflush=False, expire_on_commit=False)

    def override_get_db():
        db = TestingSession()
        try:
            yield db
        finally:
            db.close()

    app.dependency_overrides[get_db] = override_get_db
    with TestClient(app) as c:
        yield c
    app.dependency_overrides.clear()


# ---- engine / scan fixtures --------------------------------------------------


@pytest.fixture
def engine_client() -> TestClient:
    """A client bound to the in-process vulnerable app — no network, no server."""
    from tests.vulnapp import vulnapp

    return TestClient(vulnapp)


@pytest.fixture
def make_scan(db_session):
    """Build and persist scans wired to the vulnerable app, with two identities.

    Returns a callable because several tests need two scans, or a scan that is
    already cancel-requested. Use :func:`seeded_scan` for the common one-scan
    case.
    """
    from tests.factories import scan_row

    def _make(**kwargs):
        scan = scan_row(**kwargs)
        db_session.add(scan)
        db_session.commit()
        db_session.refresh(scan)
        return scan

    return _make


@pytest.fixture
def seeded_scan(make_scan):
    """One persisted scan wired to the vulnerable app, with two identities.

    The scan-level tests (engine run, cascade, report, scheduling) all start
    here; previously they imported a helper from ``test_async_scan``, which
    pulled a whole unrelated test module into collection.
    """
    return make_scan()


# ---- API-level fixtures -------------------------------------------------------

#: A two-operation spec: one object read with a path id, one search with a query.
MINIMAL_SPEC = json.dumps(
    {
        "openapi": "3.0.0",
        "info": {"title": "demo", "version": "1"},
        "paths": {
            "/accounts/{id}": {
                "get": {"parameters": [{"name": "id", "in": "path", "required": True}]}
            },
            "/search": {"get": {"parameters": [{"name": "q", "in": "query"}]}},
        },
    }
)


@pytest.fixture
def new_scan(client):
    """Create a scan over the API and return its id."""

    def _new(target_base_url: str = "http://t") -> str:
        r = client.post("/scans", json={"target_base_url": target_base_url})
        assert r.status_code == 201, r.text
        return r.json()["id"]

    return _new


@pytest.fixture
def scan_with_spec(client, new_scan):
    """Create a scan and ingest :data:`MINIMAL_SPEC`; return its id.

    The pairing most API tests want — a scan is not runnable, schedulable or
    coverable until it has operations.
    """

    def _make(target_base_url: str = "http://t") -> str:
        sid = new_scan(target_base_url)
        r = client.post(f"/scans/{sid}/spec", json={"content": MINIMAL_SPEC})
        assert r.status_code == 200, r.text
        return sid

    return _make


def pytest_sessionfinish(session, exitstatus):
    """A locally-run suite that skipped its DB tier is a green run that never
    exercised the database. The skip reason hides behind ``-q``, so surface it
    here rather than let a developer read "passed" and ship."""
    from tests.harness import database_required, was_database_skipped

    if was_database_skipped() and not database_required():
        reporter = session.config.pluginmanager.get_plugin("terminalreporter")
        if reporter is not None:
            reporter.section(
                "database tests skipped",
                "Postgres was unreachable, so the DB-backed tests were skipped "
                "(the run still exits 0). Set TEST_REQUIRE_DB=1, or run "
                "`make test` in the container, to make this a failure.",
                yellow=True,
            )
