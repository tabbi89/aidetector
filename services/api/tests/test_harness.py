"""Regression tests for isolation and failure behavior of our own test harness."""
from __future__ import annotations

import socket
import subprocess

import httpx
import pytest
from sqlalchemy.engine import make_url
from sqlalchemy.exc import OperationalError, ProgrammingError

from app.core.config import settings
from tests import harness, vulnapp
from tests.fakes import CollectorOob, adjunct_harness

APP_URL = "postgresql+psycopg://app:password@localhost/app"


@pytest.mark.parametrize("explicit", [
    APP_URL,
    "postgresql+psycopg://other:secret@LOCALHOST:5432/app?sslmode=require",
    "postgresql+psycopg://app:password@localhost/customer_data",
    "postgresql+psycopg://app:password@localhost/unsafe_test?dbname=app",
    "postgresql+psycopg://app:password@localhost/unsafe_test?service=production",
    "postgresql+psycopg://app:password@localhost/unsafe_test?host=other",
    "postgresql+psycopg://app:password@localhost/unsafe_test?options=-csearch_path=app",
    "postgresql+psycopg://app:password@localhost/" + "a" * 64 + "_test",
    'postgresql+psycopg://app:password@localhost/bad%22_test',
    "sqlite:///scratch_test",
])
def test_unsafe_database_is_rejected_before_any_connection(monkeypatch, explicit):
    def unexpected(*_args, **_kwargs):
        pytest.fail("Unsafe URL reached engine creation")

    monkeypatch.setattr(harness, "create_engine", unexpected)
    with pytest.raises(ValueError):
        harness.open_test_database(APP_URL, explicit, required=False)


@pytest.mark.parametrize("host", ["localhost", "LOCALHOST:5432", "127.0.0.1", "db-alias"])
def test_test_suffix_does_not_allow_reusing_the_application_database(host):
    app = APP_URL + "_test"
    candidate = f"postgresql+psycopg://different:secret@{host}/app_test?application_name=pytest"
    with pytest.raises(ValueError, match="differ"):
        harness.test_database_url(app, candidate)


def test_default_and_explicit_disposable_database_urls():
    assert make_url(harness.test_database_url(APP_URL)).database == "app_test"
    # Even an application whose name ends in _test gets a distinct derived DB.
    assert make_url(harness.test_database_url(APP_URL + "_test")).database == "app_test_test"
    explicit = "postgresql+psycopg://tester:secret@localhost:5433/harness_test?sslmode=disable"
    assert harness.test_database_url(APP_URL, explicit) == explicit


def test_each_xdist_worker_gets_its_own_disposable_database():
    url = harness.test_database_url(APP_URL, worker="gw3")
    assert make_url(url).database == "app_gw3_test"
    explicit = "postgresql+psycopg://tester:secret@localhost:5433/harness_test"
    assert make_url(harness.test_database_url(APP_URL, explicit, worker="gw0")).database == (
        "harness_gw0_test"
    )
    # The derived name still answers every rule, including the identifier limit.
    with pytest.raises(ValueError, match="max 63"):
        harness.test_database_url(APP_URL.replace("/app", "/" + "a" * 55), worker="gw1")
    with pytest.raises(ValueError, match="worker"):
        harness.test_database_url(APP_URL, worker="gw0; DROP")


def test_application_routing_overrides_cannot_hide_the_real_database(monkeypatch):
    def unexpected(*_args, **_kwargs):
        pytest.fail("Ambiguous application routing reached engine creation")

    monkeypatch.setattr(harness, "create_engine", unexpected)
    with pytest.raises(ValueError, match="connection options"):
        harness.open_test_database(
            APP_URL + "?dbname=hidden_test", APP_URL.replace("/app", "/hidden_test"), required=True
        )


def test_implicit_application_database_is_rejected():
    with pytest.raises(ValueError, match="named explicitly"):
        harness.test_database_url("postgresql+psycopg://None_test@localhost")


class DatabaseDouble:
    def __init__(self, error=None):
        self.error = error
        self.disposed = False
        self.closed = False
        self.statements = []

    def connect(self):
        if self.error:
            raise self.error
        return self

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        self.closed = True

    def execute(self, statement, *_args):
        self.statements.append(str(statement))
        return self

    def scalar(self):
        return False

    def dispose(self):
        self.disposed = True


@pytest.mark.parametrize("required", [False, True])
@pytest.mark.parametrize("failing_connection", [0, 1])
def test_database_outage_skips_only_when_optional(monkeypatch, required, failing_connection):
    # The simulated outage sets the module-global flag the session-finish hook
    # reads, so restore it afterwards or every real run reports a false skip.
    monkeypatch.setattr(harness, "_db_skipped", False)
    engines = [DatabaseDouble(), DatabaseDouble()]
    engines[failing_connection].error = OperationalError("", {}, Exception("secret DSN"))
    pending = iter(engines)
    monkeypatch.setattr(harness, "create_engine", lambda *_a, **_kw: next(pending))
    expected = pytest.fail.Exception if required else pytest.skip.Exception
    with pytest.raises(expected) as exc:
        harness.open_test_database(APP_URL, None, required=required)
    assert "secret DSN" not in str(exc.value)
    assert engines[0].disposed
    if failing_connection == 1:
        assert engines[1].disposed


@pytest.mark.parametrize("error", [
    RuntimeError("bug"), ProgrammingError("", {}, Exception("bad SQL")),
])
def test_programming_errors_never_become_optional_skips(monkeypatch, error):
    engine = DatabaseDouble(error)
    monkeypatch.setattr(harness, "create_engine", lambda *_a, **_kw: engine)
    with pytest.raises(type(error)):
        harness.open_test_database(APP_URL, None, required=False)
    assert engine.disposed


def test_disposable_database_is_created_and_connections_are_closed(monkeypatch):
    admin, target = DatabaseDouble(), DatabaseDouble()
    pending = iter([admin, target])
    destinations = []

    def create(url, **_kwargs):
        destinations.append(url.database)
        return next(pending)

    monkeypatch.setattr(harness, "create_engine", create)
    assert harness.open_test_database(APP_URL, None, required=True) is target
    assert destinations == ["postgres", "app_test"]
    assert admin.statements[-1] == 'CREATE DATABASE "app_test"'
    assert admin.disposed and admin.closed and target.closed
    assert not target.disposed  # caller owns the yielded engine


@pytest.mark.parametrize(("ci", "required", "expected"), [
    ("", "", False), ("false", "0", False), ("true", "0", True),
    ("", "1", True), ("1", "", True),
])
def test_ci_cannot_opt_out_of_required_database(monkeypatch, ci, required, expected):
    monkeypatch.setenv("CI", ci)
    monkeypatch.setenv("TEST_REQUIRE_DB", required)
    assert harness.database_required() is expected


def test_ambient_services_are_disabled_before_running_gates(monkeypatch):
    from app.engine import adjuncts, runner

    names = ["oast_server", "zap_base_url", "kali_base_url", "sqlmap_bin", "dalfox_bin",
             "commix_bin", "tplmap_bin", "testssl_bin", "anthropic_api_key", "deepseek_api_key"]
    for name in names:
        monkeypatch.setattr(settings, name, "sentinel-external-service")
    harness.reset_settings(monkeypatch)
    assert all(getattr(settings, name) == "" for name in names)
    assert not runner._build_oob_client().active
    db, scan, emit, events = adjunct_harness(base_url="https://target.test")
    adjuncts.run_zap(db, scan, emit)
    adjuncts.run_kali(db, scan, emit)
    adjuncts.run_testssl(db, scan, emit)
    assert list(adjuncts.confirm_passes(
        db, scan, emit, deadline=0, should_stop=lambda: False
    )) == []
    # Each pass was asked for directly, so an unconfigured tool reports itself.
    assert events == ["zap_skipped", "kali_skipped", "testssl_skipped"]


def test_real_http_and_raw_socket_traffic_are_blocked():
    with pytest.raises(pytest.fail.Exception, match="Unexpected external I/O"):
        httpx.get("http://192.0.2.1", trust_env=False)
    with socket.socket() as sock:
        with pytest.raises(pytest.fail.Exception, match="Unexpected external I/O"):
            sock.connect_ex(("127.0.0.1", 9))
    with socket.socket(type=socket.SOCK_DGRAM) as sock:
        with pytest.raises(pytest.fail.Exception, match="Unexpected external I/O"):
            sock.sendto(b"sentinel", ("192.0.2.1", 53))


def test_external_dns_is_not_used():
    with pytest.raises(socket.gaierror):
        socket.getaddrinfo("sentinel-external-service.invalid", 443)


def test_tool_processes_are_blocked():
    with pytest.raises(pytest.fail.Exception, match="Unexpected external I/O"):
        subprocess.run(["sentinel-tool"], check=True)


def test_reset_clears_callbacks_in_place_and_restores_mutable_target_stores():
    outbound = vulnapp.OUTBOUND
    collector = CollectorOob(outbound)
    outbound.append("http://old.oast.test/callback")
    vulnapp._ACCOUNTS[1]["balance"] = -1
    vulnapp._WIDGETS[1]["role"] = "changed"
    for name in ("_ORDERS", "_RECORDS", "_PROJECTS", "_PROJECT_ITEMS"):
        getattr(vulnapp, name)[999] = {"sentinel": True}
    vulnapp._SIGNUPS.add("sentinel")
    vulnapp._ORDER_REFS.add("sentinel")
    vulnapp.reset_state()
    assert vulnapp.OUTBOUND is outbound
    assert collector.poll() == []
    assert vulnapp._ACCOUNTS == vulnapp._SEED_ACCOUNTS
    assert vulnapp._WIDGETS == vulnapp._SEED_WIDGETS
    for name in ("_ORDERS", "_RECORDS", "_PROJECTS", "_PROJECT_ITEMS", "_SIGNUPS", "_ORDER_REFS"):
        assert not getattr(vulnapp, name)
