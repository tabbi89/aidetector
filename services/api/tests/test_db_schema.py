"""Database metadata boundaries: no live targets or model calls.

The adapter runs only in the CLI's local runner; these pin what it still
refuses there (cloud metadata, ambient libpq routing, unverified "verify-full")
and what it no longer needs (an operator allowlist: the user's own machine
connecting to the user's own database).
"""

from __future__ import annotations

import asyncio
import json
from unittest.mock import AsyncMock

import pytest
from pydantic import ValidationError

from app.db_schema import postgres
from app.db_schema.contracts import (
    ConnectionConfig,
    ConnectionInput,
    LocalConnection,
    SchemaUnavailable,
)

TABLE = {"schema_name": "public", "table_name": "widgets"}
CONFIG = {
    "label": "Schema context",
    "host": "127.0.0.1",
    "port": 5432,
    "database": "targetdb",
    "username": "schema_reader",
    "sslmode": "disable",
    "tables": [TABLE],
}
PASSWORD = "private-db-password-sentinel"


@pytest.fixture
def permitted(monkeypatch):
    # No ambient libpq routing on the machine running the test.
    monkeypatch.delenv("PGSERVICE", raising=False)
    monkeypatch.delenv("PGSERVICEFILE", raising=False)


@pytest.mark.parametrize(
    "change",
    [
        {"host": "/var/run/postgresql"},
        {"host": "db,evil"},
        {"host": "::ffff:169.254.1.1%eth0"},
        {"database": "host=evil password=sentinel"},
        {"database": "postgresql://evil/db"},
        {"username": "user password=sentinel"},
        {"options": "-c role=admin"},
        {"hostaddr": "evil"},
        {"service": "secret"},
        {"sslmode": "prefer"},
        {"sslrootcert": "/secret"},
        {"tables": []},
        {"tables": [TABLE] * 21},
        {"tables": [TABLE, TABLE]},
        {"tables": [{"schema_name": "public", "table_name": "*"}, TABLE]},
        {"tables": [{"schema_name": "pg_catalog", "table_name": "pg_authid"}]},
        {"tables": [{"schema_name": "public", "table_name": "x; SELECT secret"}]},
        {"port": True},
    ],
)
def test_connection_input_rejects_routes_and_unbounded_scope(change):
    with pytest.raises(ValidationError):
        ConnectionInput.model_validate({**CONFIG, "password": PASSWORD, **change})


@pytest.mark.parametrize("host", ["metadata", "metadata.google.internal", "instance-data"])
def test_cloud_metadata_names_are_refused(permitted, host):
    with pytest.raises(SchemaUnavailable, match="destination_not_allowed"):
        postgres.check_configuration(ConnectionConfig(**{**CONFIG, "host": host}))


def test_verified_tls_requires_a_ca(permitted):
    config = ConnectionConfig(**{**CONFIG, "sslmode": "verify-full"})
    with pytest.raises(SchemaUnavailable, match="tls_ca_unconfigured"):
        postgres.check_configuration(config)
    postgres.check_configuration(config, "/run/aidetector/schema-ca.pem")


def test_no_operator_allowlist_is_needed_on_the_cli_machine(permitted):
    # The server-era DB_SCHEMA_DESTINATIONS gate is gone: a local run reads the
    # user's own database, so a plain config passes the policy unaided.
    postgres.check_configuration(ConnectionConfig(**CONFIG))


@pytest.mark.parametrize(
    "host",
    [
        "169.254.169.254",
        "::ffff:169.254.169.254",
        "2002:a9fe:a9fe::1",  # 6to4 embedding 169.254.169.254
        "64:ff9b::a9fe:a9fe",  # NAT64 embedding 169.254.169.254
        "100.100.100.200",
        "168.63.129.16",
        "fd00:ec2::254",
        "fe80::1",
        "0.0.0.0",
        "::",
        "224.0.0.1",
        "ff02::1",
    ],
)
def test_forbidden_address_is_refused(permitted, host):
    with pytest.raises(SchemaUnavailable, match="destination_not_allowed"):
        asyncio.run(postgres.resolve_address(ConnectionConfig(**{**CONFIG, "host": host})))


@pytest.mark.parametrize("host", ["127.0.0.1", "::1", "10.0.0.5", "192.168.1.20"])
def test_private_and_loopback_databases_are_the_point(permitted, host):
    address = asyncio.run(postgres.resolve_address(ConnectionConfig(**{**CONFIG, "host": host})))
    assert address == host


def test_mixed_dns_answer_is_refused(permitted, monkeypatch):
    monkeypatch.setattr(
        postgres.dns,
        "resolve",
        AsyncMock(
            return_value=["10.0.0.2", "169.254.169.254"],
        ),
    )
    with pytest.raises(SchemaUnavailable, match="destination_not_allowed"):
        asyncio.run(postgres.resolve_address(ConnectionConfig(**{**CONFIG, "host": "db.test"})))


@pytest.mark.parametrize(
    "change",
    [
        {"sslrootcert": "relative/ca.pem"},
        {"sslrootcert": "/run/ca.pem host=evil"},
        {"options": "-c role=admin"},
        {"password": ""},
    ],
)
def test_local_connection_rejects_routes(change):
    with pytest.raises(ValidationError):
        LocalConnection.model_validate({**CONFIG, "password": PASSWORD, **change})


class Cursor:
    def __init__(self, rows):
        self.rows = rows

    async def fetchone(self):
        return self.rows[0] if self.rows else None

    async def fetchall(self):
        return self.rows


class CatalogConnection:
    def __init__(self, *, allowed=True, columns=None, constraints=None, tables=None):
        self.allowed = allowed
        self.columns = (
            columns
            if columns is not None
            else [
                {"name": "title", "type_name": "varchar", "nullable": False, "max_length": 40},
            ]
        )
        self.constraints = constraints or []
        self.tables = tables if tables is not None else [{"table_name": "widgets"}]
        self.calls = []
        self.closed = False

    async def __aenter__(self):
        return self

    async def __aexit__(self, *args):
        return False

    async def close(self):
        self.closed = True

    async def execute(self, query, params=None):
        self.calls.append((query, params))
        rows = []
        if query == postgres.PRIVILEGES:
            rows = [{"allowed": self.allowed}]
        elif query == postgres.TABLES:
            rows = self.tables
        elif query == postgres.COLUMNS:
            rows = self.columns
        elif query == postgres.CONSTRAINTS:
            rows = self.constraints
        else:
            assert query == "SET TRANSACTION READ ONLY"
        return Cursor(rows)


def bind_catalog(monkeypatch, connection):
    connect = AsyncMock(return_value=connection)
    monkeypatch.setattr(postgres.psycopg.AsyncConnection, "connect", connect)
    return connect


def test_catalog_queries_are_fixed_pinned_and_value_free(permitted, monkeypatch):
    connection = CatalogConnection(
        constraints=[
            {
                "kind": "f",
                "columns": ["owner_id"],
                "ref_schema": "private",
                "ref_table": "secret_table",
                "ref_columns": ["id"],
            },
        ]
    )
    connect = bind_catalog(monkeypatch, connection)
    config = ConnectionConfig(**CONFIG)
    result = asyncio.run(postgres.read_schema(config, PASSWORD, config.tables))
    assert result["tables"][0]["columns"][0]["max_length"] == 40
    assert result["tables"][0]["constraints"] == []
    assert "secret_table" not in json.dumps(result) and PASSWORD not in json.dumps(result)
    kwargs = connect.call_args.kwargs
    assert kwargs["hostaddr"] == "127.0.0.1"
    assert kwargs["password"] == PASSWORD
    assert kwargs["sslcert"] == "/dev/null/client.crt"
    assert kwargs["ssl_min_protocol_version"] == "TLSv1.2"
    assert kwargs["gssencmode"] == "disable" and kwargs["passfile"] == "/dev/null"
    assert "default_transaction_read_only=on" in kwargs["options"]
    assert kwargs["sslrootcert"] == "/dev/null"  # no CA configured, sslmode=disable
    assert connection.calls[-1][1] == ("public", "widgets")
    assert connection.closed


def test_a_configured_ca_reaches_libpq(permitted, monkeypatch):
    connect = bind_catalog(monkeypatch, CatalogConnection())
    config = ConnectionConfig(**{**CONFIG, "sslmode": "verify-full"})
    asyncio.run(
        postgres.read_schema(
            config, PASSWORD, config.tables, sslrootcert="/run/aidetector/schema-ca.pem"
        )
    )
    kwargs = connect.call_args.kwargs
    assert kwargs["sslmode"] == "verify-full"
    assert kwargs["sslrootcert"] == "/run/aidetector/schema-ca.pem"


def test_privileged_account_is_reported_but_metadata_remains_read_only(permitted, monkeypatch):
    connection = CatalogConnection(allowed=False)
    bind_catalog(monkeypatch, connection)
    config = ConnectionConfig(**CONFIG)
    result = asyncio.run(postgres.read_schema(config, PASSWORD, config.tables))
    assert result["warnings"] == ["privileged_account"]
    assert connection.calls[-1][0] == postgres.CONSTRAINTS and connection.closed


def test_schema_wildcard_expands_to_bounded_table_list(permitted, monkeypatch):
    connection = CatalogConnection(tables=[{"table_name": "accounts"}, {"table_name": "widgets"}])
    bind_catalog(monkeypatch, connection)
    config = ConnectionConfig(
        **{**CONFIG, "tables": [{"schema_name": "public", "table_name": "*"}]}
    )
    result = asyncio.run(postgres.read_schema(config, PASSWORD, config.tables))
    assert [table["table_name"] for table in result["tables"]] == ["accounts", "widgets"]
    assert any(query == postgres.TABLES for query, _ in connection.calls)


def test_schema_wildcard_keeps_table_discovery_bounded(permitted, monkeypatch):
    connection = CatalogConnection(
        tables=[{"table_name": f"table_{index}"} for index in range(51)]
    )
    bind_catalog(monkeypatch, connection)
    config = ConnectionConfig(
        **{**CONFIG, "tables": [{"schema_name": "public", "table_name": "*"}]}
    )
    with pytest.raises(SchemaUnavailable, match="metadata_limit"):
        asyncio.run(postgres.read_schema(config, PASSWORD, config.tables))


@pytest.mark.parametrize(
    "columns, code",
    [
        ([], "table_unavailable"),
        ([{}] * 201, "metadata_limit"),
        ([{"name": "x" * 70000}], "metadata_limit"),
    ],
)
def test_metadata_limits(permitted, monkeypatch, columns, code):
    bind_catalog(monkeypatch, CatalogConnection(columns=columns))
    config = ConnectionConfig(**CONFIG)
    with pytest.raises(SchemaUnavailable, match=code):
        asyncio.run(postgres.read_schema(config, PASSWORD, config.tables))


def test_driver_failures_never_echo_password(permitted, monkeypatch, caplog):
    connect = AsyncMock(side_effect=RuntimeError(PASSWORD))
    monkeypatch.setattr(postgres.psycopg.AsyncConnection, "connect", connect)
    config = ConnectionConfig(**CONFIG)
    with pytest.raises(SchemaUnavailable) as error:
        asyncio.run(postgres.read_schema(config, PASSWORD, config.tables))
    assert str(error.value) == "unavailable"
    assert PASSWORD not in caplog.text


def test_total_deadline_includes_connect(permitted, monkeypatch):
    async def stalled(**kwargs):
        await asyncio.Event().wait()

    monkeypatch.setattr(postgres, "TIMEOUT_SECONDS", 0.01)
    monkeypatch.setattr(postgres.psycopg.AsyncConnection, "connect", stalled)
    config = ConnectionConfig(**CONFIG)
    with pytest.raises(SchemaUnavailable):
        asyncio.run(postgres.read_schema(config, PASSWORD, config.tables))


def test_dns_timeout_terminates_resolver(monkeypatch):
    from app.db_schema import dns

    class HungResolver:
        returncode = None
        killed = False
        waited = False

        async def communicate(self):
            await asyncio.Event().wait()

        def kill(self):
            self.killed = True
            self.returncode = -9

        async def wait(self):
            self.waited = True
            return self.returncode

    process = HungResolver()
    spawn = AsyncMock(return_value=process)
    monkeypatch.setattr(asyncio, "create_subprocess_exec", spawn)

    async def bounded():
        async with asyncio.timeout(0.01):
            await dns.resolve("db.test", 5432)

    with pytest.raises(TimeoutError):
        asyncio.run(bounded())
    assert process.killed and process.waited
    assert "-I" in spawn.call_args.args


@pytest.mark.allow_subprocess
def test_isolated_dns_resolves_only_localhost():
    from app.db_schema import dns

    addresses = asyncio.run(dns.resolve("localhost", 5432))
    assert addresses and set(addresses) <= {"127.0.0.1", "::1"}


@pytest.mark.parametrize("variable", ["PGSERVICE", "PGSERVICEFILE"])
def test_ambient_libpq_services_are_not_inherited(permitted, monkeypatch, variable):
    monkeypatch.setenv(variable, "private-connection")
    with pytest.raises(SchemaUnavailable, match="ambient_service_forbidden"):
        postgres.check_configuration(ConnectionConfig(**CONFIG))


def test_two_wildcards_cannot_exceed_what_the_upload_accepts(permitted, monkeypatch):
    # Each schema.* fits under MAX_TABLES, the sum does not: the run gets a named
    # reason rather than a snapshot the server would reject as invalid_upload.
    connection = CatalogConnection(tables=[{"table_name": f"t{index}"} for index in range(30)])
    bind_catalog(monkeypatch, connection)
    config = ConnectionConfig(**{**CONFIG, "tables": [
        {"schema_name": "app", "table_name": "*"},
        {"schema_name": "audit", "table_name": "*"},
    ]})
    with pytest.raises(SchemaUnavailable, match="metadata_limit"):
        asyncio.run(postgres.read_schema(config, PASSWORD, config.tables))


def test_without_tls_the_password_is_never_sent_in_the_clear(permitted, monkeypatch):
    connect = bind_catalog(monkeypatch, CatalogConnection())
    config = ConnectionConfig(**CONFIG)  # sslmode=disable
    asyncio.run(postgres.read_schema(config, PASSWORD, config.tables))
    assert connect.call_args.kwargs["require_auth"] == "!password"
    connect = bind_catalog(monkeypatch, CatalogConnection())
    config = ConnectionConfig(**{**CONFIG, "sslmode": "verify-full"})
    asyncio.run(postgres.read_schema(config, PASSWORD, config.tables, sslrootcert="/ca.pem"))
    assert connect.call_args.kwargs["require_auth"] is None
