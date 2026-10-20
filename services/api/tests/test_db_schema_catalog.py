"""Production catalog queries against transactional, disposable DB fixtures."""

from __future__ import annotations

import uuid

import pytest
from sqlalchemy import text

from app.db_schema.postgres import COLUMNS, CONSTRAINTS, PRIVILEGES


@pytest.fixture
def catalog(db_engine):
    suffix = uuid.uuid4().hex[:12]
    role, namespace = f"metadata_{suffix}", f"fixture_{suffix}"
    with db_engine.connect() as connection:
        transaction = connection.begin()
        try:
            database = connection.execute(text("SELECT current_database()")).scalar_one()
            assert database.endswith("_test")
            connection.execute(text(f'CREATE ROLE "{role}" NOLOGIN'))
            connection.execute(text(f'REVOKE TEMP, CREATE ON DATABASE "{database}" FROM PUBLIC'))
            connection.execute(text("REVOKE CREATE ON SCHEMA public FROM PUBLIC"))
            connection.execute(text(f'CREATE SCHEMA "{namespace}"'))
            connection.execute(text(f'CREATE TABLE "{namespace}".owners (id integer PRIMARY KEY)'))
            connection.execute(
                text(f"""CREATE TABLE "{namespace}".widgets (
                id integer PRIMARY KEY,
                owner_id integer REFERENCES "{namespace}".owners(id),
                title varchar(40) NOT NULL UNIQUE DEFAULT 'private-default-sentinel',
                CHECK (title <> 'private-check-sentinel')
            )""")
            )
            connection.execute(
                text(f"COMMENT ON TABLE \"{namespace}\".widgets IS 'private-comment'")
            )
            yield connection, role, namespace
        finally:
            transaction.rollback()


def as_reader(connection, role):
    connection.execute(text(f'SET SESSION AUTHORIZATION "{role}"'))


def allowed(connection):
    return connection.execute(text(PRIVILEGES)).scalar_one()


def test_metadata_only_role_reads_structure_without_row_access(catalog):
    connection, role, namespace = catalog
    as_reader(connection, role)
    assert allowed(connection) is True
    params = (namespace, "widgets")
    columns = connection.exec_driver_sql(COLUMNS, params).mappings().all()
    constraints = connection.exec_driver_sql(CONSTRAINTS, params).mappings().all()
    assert [c["name"] for c in columns] == ["id", "owner_id", "title"]
    assert columns[-1]["max_length"] == 40 and columns[-1]["nullable"] is False
    assert {c["kind"] for c in constraints} == {"p", "u", "f"}
    assert "private-" not in str(columns) + str(constraints)
    assert (
        connection.execute(
            text(
                "SELECT pg_catalog.has_table_privilege(:role, c.oid, 'SELECT') "
                "FROM pg_catalog.pg_class c JOIN pg_catalog.pg_namespace n ON n.oid=c.relnamespace "
                "WHERE c.relname='widgets' AND n.nspname=:namespace"
            ),
            {"role": role, "namespace": namespace},
        ).scalar_one()
        is False
    )


@pytest.mark.parametrize(
    "grant",
    [
        'GRANT SELECT ON "{namespace}".widgets TO "{role}"',
        'GRANT SELECT (title) ON "{namespace}".widgets TO "{role}"',
        'GRANT UPDATE (title) ON "{namespace}".widgets TO "{role}"',
        'GRANT SELECT ON "{namespace}".widgets TO PUBLIC',
        'GRANT CREATE ON SCHEMA "{namespace}" TO "{role}"',
        'ALTER TABLE "{namespace}".widgets OWNER TO "{role}"',
        'ALTER ROLE "{role}" CREATEDB',
        'ALTER ROLE "{role}" CREATEROLE',
        'ALTER ROLE "{role}" BYPASSRLS',
        'ALTER ROLE "{role}" REPLICATION',
        'ALTER ROLE "{role}" SUPERUSER',
        'GRANT pg_read_all_data TO "{role}"',
        "CREATE FUNCTION \"{namespace}\".read_secret() RETURNS int LANGUAGE SQL AS 'SELECT 1'",
        "CREATE TYPE \"{namespace}\".owned_type AS ENUM ('private-enum'); "
        'ALTER TYPE "{namespace}".owned_type OWNER TO "{role}"',
        'CREATE SEQUENCE "{namespace}".seq; GRANT USAGE ON "{namespace}".seq TO "{role}"',
    ],
)
def test_effective_overprivilege_is_refused(catalog, grant):
    connection, role, namespace = catalog
    connection.execute(text(grant.format(role=role, namespace=namespace)))
    as_reader(connection, role)
    assert allowed(connection) is False


def test_real_adapter_connects_with_metadata_only_credentials(db_engine, monkeypatch):
    """Full libpq path to the harness DB only; temporary grants restored in finally."""
    import asyncio
    from unittest.mock import AsyncMock

    from app.db_schema import postgres
    from app.db_schema.contracts import ConnectionConfig

    suffix = uuid.uuid4().hex[:12]
    role, namespace = f"meta_login_{suffix}", f"adapter_{suffix}"
    database = db_engine.url.database
    assert database and database.endswith("_test")
    with db_engine.connect() as connection:
        address = connection.connection.driver_connection.info.hostaddr
        # Inspect only the disposable test database's prior PUBLIC grants.
        public_privileges = (
            connection.execute(
                text(
                    "SELECT a.privilege_type FROM pg_catalog.pg_database d, "
                    "LATERAL pg_catalog.aclexplode(COALESCE(d.datacl, "
                    "pg_catalog.acldefault('d', d.datdba))) a "
                    "WHERE d.datname = current_database() AND a.grantee = 0"
                )
            )
            .scalars()
            .all()
        )
        connection.commit()
        try:
            connection.execute(text(f"CREATE ROLE \"{role}\" LOGIN PASSWORD 'fixture-password'"))
            connection.execute(text(f'REVOKE TEMP, CREATE ON DATABASE "{database}" FROM PUBLIC'))
            connection.execute(text(f'CREATE SCHEMA "{namespace}"'))
            connection.execute(
                text(f'CREATE TABLE "{namespace}".widgets (title varchar(40) NOT NULL)')
            )
            connection.commit()
            monkeypatch.setattr(postgres, "resolve_address", AsyncMock(return_value=address))
            config = ConnectionConfig(
                label="Fixture",
                host=db_engine.url.host,
                port=db_engine.url.port or 5432,
                database=database,
                username=role,
                sslmode="disable",
                tables=[{"schema_name": namespace, "table_name": "widgets"}],
            )
            result = asyncio.run(postgres.read_schema(config, "fixture-password", config.tables))
            assert result["tables"][0]["columns"] == [
                {"name": "title", "type_name": "varchar", "nullable": False, "max_length": 40},
            ]
        finally:
            connection.rollback()
            connection.execute(text(f'DROP SCHEMA IF EXISTS "{namespace}" CASCADE'))
            connection.execute(text(f'DROP ROLE IF EXISTS "{role}"'))
            for privilege in ("CREATE", "TEMPORARY"):
                if privilege in public_privileges:
                    connection.execute(
                        text(f'GRANT {privilege} ON DATABASE "{database}" TO PUBLIC')
                    )
            connection.commit()
