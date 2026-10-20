"""Fixed PostgreSQL catalog queries, pinned egress and enforceable call deadlines.

Runs only inside the local runner, on the machine the user ran ``aidetector
--local`` from: the server never connects to a target database. It stays as
strict as when it ran server-side — fixed catalog queries in a read-only
transaction, one vetted address, hard deadlines, bounded output — because the
runner is still our code holding the user's password.
"""

from __future__ import annotations

import asyncio
import json
import os
from ipaddress import ip_address

import psycopg
from psycopg.rows import dict_row

from app.core.target_guard import METADATA_HOSTNAMES, is_metadata_ip
from app.db_schema import dns
from app.db_schema.contracts import ConnectionConfig, SchemaUnavailable, TableRef

MAX_COLUMNS = 200
MAX_CONSTRAINTS = 100
MAX_TABLES = 50
MAX_BYTES = 64 * 1024
TIMEOUT_SECONDS = 10

# PostgreSQL's effective-privilege helpers include PUBLIC grants. No membership
# is permitted, including NOINHERIT memberships that could be used with SET ROLE.
# Ownership dependencies catch DDL rights over types/functions as well as tables.
PRIVILEGES = """
SELECT current_user = session_user
 AND NOT (r.rolsuper OR r.rolcreaterole OR r.rolcreatedb OR r.rolreplication OR r.rolbypassrls)
 AND NOT EXISTS (SELECT 1 FROM pg_catalog.pg_auth_members WHERE member = r.oid)
 AND NOT EXISTS (SELECT 1 FROM pg_catalog.pg_shdepend
                 WHERE refclassid = 'pg_catalog.pg_authid'::regclass
                   AND refobjid = r.oid AND deptype = 'o')
 AND NOT pg_catalog.has_database_privilege(current_database(), 'CREATE,TEMP')
 AND NOT EXISTS (SELECT 1 FROM pg_catalog.pg_namespace n
                 WHERE pg_catalog.has_schema_privilege(n.oid, 'CREATE'))
 AND NOT EXISTS (
   SELECT 1 FROM pg_catalog.pg_class c JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace
   WHERE n.nspname NOT IN ('pg_catalog', 'information_schema')
     AND ((c.relkind IN ('r','v','m','f','p') AND
          (pg_catalog.has_table_privilege(
            c.oid, 'SELECT,INSERT,UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER')
           OR pg_catalog.has_any_column_privilege(c.oid, 'SELECT,INSERT,UPDATE,REFERENCES')))
       OR (c.relkind = 'S' AND pg_catalog.has_sequence_privilege(c.oid, 'USAGE,SELECT,UPDATE'))))
 AND NOT EXISTS (
   SELECT 1 FROM pg_catalog.pg_proc p JOIN pg_catalog.pg_namespace n ON n.oid = p.pronamespace
   WHERE n.nspname NOT IN ('pg_catalog', 'information_schema')
     AND pg_catalog.has_function_privilege(p.oid, 'EXECUTE')) AS allowed
FROM pg_catalog.pg_roles r WHERE r.rolname = current_user
"""
COLUMNS = """
SELECT a.attname AS name, t.typname AS type_name, NOT a.attnotnull AS nullable,
       CASE WHEN t.typname IN ('varchar','bpchar') AND a.atttypmod >= 4
            THEN a.atttypmod - 4 ELSE NULL END AS max_length
FROM pg_catalog.pg_attribute a
JOIN pg_catalog.pg_class c ON c.oid = a.attrelid
JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace
JOIN pg_catalog.pg_type t ON t.oid = a.atttypid
WHERE n.nspname = %s AND c.relname = %s AND c.relkind IN ('r','p')
  AND a.attnum > 0 AND NOT a.attisdropped
ORDER BY a.attnum LIMIT 201
"""
# Only key structure; no constraint names, expressions, defaults or literal enum values.
CONSTRAINTS = """
SELECT co.contype AS kind,
       ARRAY(SELECT a.attname FROM unnest(co.conkey) WITH ORDINALITY k(num, pos)
             JOIN pg_catalog.pg_attribute a ON a.attrelid = co.conrelid AND a.attnum = k.num
             ORDER BY k.pos) AS columns,
       rn.nspname AS ref_schema, rc.relname AS ref_table,
       ARRAY(SELECT a.attname FROM unnest(co.confkey) WITH ORDINALITY k(num, pos)
             JOIN pg_catalog.pg_attribute a ON a.attrelid = co.confrelid AND a.attnum = k.num
             ORDER BY k.pos) AS ref_columns
FROM pg_catalog.pg_constraint co
JOIN pg_catalog.pg_class c ON c.oid = co.conrelid
JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace
LEFT JOIN pg_catalog.pg_class rc ON rc.oid = co.confrelid
LEFT JOIN pg_catalog.pg_namespace rn ON rn.oid = rc.relnamespace
WHERE n.nspname = %s AND c.relname = %s AND co.contype IN ('p','u','f')
ORDER BY co.oid LIMIT 101
"""
TABLES = """
SELECT c.relname AS table_name
FROM pg_catalog.pg_class c
JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace
WHERE n.nspname = %s AND c.relkind IN ('r','p')
ORDER BY c.relname LIMIT 51
"""


def tables_allowed(requested: list[TableRef], configured: list[TableRef]) -> bool:
    explicit = {(table.schema_name, table.table_name) for table in configured}
    wildcard_schemas = {
        table.schema_name for table in configured if table.table_name == "*"
    }
    return bool(requested) and all(
        (table.schema_name, table.table_name) in explicit
        or table.schema_name in wildcard_schemas
        for table in requested
    )


def check_configuration(config: ConnectionConfig, sslrootcert: str | None = None) -> None:
    # An empty libpq service name is a lookup, not a way to disable services.
    # Refuse ambient service files instead of inheriting hidden connection options.
    if os.getenv("PGSERVICE") or os.getenv("PGSERVICEFILE"):
        raise SchemaUnavailable("ambient_service_forbidden")
    if config.host in METADATA_HOSTNAMES:
        raise SchemaUnavailable("destination_not_allowed")
    if config.sslmode == "verify-full" and not sslrootcert:
        raise SchemaUnavailable("tls_ca_unconfigured")


async def resolve_address(config: ConnectionConfig) -> str:
    try:
        addresses = [ip_address(config.host)]
    except ValueError:
        addresses = [ip_address(value) for value in await dns.resolve(config.host, config.port)]
    if not addresses:
        raise SchemaUnavailable("destination_not_allowed")
    for address in addresses:
        # Private and loopback are the point of a local run (a dev database);
        # cloud metadata never is, in any embedded-IPv4 form the guard knows.
        effective = getattr(address, "ipv4_mapped", None) or address
        if (
            is_metadata_ip(address)
            or effective.is_link_local
            or effective.is_multicast
            or effective.is_unspecified
        ):
            raise SchemaUnavailable("destination_not_allowed")
    # One vetted address, no libpq DNS lookup/fallback or re-resolution.
    return str(addresses[0])


async def read_schema(
    config: ConnectionConfig,
    password: str,
    tables: list[TableRef],
    *,
    sslrootcert: str | None = None,
) -> dict:
    """Read structure for ``tables``. Never returns database exception messages."""
    try:
        async with asyncio.timeout(TIMEOUT_SECONDS):
            check_configuration(config, sslrootcert)
            if not tables_allowed(tables, config.tables):
                raise SchemaUnavailable("table_not_allowed")
            address = await resolve_address(config)
            conn = await psycopg.AsyncConnection.connect(
                host=config.host,
                hostaddr=address,
                port=config.port,
                dbname=config.database,
                user=config.username,
                password=password,
                sslmode=config.sslmode,
                sslrootcert=sslrootcert or "/dev/null",
                # ENOTDIR is treated as an absent certificate by libpq; /dev/null
                # itself is an existing invalid PEM file and would break TLS.
                sslcert="/dev/null/client.crt",
                sslkey="/dev/null/client.key",
                ssl_min_protocol_version="TLSv1.2",
                passfile="/dev/null",
                gssencmode="disable",
                # Without TLS an on-path server could ask for the password in
                # the clear; refuse that method so it can only be challenged.
                require_auth="!password" if config.sslmode == "disable" else None,
                connect_timeout=3,
                application_name="aidetector-schema",
                options="-c search_path=pg_catalog -c default_transaction_read_only=on "
                "-c statement_timeout=1500 -c lock_timeout=500 "
                "-c idle_in_transaction_session_timeout=3000",
                row_factory=dict_row,
            )
            try:
                async with conn:
                    await conn.execute("SET TRANSACTION READ ONLY")
                    cursor = await conn.execute(PRIVILEGES)
                    row = await cursor.fetchone()
                    privileged = not row or row["allowed"] is not True
                    expanded_tables: list[TableRef] = []
                    for table in tables:
                        if table.table_name != "*":
                            expanded_tables.append(table)
                            continue
                        cursor = await conn.execute(TABLES, (table.schema_name,))
                        rows = await cursor.fetchall()
                        if not rows:
                            raise SchemaUnavailable("table_unavailable")
                        if len(rows) > MAX_TABLES:
                            raise SchemaUnavailable("metadata_limit")
                        expanded_tables.extend(
                            TableRef(schema_name=table.schema_name, table_name=item["table_name"])
                            for item in rows
                        )
                    # The upload contract holds at most MAX_TABLES; two wildcard
                    # schemas could each fit and together exceed it.
                    if len(expanded_tables) > MAX_TABLES:
                        raise SchemaUnavailable("metadata_limit")
                    result: dict = {
                        "tables": [],
                        "warnings": ["privileged_account"] if privileged else [],
                    }
                    for table in expanded_tables:
                        params = (table.schema_name, table.table_name)
                        cursor = await conn.execute(COLUMNS, params)
                        columns = await cursor.fetchall()
                        if not columns:
                            raise SchemaUnavailable("table_unavailable")
                        cursor = await conn.execute(CONSTRAINTS, params)
                        constraints = await cursor.fetchall()
                        if len(columns) > MAX_COLUMNS or len(constraints) > MAX_CONSTRAINTS:
                            raise SchemaUnavailable("metadata_limit")
                        # Foreign targets outside the configured allowlist are not disclosed.
                        permitted = {
                            (t.schema_name, t.table_name) for t in expanded_tables
                        }
                        constraints = [
                            c
                            for c in constraints
                            if c["kind"] != "f" or (c["ref_schema"], c["ref_table"]) in permitted
                        ]
                        result["tables"].append(
                            {**table.model_dump(), "columns": columns, "constraints": constraints}
                        )
                        if len(json.dumps(result).encode()) > MAX_BYTES:
                            raise SchemaUnavailable("metadata_limit")
                    return result
            finally:
                await conn.close()
    except SchemaUnavailable:
        raise
    except Exception:
        raise SchemaUnavailable() from None
