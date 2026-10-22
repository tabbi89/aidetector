"""Strict, value-free contracts for the PostgreSQL metadata adapter.

Two halves. ``ConnectionConfig``/``ConnectionInput`` describe a database the
*local runner* reads on the CLI machine (from ``runpentests.yml``); the server
never sees the password and never opens a database socket. ``SchemaUpload`` is
what that runner sends back with its results: structure only, re-validated
here because the server trusts the runner to report what it read, not to
decide what the server stores.
"""

from __future__ import annotations

import json
from typing import Annotated, Any, Literal

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    SecretStr,
    ValidationError,
    field_validator,
    model_validator,
)

Identifier = Annotated[str, Field(pattern=r"^[A-Za-z_][A-Za-z0-9_$-]{0,62}$")]
TableIdentifier = Annotated[str, Field(pattern=r"^(?:\*|[A-Za-z_][A-Za-z0-9_$-]{0,62})$")]


class TableRef(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    schema_name: Identifier
    table_name: TableIdentifier

    @field_validator("schema_name")
    @classmethod
    def application_schema(cls, value: str) -> str:
        if value.startswith("pg_") or value == "information_schema":
            raise ValueError("application schemas only")
        return value


class ConnectionConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")
    label: str = Field(min_length=1, max_length=120)
    host: str = Field(min_length=1, max_length=253, pattern=r"^[A-Za-z0-9.:-]+$")
    port: int = Field(default=5432, ge=1, le=65535, strict=True)
    database: Identifier
    username: Identifier
    sslmode: Literal["verify-full", "disable"] = "verify-full"
    tables: list[TableRef] = Field(min_length=1, max_length=20)

    @field_validator("host")
    @classmethod
    def normalize_host(cls, value: str) -> str:
        return value.lower().rstrip(".")

    @field_validator("tables")
    @classmethod
    def distinct_tables(cls, value: list[TableRef]) -> list[TableRef]:
        if len(set(value)) != len(value):
            raise ValueError("duplicate tables")
        wildcard_schemas = {table.schema_name for table in value if table.table_name == "*"}
        if any(
            table.schema_name in wildcard_schemas and table.table_name != "*"
            for table in value
        ):
            raise ValueError("schema wildcard cannot be combined with named tables")
        return value


class ConnectionInput(ConnectionConfig):
    password: SecretStr = Field(min_length=1, max_length=1024)


class LocalConnection(ConnectionInput):
    """The ``schema`` block the CLI hands the local runner on stdin.

    ``sslrootcert`` is a path *inside* the runner container (the CLI mounts the
    project's CA file read-only); ``label`` is fixed because the file names
    the connection, not the user.
    """

    label: str = Field(default="runpentests.yml", min_length=1, max_length=120)
    sslrootcert: str | None = Field(default=None, max_length=255, pattern=r"^/[\w./-]+$")


#: The adapter's output bound, re-checked on upload.
MAX_SNAPSHOT_BYTES = 64 * 1024

# Catalog names can be anything PostgreSQL accepts, so the upload is bounded by
# length and printability rather than by the identifier rule a config uses.
CatalogName = Annotated[str, Field(min_length=1, max_length=63, pattern=r"^[^\x00-\x1f\x7f]+$")]
ReasonCode = Annotated[str, Field(pattern=r"^[a-z_]{1,60}$")]


class ColumnMeta(BaseModel):
    model_config = ConfigDict(extra="forbid")
    name: CatalogName
    type_name: CatalogName
    nullable: bool
    max_length: int | None = Field(default=None, ge=0, le=10_485_760)


class KeyMeta(BaseModel):
    model_config = ConfigDict(extra="forbid")
    kind: Literal["p", "u", "f"]
    columns: list[CatalogName] = Field(max_length=32)
    ref_schema: CatalogName | None = None
    ref_table: CatalogName | None = None
    ref_columns: list[CatalogName] = Field(default_factory=list, max_length=32)


class TableMeta(BaseModel):
    model_config = ConfigDict(extra="forbid")
    schema_name: CatalogName
    table_name: CatalogName
    columns: list[ColumnMeta] = Field(min_length=1, max_length=200)
    constraints: list[KeyMeta] = Field(default_factory=list, max_length=100)


class SchemaUpload(BaseModel):
    """One local run's attempt to read the schema, as uploaded with its results."""

    model_config = ConfigDict(extra="forbid")
    status: Literal["available", "unavailable"]
    reason: ReasonCode | None = None
    tables: list[TableMeta] = Field(default_factory=list, max_length=50)
    warnings: list[Literal["privileged_account"]] = Field(default_factory=list, max_length=4)

    @model_validator(mode="after")
    def consistent(self) -> SchemaUpload:
        if self.status == "available" and (not self.tables or self.reason):
            raise ValueError("an available snapshot has tables and no reason")
        if self.status == "unavailable" and (self.tables or not self.reason):
            raise ValueError("an unavailable attempt has a reason and no tables")
        return self


def accept_upload(raw: Any, captured_at: str) -> dict:
    """The stored form of an uploaded attempt — never raises.

    A snapshot the server cannot accept is recorded as an ``invalid_upload``
    attempt instead of failing the upload: schema context is an enhancement,
    and a malformed one must not cost the run its findings.
    """
    try:
        upload = SchemaUpload.model_validate(raw)
        stored = {**upload.model_dump(), "captured_at": captured_at}
        if len(json.dumps(stored).encode()) > MAX_SNAPSHOT_BYTES + 1024:
            raise ValueError("snapshot over the size bound")
        return stored
    except (ValidationError, ValueError, TypeError):
        return {
            "status": "unavailable",
            "reason": "invalid_upload",
            "tables": [],
            "warnings": [],
            "captured_at": captured_at,
        }


class SchemaUnavailable(Exception):
    """Only fixed reason codes cross the worker/API boundary."""

    def __init__(self, code: str = "unavailable") -> None:
        self.code = code
        super().__init__(code)
