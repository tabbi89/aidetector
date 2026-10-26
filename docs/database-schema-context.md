# Database schema context

Schema context is **local-only**. The server never connects to a target database and holds no database credentials. A project's `schema:` block in `runpentests.yml` is read by the `runpentests` CLI (every CLI run is local) on the CLI machine, which uploads a structure-only snapshot with its results. The scan then reuses the newest available snapshot for its server-side AI passes.

Migration `0052` adds `scan_runs.schema_context` and drops `database_connections` together with the encrypted passwords it held (the downgrade recreates an empty table; the secrets are gone by design). Run `alembic upgrade head` in `services/api`. There are no `DB_SCHEMA_*` settings and nothing to configure on the server or worker for schema access.

## `runpentests.yml`

```yaml
schema:
  host: db.example.com
  port: 5432                # default
  database: appdb
  username: scanner
  password_env: DB_PASSWORD # read on this machine, never written to the server
  sslmode: verify-full      # or disable
  sslrootcert: ca.pem       # required for verify-full, relative to this file
  tables: [public.users, audit.*]
```

| Field | Meaning |
| --- | --- |
| `host` | Required. Hostname or address. Lowercased, trailing dot stripped. A loopback host is rewritten to `host.docker.internal` for the runner container. |
| `port` | Defaults to `5432`; must be 1-65535. |
| `database` | Required PostgreSQL identifier. |
| `username` | Required PostgreSQL identifier. |
| `password_env` | Required. Name of the environment variable holding the password. A key such as `password:` in the file is refused, like every other secret. |
| `sslmode` | `verify-full` (default) or `disable`. |
| `sslrootcert` | Required when `sslmode` is `verify-full`. Path to a PEM CA file, absolute or relative to the project file. It is mounted read-only into the runner. |
| `tables` | 1-20 entries, each `schema.table` or `schema.*`. Duplicates are refused, `pg_*` and `information_schema` are refused, and a schema cannot be listed both as `schema.*` and as a named table. |

A server run does not read the block: it reuses the scan's latest snapshot, if any, and the CLI prints a note saying so. The file's `schema` block is reported to the server as a managed setting, like the other project-file controls.

### A database on this machine

Use `sslmode: disable` for a local database. The CLI rewrites `localhost` to `host.docker.internal` so the runner container can reach it, and `verify-full` then fails hostname verification: the certificate names `localhost`, not `host.docker.internal`. Remote databases can use `verify-full` with a CA. `verify-full` without a CA is rejected both by the project file and by the adapter (`tls_ca_unconfigured`).

## What happens on a local run

1. The run is claimed from the server first; only then does the CLI collect the `schema:` block.
2. The password is read from the variable named by `password_env`. If that is empty and stdin is a terminal, the CLI prompts for it with hidden input. If it is still empty, the CLI warns and sends the block without a password, so the run records `password_missing` rather than silently looking unconfigured.
3. A loopback host becomes `host.docker.internal`; the container gets `--add-host host.docker.internal:host-gateway`.
4. A configured CA is checked to be a regular file, resolved against the project directory, mounted read-only at `/run/aidetector/schema-ca.pem`, and named in the block. The CA is not a secret.
5. The claim, the identity secrets and the schema block are written as JSON to the runner's stdin. Nothing is passed in argv or the environment; the password never leaves the machine.
6. The runner registers the password with its redactor, then reads the schema before scanning, using the bounded adapter described below. The `schema` block is optional: without it no read happens and nothing is uploaded.
7. The runner posts what the read did, then scans. A schema failure never fails or delays the run.

Events use fixed stage names:

| Event | When |
| --- | --- |
| `schema_context` | The read succeeded, naming the number of tables read on this machine. |
| `schema_context_unavailable` | The read did not succeed, naming the reason; the run continues without it. |
| `schema_privileged_account` | The read succeeded but the account has more than metadata privileges. |

Every failure is a fixed reason code, not an exception message:

| Reason | Meaning |
| --- | --- |
| `password_missing` | The block had no password and none was supplied. |
| `invalid_config` | The block failed the strict connection contract (bad host, sslmode, tables, or extra keys). |
| `destination_not_allowed` | The host is a known cloud-metadata name, or resolves to a metadata, link-local, multicast or unspecified address, including IPv6 forms embedding one. |
| `tls_ca_unconfigured` | `verify-full` was requested without a CA. |
| `ambient_service_forbidden` | The runner environment sets `PGSERVICE` or `PGSERVICEFILE`. |
| `table_unavailable` | A configured table, or every table of a wildcard schema, does not exist or has no visible columns. |
| `metadata_limit` | The read exceeded 50 tables in a wildcard, 200 columns or 100 constraints on a table, or 64 KiB of output. |
| `unavailable` | Any other connect or query failure; the adapter maps it to this code and never returns a driver message. |
| `invalid_upload` | Server-side only: the uploaded snapshot failed validation. Recorded as an attempt; the run's findings are still accepted. |

The results bundle carries the attempt (`status`, `reason`, `captured_at`, `tables`, `warnings`) only when the project configured a `schema` block. On receipt the server re-validates it with `accept_upload`: structure only, no extra keys, no rows or values, no password, within the size bound. A snapshot it cannot accept is stored as an `invalid_upload` attempt instead of refusing the run.

## How a scan reuses snapshots

Snapshots are stored on `ScanRun.schema_context` as `{status, reason, captured_at, tables, warnings}`. `app.db_schema.snapshots` finds:

- `latest_attempt` — the newest run that tried to read the schema, successful or not.
- `latest_snapshot` — the newest run whose attempt was available, by run number. A later failed read leaves the earlier snapshot in use.

When a server run opens with `adaptive`, `resource_refine` or `security_review`, it calls `_attach_schema_snapshot` once and sets `ctx.schema_context` to that snapshot. The run posts `schema_context` naming the source run and table count, or `schema_context_unavailable` telling the operator to add a `schema:` block and run `aidetector` from the CLI. Runs without those options never look.

All consumers now share that one value:

- Adaptive validation uses it as its schema context.
- AI resource refinement passes it to provisioning.
- The security design review sends it as the database structure.

Previously each of these opened its own database connection, and adaptive validation and resource refinement read only the first configured table. A snapshot now covers every configured table, including expanded wildcards, and is read once per run with no server-side socket.

## API

All routes are under `/scans/{scan_id}/schema-context`, authenticated and scoped to the scan's tenant. The old `/scans/{id}/database-connection` routes are gone, along with the connection test task.

`GET /scans/{scan_id}/schema-context` is read-only and returns:

```json
{
  "latest": {"run_number": 4, "status": "unavailable", "reason": "table_unavailable", "captured_at": "..."},
  "snapshot": {
    "run_number": 3,
    "captured_at": "...",
    "warnings": [],
    "tables": [{"schema_name": "public", "table_name": "widgets", "column_count": 6, "constraint_count": 3}]
  }
}
```

`latest` is the newest attempt, whatever its outcome; `snapshot` is the newest available one the AI passes will use. Both are `null` when the scan has no attempts. Responses never contain the password, host, database name, DSN or driver errors.

`DELETE /scans/{scan_id}/schema-context` requires a mutation role, refuses with 409 while the scan is queued or running, clears every stored attempt on the scan, records the `schema_context.forgotten` audit entry and returns `{"removed": n}`.

The web panel is read-only: it shows the newest snapshot with table and key counts, the privileged-account warning, the reason for a newer failed read, and a **Forget snapshot** action. There is no connection form and no credential test.

## Recommended database identity

Use a dedicated login for this read. No table or column `SELECT` is needed: the adapter reads `pg_catalog` with fixed queries only. It returns table and column names, types, nullability, character length, primary/unique keys and allowlisted foreign-key relationships. It never selects application rows and returns no defaults, comments, enum literals or check expressions. Foreign-key targets outside the configured tables are omitted.

Each read evaluates effective privileges, including PUBLIC grants. It reports a `privileged_account` warning for a role that is superuser, can create roles or databases, replicate or bypass RLS; has any role membership; owns objects; holds database CREATE/TEMP, schema CREATE, any application table/column/sequence privilege, or EXECUTE on any application routine. The warning does not refuse the read; only the fixed read-only catalog queries run regardless. A dedicated metadata-only account still limits what a compromised credential could reach.

PostgreSQL commonly grants TEMP on databases and EXECUTE on routines to PUBLIC, and has no per-role deny that overrides a PUBLIC grant, so an ordinary "read-only" application account usually triggers the warning. Provision a metadata-only environment or identity if that matters to you. The scanner does not alter target grants or schema.

The connection is pinned to one vetted address with no libpq DNS fallback, does not load ambient client certificates or password files, requires TLS 1.2 or newer, and runs its statements in a read-only transaction with `search_path=pg_catalog`. Private and loopback addresses are allowed because reading a development database on the CLI machine is the point; cloud-metadata addresses never are.

## Limits

One local run reads at most 20 configured tables, a wildcard expands to at most 50 tables, and a table yields at most 200 columns and 100 key constraints. The whole result is capped at 64 KiB; the server re-checks a snapshot at the same size. The read has a 10-second deadline including DNS and connection setup, a 3-second connection timeout, a 1.5-second statement timeout, a 0.5-second lock timeout and a 3-second idle-in-transaction timeout. DNS runs in a terminable isolated interpreter. Everything fits in one bounded call per run; there is no tool-call loop, model-selected SQL or arbitrary query path.

## AI security design review

Enable the review in run options (`security_review: true`). A local run may now request it: the pass sends no target traffic, so the server runs it after the upload in `review_local_run`, where the AI budget and ledger live. The review is queued only after the completed run's snapshot is stored, so it sees the structure that run just read, or the newest earlier snapshot. The run shows `status: running` until the worker settles it to `completed` or `unavailable`. Events from that worker are written only while the run is still the scan's newest.

The review sends the model a bounded structural view of the OpenAPI/Swagger spec plus the snapshot's tables. Without a snapshot it reviews the spec alone and records `schema_status: not_provided`; with one it records `available`. Either way it never changes findings, finding counts, triage, SARIF or finding diffs.

The **Security improvements** section beside Findings displays advisory design changes, their observed structure, security risk, implementation suggestion, validation step, assumptions and exact schema references. The review is stored per run in `ScanRun.security_review` and returned by `GET /scans/{id}/runs`.

The reusable prompt is `services/api/ai_runtime/security_review_prompt.md`. It covers ownership and tenant isolation, authentication, sensitive fields, mass assignment, constraint mismatches and resource limits. Input excludes examples, defaults, enum values, prose, external URLs, credentials and application rows. Names and output text are additionally redacted, and internal schema references are preserved without ever being fetched. Input is capped at 96 KB and depth 32; oversized input skips the review rather than reviewing a truncated schema. Output is capped at eight suggestions with validated references and bounded text.

This is one direct DeepSeek call using the existing executor configuration and AI timeout, with no Claude SDK tools and no target requests. Token use is recorded under `security_review`, including completed calls whose output fails validation. Malformed output, missing AI configuration and timeouts leave the core scan intact.
