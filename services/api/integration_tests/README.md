# Service-backed tests

The normal `pytest` command collects `tests/`: target traffic is in process,
external I/O is blocked, and Celery runs eagerly. This directory deliberately
has a different fixture tree. Run it explicitly with PostgreSQL and Redis:

```sh
# From the repository root; use your disposable local services' ports.
export TEST_DATABASE_URL=postgresql+psycopg://aidetector:aidetector@localhost:5433/aidetector_test
export TEST_REDIS_URL=redis://localhost:6379/15
make test-integration
```

Both URLs are required; missing services fail the suite. The database URL goes
through the same safety validator as ordinary tests, then uses a separate
`<name>_worker_test` database. Alembic builds its schema. Each invocation uses a
random Redis key prefix and queue; teardown removes only its own keys and scan
rows, terminates its worker, and closes connections. It never flushes Redis.
The empty test database remains available for subsequent runs.

The worker is a real separate process with two worker threads, a real broker,
JSON messages, task result storage, and independent database sessions. The
scanner targets an in-process ASGI app in that worker; AI providers are fakes
and adjunct settings reset to defaults. These tests cover dispatch boundaries,
option serialization, persistent results, concurrent duplicate delivery, and
cancellation observed from another database session. They do not validate
external scanners, production prefork/crash recovery, or end-to-end HTTP target
networking. The row claim prevents overlapping and completed duplicates; it is
not a generation token for a stale message arriving after a later requeue.

CI runs this suite after ordinary tests. Worker logs are written under pytest's
temporary directory for debugging.
