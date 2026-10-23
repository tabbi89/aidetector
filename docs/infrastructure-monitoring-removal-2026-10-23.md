# Infrastructure monitoring removal

Infrastructure monitoring is retired. Its pages/navigation, client module,
API routes and schemas, models, telemetry collectors/connectors, explanations,
Cursor runtime, task registrations, schedules, correlation injection and
notification events have been removed. Monitoring-specific AWS configuration,
the AWS Compose overlay, optional Cursor build and unused botocore dependency
are also removed. Historical migrations remain intact.

The bundled example scan was extracted to `app/scans/examples.py`. API scanning,
scan schedules, findings/history, schema snapshots, notifications for scan/work
events and local CLI execution remain supported. API snapshots and web/CLI
contract assertions have been refreshed.

Migration `0059` drops the six retired tables, removes monitor subscriptions
from notification endpoints and dead-letters pending monitoring deliveries.
Downgrade restores empty tables; it cannot recover deleted telemetry, source
credentials or subscriptions. Delivered-event audit records remain. The delivery
worker also rejects unsupported event types before any outbound request, even
before a deployment applies this migration.

The migration was tested only on isolated test databases. Existing application
data has not been migrated or deleted. Apply the migration during deployment
and rebuild/recreate services to remove obsolete dependencies, environment
settings and AWS mounts from existing containers. The local scheduler and idle
worker were reloaded to stop dispatching/registering monitoring jobs.

Verification:

- Full remaining API suite: **2,187 passed**, no skipped tests.
- Full browser suite with retired-page/navigation coverage: **86 passed**.
- CLI formatting, vet and race tests: passed.
- Web/API contract checks and refreshed CLI snapshot: passed.
- TypeScript, ESLint, Ruff and mypy: passed.
- Next production build through Playwright: passed.
- Migration tests cover removal, notification cleanup, preserved scan data,
  rollback to empty retired tables and migration-head/ORM agreement.
- Strict frontend audit: zero findings; see the adjacent audit JSON.

Monitoring-specific test suites and roadmap documents were removed with their
feature. Older dated UI review reports remain historical evidence, not current
product requirements.
