# Scan detail improvements — 2026-10-22

The scan workbench now distinguishes plan access from deployment availability.
Premium uses the existing violet diamond; included local-run features use a
neutral label. Plan failures stay unconfirmed and can be retried, with a shared
answer updating mounted run, question, schedule and export controls together.

Per the current product decision, web/server execution and recurring server
schedules require Premium. Free workspaces retain scan configuration, results,
standard exports and local CLI execution at all levels. The API enforces the
execution lane before admission/queueing. Scheduled dispatch pauses after a
downgrade; stopping a standing schedule remains available. No detection pass,
write consent, AI consent, evidence grade or fingerprint was changed.

Findings now prioritize search, severity and verified evidence. A shared export
menu replaces five separate buttons. Secondary filters and the badge legend are
disclosed on demand, with active filters visible on the trigger. Filter URLs
restore on reload/history; search preserves IME composition and clear focus.
Ask your scan starts collapsed, preserving any stored disclosure preference.

Request-log details put redacted bodies before headers. Headers and payload
structure remain available in native disclosures. Metadata sits outside body
code; panes size independently, code remains keyboard-scrollable, and transport
errors, omitted bodies and truncated responses remain explicit. Mobile details
retain the identity and check even when summary metadata is hidden.

Verification:

- Full browser suite: **86 passed**. Final affected workflows after the last
  layout/loading refinements: **16 passed**. Includes light/dark, 390px/1440px,
  keyboard, exports, URL restoration, composition, plan errors/recovery, Free
  execution restrictions, and request omission/error/truncation states.
- Focused API policy, scan, schedule, local runner and coverage suite:
  **184 passed**, no skipped tests.
- Full API suite: one unrelated monitoring-demo assertion remains failing in
  `tests/test_examples.py::test_example_monitor_shows_anomalies_and_bot_traffic`
  (`change` is `0.992`, expected greater than `1`). No monitoring code was changed
  by this work. Distribution tests require the `/repo/services/api` workdir.
- TypeScript, ESLint, Next production builds, API Ruff and mypy passed.
- DESIGN.md lint: zero errors/warnings. Strict Premium audit: zero findings;
  see `scan-plan-premium-audit-2026-10-22.json`.
- Browser screenshots inspected for findings, plan options and request details.
  Generated previews live in `apps/web/test-results/` after the relevant tests.

The linked localhost page requires authentication in a fresh browser. Browser
validation used the repository's isolated API fixtures; no live scan was started.
The mounted web/API sources reload locally; the local beat scheduler was restarted
to load its updated entitlement check. Existing workspace plans were not changed.
