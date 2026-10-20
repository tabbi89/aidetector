# Phase K completion work

This work continues the monitoring backend and JSON source connector already in
this checkout. Final verification includes a self-review of correctness, code
quality and security; acceptance gaps must be recorded rather than hidden.

## Implementation checklist

- [ ] Strict source contracts, encrypted credentials, audit and source health.
- [ ] Bounded AWS CloudWatch WAF collection, retry/cancellation/revocation checks.
- [ ] Pinned GitHub and existing schema-only database context through a narrow MCP boundary.
- [ ] Privacy-safe route mapping, method/cohort baselines, enumeration and sensitive metadata detectors.
- [ ] Active evidence correlation without changing finding confidence or identity.
- [ ] Daily scheduling, bounded overlap, retention, recovery, triage and in-app alerts.
- [ ] Monitoring UI and API contract tests.
- [ ] Regression, migration, browser and security checks.
- [ ] Final self-review and explicit remaining operational limitations.
