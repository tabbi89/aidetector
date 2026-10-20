# Pilot metrics

`services/api/app/scans/pilot_metrics.py` derives the five measurements the
pilot needs from rows the scanner already keeps. It is read-only and value-free:
it never reads an evidence body, finding title, target URL or credential
material, so its output can be shared with a pilot team.

## Run

```bash
docker compose exec -T api python -m benchmarks.pilot_metrics --tenant acme
docker compose exec -T api python -m benchmarks.pilot_metrics --tenant acme --since 2026-10-01
docker compose exec -T api python -m benchmarks.pilot_metrics --tenant acme --format csv > acme.csv
```

`--tenant` is required: the report never aggregates across workspaces. JSON
includes the tenant aggregate plus one row per scan; CSV is one row per scan.
Use `--since` to bound the pilot window by scan creation date.

## Definitions

- **Setup complete** — a spec was uploaded, at least two non-anonymous
  identities exist, and a run started. `setup_seconds` is scan creation → first
  run. Scans created before the timestamp columns existed report
  `setup_complete: false`; that is honest, not a zero.
- **Time to first useful finding** — scan creation → the first finding at or
  above medium severity with `verified` confidence. If a re-run replaced the
  live findings, the first run whose archived snapshot contained one is used,
  and its finish is the conservative bound.
- **False-positive rate** — dismissed ÷ (dismissed + confirmed) over the scan's
  remembered triage. A verified-only rate is reported separately.
- **Exercised endpoint coverage** — the latest run's enabled operations with at
  least one request, as a percentage. The all-operations percentage is reported
  beside it.
- **Fixes verified** — findings resolved between the last two completed runs,
  excluding dismissed findings and rows the newer run could not have re-tested
  (a dropped pass, a narrowed check scope, or a spent tool/request budget). It
  uses the same rules as `GET /scans/{id}/diff`.

## Reading it

Medians are used for timing and coverage so one abandoned scan does not move
the pilot's headline. Per-scan rows are kept beside the aggregate so a team can
be reviewed individually. A `null` rate means there was nothing to divide by
(no triage, no coverage rows), not a zero.

The pilot kit itself — consent, staging scope, onboarding and the weekly review
— lives with the pilot process, not in this module.
