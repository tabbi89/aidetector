# Effectiveness benchmark against real vulnerable APIs

`pilot_metrics.py` reports on real scans a workspace has already run.
`effectiveness.py` answers a different question: **how well does the engine do
against an API it was not built against?**

Every other quality number in the repo comes from paired synthetic targets
(`tests/vulnapp.py` / `tests/safeapp.py`, `tests/methodology_benchmark.py`).
Those are written alongside the checks, so a 100% synthetic score says the
checks still do what their authors intended — not how they fare on a real API.
This harness scans a known-vulnerable third-party API and scores the result
against a hand-curated list of that API's documented weaknesses.

It reports, overall and per OWASP category:

- **recall** — of the documented weaknesses, how many the engine found;
- **manifest-precision** — of the findings, how many line up with the manifest.
  The manifest is necessarily incomplete (a real API has weaknesses nobody wrote
  down), so a finding that matches nothing is reported as **unexpected** — a lead
  to review, *not* a confirmed false positive. Read this number as a floor.

## Ground-truth manifests

`targets/vampi.json` and `targets/crapi.json` list each documented weakness as
`{owasp_id, route, method?, check?, note}`, using the OWASP 2023 ids the engine
emits. They are curated from each project's public documentation and are meant
to be refined against the spec of the instance you actually run — a route
template that differs by a path segment will miss, so align the manifest with
the target's served spec first.

## Running it

You need the aidetector stack up (`make up-all`) and the target reachable from
the API/worker. The harness drives the public HTTP API exactly as the CLI and
web do, so it exercises the whole pipeline.

```bash
# 1. Stand up a target. For example, VAmPI in vulnerable mode:
docker run -d -p 5002:5000 -e vulnerable=1 erev0s/vampi:latest
#    (crAPI: follow https://github.com/OWASP/crAPI deploy docs.)

# 2. Point the benchmark at both, with the target's OpenAPI spec.
docker compose exec -T api python -m benchmarks.effectiveness \
  --api-url http://localhost:8000 \
  --target-url http://host.docker.internal:5002 \
  --spec /path/to/vampi-openapi.json \
  --manifest benchmarks/targets/vampi.json \
  --format table
```

Scanning a public target still requires the normal authorization and
domain-ownership gates; a locally hosted target that resolves to a private
address is exempt (see `app/scans/domains.py`). The run uses `--level deep` and
`mutate` by default so the write-side oracles (BOLA-write, BFLA-write, mass
assignment) are exercised — only run it against a target you own or control.

## What to do with the result

The point is the **missed** list and the per-category recall: they say which
check to improve next, with a concrete endpoint to reproduce against. Re-run
after a change to see recall move. The `unexpected` list is the precision review
queue — each entry is a finding the manifest did not predict, to confirm or to
turn into a precision fix (or a `tests/safeapp.py` case).

The scoring half (`score`, `load_manifest`, `Finding`, `ExpectedVuln`) is pure
and unit-tested in `tests/test_effectiveness_benchmark.py`; the live driver
needs a running stack and target and is not part of the offline suite.
