# Scan methodology

The scanner records a test case as `passed`, `finding`, `blocked`, `unsupported`,
`error`, `budget_exhausted`, or `inconclusive`. A case reserves its control,
attack, verification, and cleanup requests before it starts. Cleanup requests
use their reserved capacity even when endpoint fairness or the main probe budget
is exhausted.

## Independent confirmation

Confirmation samples are opt-in (`confirm`). High-risk query inputs receive a
valid control, two independent arithmetic probes, a repeat, and a literal
negative control. A result is verified only when both computed values are
correct, repeatable, and not reflected as the input. Existing CLI confirmers
replay the exact method, query, headers, and companion parameters when a lead
has them; body/header/cookie leads are skipped by URL-only tools instead of
being converted to a GET query.

## Business state

An OpenAPI document can declare explicit workflows under
`x-aidetector-workflows`. A workflow names setup, transitions, an observation
JSON pointer, the expected normal state, cleanup, and bounded scenarios for
skipping, replaying, or switching identities. Each scenario runs against a
fresh fixture after a successful normal control. Invalid or out-of-scope
workflows are reported as unsupported, never inferred from route names.

## Input shapes

The request-shape layer preserves nested JSON pointers, bounded arrays, `oneOf`,
`anyOf`, and `allOf` branches. It validates generated controls before probing and
supports JSON, URL-encoded forms, multipart forms, plain text, headers, cookies,
query parameters, and path parameters. Reserved transport headers and unresolved
remote references are excluded.

## Reproducibility and effectiveness

Each run archives a manifest containing the seed, spec/options/payload digests,
operation list, methodology version, complete-case outcomes, valid-request
coverage, and cleanup success. The optional API `seed` lets a rerun reuse the
payload-selection seed. AI cache reuse keeps the stable finding fingerprint for
human triage but adds an evidence-sensitive review key, so changed evidence,
model settings, or prompt/runtime bytes trigger a fresh review.

The held-out paired benchmark in `tests/methodology_benchmark.py` reports
precision, recall, valid-request coverage, inconclusive rate, and cleanup
success. Its generated snapshot is `docs/methodology-benchmark.json`; these are
synthetic regression measurements, not estimates of production prevalence.
