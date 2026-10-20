# H1 test effectiveness baseline

Measured locally on 2026-09-05 with Python 3.13, a disposable PostgreSQL database,
and the pinned development dependencies. CI uses Python 3.12. The workflows are
wired; a hosted run is still required before calling H1 verified in CI.

Final regression validation also passed: 3 real-worker tests, 4 Chromium
workflows (11.4 seconds including the isolated UI build, using Node 20), API
ruff/mypy, frontend lint/type checking, exact contracts and the production build.

## Coverage

The complete ordinary suite passed **850 tests, zero skips** in **21.88 seconds**.
Coverage includes all of `services/api/app`, including modules not imported by
a test. It measures branches as well as executable lines.

| Measurement | Covered / total | Baseline | Initial CI floor |
| --- | --- | --- | --- |
| Lines | 5,629 / 6,241 | 90.19% | 89% |
| Branches | 1,474 / 1,894 | 77.82% | 76% |
| Combined (coverage.py display) | 7,103 / 8,135 | 87.31% | separate floors above |

The small margin accommodates platform differences without allowing a large
regression. `scripts/check_coverage.py` also rejects JUnit reports containing
skips, errors, failures or no tests. CI and `make test-coverage` require the DB,
so an unavailable database cannot create an apparently healthy baseline.
Broken report fixtures prove both floors and the skip/error gate fail.

Scope exclusions: the subprocess AI runtime, migrations, tests, web app and
external scanner binaries are outside `app/`. Coverage.py's normal exclusions
account for 56 lines; no new per-file or per-line coverage exclusions were added.
Real-worker and browser suites run separately and are not merged into this
ordinary-suite coverage percentage.

## Mutation audit

`mutmut==3.6.0` mutates four pure policy modules and selects their existing
network-free tests plus the new policy/fingerprint properties. It uses two
workers; the final local run reported 28.87 mutations/second (about 31 seconds
for the mutation phase, excluding collection/baseline setup). A fresh hosted
run may be slower; the job has a 15-minute limit.

| Module | Killed | Survived | Total |
| --- | --- | --- | --- |
| `header_policy` | 326 | 128 | 454 |
| `exposure_policy` | 106 | 26 | 132 |
| `fingerprint` | 65 | 5 | 70 |
| `spec_values` | 168 | 58 | 226 |
| **Total** | **665** | **217** | **882** |

There were **0 timed out, 0 errored, 0 untested, 0 skipped and 0 unchecked**
mutants. The raw killed/total ratio is 75.40%; it is not an adjusted quality
score. The first pass killed 594 mutants; focused assertions raised that to
665 without changing the four production policy modules or stored fingerprints.

Initial survivor triage:

- **Actual assertion gaps fixed:** CSP script/default precedence; CORS origin
  and credential severity; malformed field keys; nested-array depth; empty
  identity fallback; malformed Unicode in fingerprints.
- **Equivalent examples retained in the report:** fingerprint
  `x_fingerprint__mutmut_4` changes `\x1f` to `\x1F`; `_19` changes the codec
  spelling to `UTF-8`; `x_identity_parts__mutmut_18` changes an initial false
  sentinel to `None`. These preserve the behavior being tested. The exposure
  walk's outer `>= MAX_FIELDS` to `> MAX_FIELDS` mutant is still bounded by the
  inner guard. These are not subtracted from the denominator.
- **Import-time limitation:** the 11 `_rule` factory mutants survive because
  the rule catalogue is constructed before per-mutant execution in mutmut's
  fork model. This does not establish that corrupting the catalogue is safe.
  Module-level constants themselves are outside mutmut 3's function mutation
  scope; existing example tests still exercise catalogue behavior.
- **Remaining test debt:** `spec_values` has unpinned formatted baselines and
  malformed enum/schema variants; boolean identity canonicalization remains
  unpinned. Header survivors include issue text/observed-value changes and
  branches outside the selected assertions. Not all 217 survivors have been
  classified as equivalent; do not infer that they are harmless.

No blocking mutation-score threshold is set. The weekly Monday 04:23 UTC and
manual workflow publishes individual results, raw exit codes and the mutation
workspace for review. The report distinguishes pytest internal errors from
kills and rejects incomplete results or tool errors. Further classification and
the first hosted runtime measurement should precede a score gate or expansion
to more modules. No mutations are applied to the source checkout.

## Properties and contracts

Policy properties use 60 deterministic bounded examples; fingerprint properties
use 40, alongside the unchanged hash goldens. They check positive and negative
expectations for normalization, depth/width bounds, sensitive value rotation,
write permission, payload placement, run noise and identity-defining changes.
Settings are local to each test and do not alter unrelated Hypothesis tests.

`test_api_contract.py` uses the actual application's OpenAPI with explicit
Schemathesis status/content-type/header/schema checks. A seeded authenticated
lifecycle covers scans, credentials, findings, run history, diff, coverage,
cost, Q&A, scheduling, queueing, cancellation and events. Positive and negative
create requests and positive run requests use 12 generated examples per pass.
Raw invalid JSON bytes exercise the parser's 400/422 responses. Known-good
responses are then deliberately broken to prove missing fields, invalid enums
and nullability violations are detected.

All calls use TestClient with a dedicated database. Dispatch and AI are stubs;
direct worker/scheduler execution is forbidden, and the ordinary harness blocks
target sockets, DNS and tool processes. The contract tests do not exhaust every
route, business error or input combination. Reports, multipart upload and real
scan behavior retain their separate existing tests.

`make test-contracts` exports OpenAPI from the local application, generates
temporary types with pinned `openapi-typescript`, and compiles exact comparisons
for 17 client response types, 19 client response-to-route bindings and 10 request
shapes bound to their routes. Six deliberately mismatched
TypeScript fixtures cover optionality, nullability, missing/extra fields, enums
and request defaults. Generated files are ignored, never a stale committed source
of truth. CI passes the API job's export to the web job. Untyped dictionary
responses from the two DELETE methods are outside these compile assertions;
their existing behavioral tests remain in the ordinary suite.

Contract corrections made during this work: output schemas now require fields
the serializer always includes, `/health` declares its status object, scan
routes document existing 400 errors, and the client mirrors tenant/credential
metadata, enum types, nullable update secrets and arbitrary parameter objects.
Response JSON, scanner behavior and default-off run options are unchanged.

## Commands

Install the pinned API development requirements and run `npm ci` in `apps/web`.
From the repository root, with the usual database environment configured:

```sh
make test-coverage
make test-contracts
make test-mutation
```

Coverage artifacts are `services/api/coverage.{json,xml}` and `test-report.xml`.
Mutation artifacts are `services/api/mutation-report.json`, `mutation-results.txt`
and `mutants/`. Use `.venv/bin/mutmut show <name>` from the API
directory to inspect a survivor. Mutmut remembers prior results; remove its
generated `mutants/` workspace when a completely fresh audit is needed.
