# Use it as a CI gate

```bash
runpentests run "$SCAN_ID" --authorized \
    --fail-on high --verified-only --new-only
```

Inside a repository with an `runpentests.yml` that sets `fail_on:`, the step is just:

```bash
runpentests --authorized
```

`--authorized` is required with no terminal: the CI job is the one place the person who
set it up answers the authorization gate for every run. It is a flag, never a file key.

`--output` chooses how the gate reports: `table` (the default), `json`,
`github` (one workflow command per finding, so GitHub annotates the job), or
`junit` (an XML report CI systems parse). `--json` is the older spelling of
`--output json`; giving both is fine only when they agree.

```bash
# Annotate the GitHub Actions run with each finding
runpentests run "$SCAN_ID" --authorized --fail-on high --output github

# Publish the gate as a JUnit test report
runpentests wait "$SCAN_ID" --fail-on high --output junit > runpentests.xml
```

The scan runs on the CI machine itself, so the job needs Docker and the runner image, and
the target must be reachable from it. To gate again later without re-running, use
`wait ID --fail-on high`.

| exit | meaning |
| --- | --- |
| `0` | ran, and nothing at or above `--fail-on` |
| `1` | findings reached `--fail-on` |
| `2` | usage, config or auth error, or the server refused the request |
| `3` | the scan failed or was cancelled, or the server was unreachable |
| `4` | waiting timed out (the AI analysis, or a `wait`, keeps going on the server) |

- `--verified-only` counts only findings whose evidence demonstrates the weakness, not leads.
- `--new-only` judges only what is new since the previous run, so a pipeline fails on
  regressions rather than known debt. A first run has nothing to compare with, so
  everything counts.
- A finding a person already **dismissed** never fails the gate — that is what triage is for.
  Dismiss a false positive with `runpentests findings dismiss SCAN ID`; it stays dismissed on
  later runs and never fails the gate.
- Progress goes to **stderr**; stdout stays clean for `--json`, `--output github`
  and `--output junit`.
- Ctrl-C while waiting asks the server to cancel the run instead of leaving it going.

CI needs no saved login: set `RUNPENTESTS_SERVER` and `RUNPENTESTS_API_KEY` (a workspace API
token) as secrets, and each identity's `secret_env` variable.

Upload SARIF to GitHub code scanning with `report --format sarif` — only verified
evidence maps to the `error` level.
