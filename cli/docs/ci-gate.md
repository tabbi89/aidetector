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
| `5` | no finding reached `--fail-on`, but an opted-in quality policy failed (below) |

Findings win: a run that is both incomplete and has a finding at `--fail-on` exits `1`,
because a finding the run did make stands whatever it missed.

## Did the scan actually test the API?

An empty findings list is only good news if the run reached the API. A run whose every
request answered 401 (a rejected key), 404 (wrong paths or ids) or nothing at all finds
nothing too — and a gate on findings alone passes it. Two opt-in policies catch that:

```bash
runpentests --authorized --fail-on high --require-complete --min-exercised 80
```

- `--require-complete` (`require_complete:`) fails the run when it did not do what it was
  asked: a check that did not finish, a requested tool that did not run, a spent request
  budget, an identity left out, a run that did not complete, or no in-scope endpoint
  answering with a 2xx. A check that had nothing to test in this API (no URL parameter
  for SSRF, say) is a note, not a failure.
- `--min-exercised N` (`min_exercised:`) fails the run when fewer than N percent of the
  enabled endpoints were **exercised** — answered at least one request with a 2xx. The
  share is printed with its parts (`8/10 (80%)`, plus how many were excluded). No
  in-scope endpoint, or a run recorded before the server kept response outcomes, is
  *unknown*, and a policy never counts unknown as covered.

Exercised measures reachability, not safety: it does not mean every check ran against
that endpoint, or that it has no weakness. Each endpoint's state is in
`runpentests coverage ID` (`--inconclusive` lists only the ones that were not exercised).

The quality verdict is in every machine format: `quality` in `--output json` (with
`status`, the `exercised` share, `incomplete` reasons and `failures`), one `::error` per
failure with `--output github`, and an `execution quality` test case with `--output junit`.
After an everyday scan or `wait`, the same summary is printed to stderr for information,
without changing the exit code unless a policy asked for it.

## Comparing against a fixed baseline

`--new-only` compares the run with the one just before it. When other runs happen in
between (a narrow local run, a teammate's scan), "the previous run" stops meaning "main
as it was accepted". Name the run to compare with instead:

```bash
runpentests --authorized --fail-on high --baseline-run 42
```

`--baseline-run N` implies `--new-only` and compares run N with the run this command
just made — never whichever run is newest by the time it asks. The baseline is printed
(and is `baseline_run` in JSON). When the two runs used different options, executors or
project files, the gate says the comparison is partial. A finding the newer run could not
have reproduced — its pass was off, its check failed or was skipped, its identity was
missing, or its endpoint was not exercised — is **not retested**, never fixed.
`runpentests diff ID --from 42 --to 57` shows the same comparison for any two runs.

To reproduce a run's payload choice, reuse its seed: `runpentests runs ID --json` shows
`manifest.seed`, and `--seed N` on `run` or the URL form sends the same one. The target's
own state, AI output and external tools can still differ between runs.

## Retesting one finding after a fix

```bash
runpentests retest SCAN 9e41 --authorized          # 9e41: a finding ID or fingerprint prefix
```

`retest` runs the check behind that finding again, with the original run's seed and its
shaping passes (`fuzz`, `premium`), then compares with that run. It exits `0` when the check
ran, the finding's endpoint answered with a 2xx, and the finding did not come back; `1`
when it is still there; `5` when the retest could not have found it — which is not a fix.

It is honest about its reach: the engine scopes by check, not by endpoint, so retesting one
BOLA finding re-runs BOLA on every in-scope endpoint, within the normal request budget. It
is a real run — consent, the ownership gate and the budget apply — and it becomes the
scan's newest run, so gate a later CI run with `--baseline-run`, not "the previous run".
Writes and AI are never repeated implicitly: if the original run had writes on, pass
`--writes` (or `--read-only` to accept that write findings come back not retested), and
`--ai` to repeat its AI passes. ZAP, Kali and the other tools are left out.

## How the gate counts

- `--verified-only` counts only findings whose evidence demonstrates the weakness, not leads.
- `--new-only` judges only what is new since the previous run, so a pipeline fails on
  regressions rather than known debt. A first run has nothing to compare with, so
  everything counts (and the gate says so). `--baseline-run N` compares with run N instead.
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
