# Levels and passes

The everyday choices are three words:

- `--level quick|standard|deep` — how hard to look. The server expands it: quick is the
  engine only, standard adds fuzzing (and premium checks when entitled), deep adds ZAP,
  Kali, lead confirmation and the testssl.sh TLS audit.
- `--writes` — allow tests that change target data. It is the documented spelling of
  `--mutate`, which still works; a level never implies it.
- `--ai` — the AI passes that fit the level (risk plan, verdicts, security review); it
  spends tokens. The AI passes need `DEEPSEEK_API_KEY` set on the server; without it they
  are skipped (the scan still runs).

In `aidetector.yml` the same choices are `level:` and `passes:` (pass names without the
dashes; `writes` is `mutate`):

```yaml
level: standard
passes: [ai]
```

The web **Run** button covers quick and standard plus the writes and AI switches; `deep`
(ZAP, Kali, the confirm tools) is the CLI's.

## The individual passes

The individual pass flags are advanced and mirror the server's `RunRequest`:

| flag | does |
| --- | --- |
| `--mutate` | write to the target: write oracle, mass assignment, race, seeded BOLA, body-field fuzzing (restores and cleans up after itself); `--writes` is the same |
| `--fuzz` | schema fuzzing of request inputs |
| `--premium` | premium checks (needs entitlement) |
| `--zap` | OWASP ZAP active scan — slow, far more traffic than the request budget |
| `--kali` | Kali tools (ffuf, katana, arjun, nuclei) plus a discovery re-probe — slow |
| `--confirm` | confirm injection leads with sqlmap/dalfox/commix/tplmap — slow |
| `--testssl` | testssl.sh deep TLS audit of an HTTPS target — slow (up to 5 minutes) |
| `--plan` | AI: rank endpoints by risk before the engine runs |
| `--adjudicate` | AI: review BOLA/BFLA/SSRF findings and set a verdict |
| `--security-review` | AI: security review of the scan |
| `--genai-payloads` | AI: generate extra payloads |
| `--adaptive` | AI: adaptive follow-up probing |
| `--resource-refine` | AI: refine resource id discovery |
| `--agent` | bounded whitebox agent over the `source` code (local runs only); its tools (nuclei, ffuf, sqlmap) need a Docker sandbox (`AGENT_SANDBOX_ENABLED`), so where there is none it runs nothing — `source:` alone already adds file:line |
| `--ai` | the AI passes that fit the level |

Every AI pass spends tokens. `--checks a,b` scopes the engine to some checks and
`--rps N` slows the request rate. **Every pass is off unless you ask for it** —
`--mutate`/`--writes` writes to the target, `--zap/--kali/--confirm` fire far more traffic
than the budget allows, and `--testssl` can take five minutes.

`aidetector status` lists which passes this server can run and why the others cannot. A
pass the server cannot run is recorded on the run as not run, never as a clean result.
