# How a run works: the traffic leaves from this machine

Every scan the CLI starts runs **here**: the engine runs in a throwaway container on this
machine and every request to the target leaves from it, so a scan reaches an API only you
can see (an internal host, a service behind a VPN, `localhost`) as easily as a public one.
The service keeps the record and does the thinking: the results, the full request log and
the methodology manifest go to it, it runs any AI analysis you asked for (`--ai`:
adjudication and the security design review) before the run completes, and it renders the
reports — graded, fingerprinted, diffable and triaged like any other run.

```bash
make runner-image                                   # once: build the runner image
# and on the server: LOCAL_RUNNER_ENABLED=true (off by default; the claim 404s otherwise)

export RUNPENTESTS_SECRET_ALICE=...  RUNPENTESTS_SECRET_ADMIN=...   # or --secrets-file / a prompt
runpentests run "$ID" --authorized --fail-on high --verified-only
```

With `--ai`, the CLI waits after the upload while the service adjudicates the findings
("results uploaded; the service is running the AI analysis"); Ctrl-C stops waiting, the
analysis carries on, and `runpentests wait ID` picks it up again.

## The heavy tools (ZAP, Kali)

`--zap` and `--kali` (and `--level deep`) run those tools too, still from this machine:
the CLI starts each as its own container on the Docker network you pass, and the runner
reaches it there by name. Because the runner finds them by name, **a shared network is
required** — pass `--docker-network` (the same one that reaches the target). Build the
Kali image once with `make kali-image`; the ZAP image is pulled on first use. Each tool
gets a fresh per-run API key, and the CLI removes both containers when the run ends.
Lead confirmation (sqlmap/dalfox/commix/tplmap) and the testssl audit still run only on
the server.

How it works: the CLI **claims** the run from the server — which answers the authorization
gate, the target guard and the premium check, and issues the request budget and a per-run
token — then starts the engine in a throwaway container here. The container uploads its
findings, authenticated by that token alone.

- **Secrets stay local.** Each identity's secret is found on this machine, in order: a
  `--secrets-file` (JSON `{name: secret}`, must be mode `0600`), a `secret_env` value from
  `runpentests.yml`, `RUNPENTESTS_SECRET_<NAME>` (and `RUNPENTESTS_REFRESH_SECRET_<NAME>`),
  then a hidden prompt. Secrets are keyed by credential **name**, so two identities with
  the same role keep distinct secrets. A role key (`{role: secret}`, or
  `RUNPENTESTS_SECRET_<ROLE>`) is accepted only when that role is unique; a shared role must
  be keyed by name, and using a role key for it is a usage error naming the identities.
  Secrets go to the container on **stdin** — never argv, never its environment, never the
  server. An identity with no secret is dropped from the run with a named reason; the rest
  still run.
- **The container holds no API key** — only the per-run token, which is scoped to this one
  run and dies when it ends.
- **The container is locked down:** read-only filesystem, non-root, all capabilities
  dropped, no-new-privileges, 1 GB memory and a process limit, and no Docker socket.
- **The server's budget is the budget.** The runner cannot raise the request cap or rate,
  and the server refuses an upload that reports more requests than it issued.
- **Cloud metadata is always refused** (including IPv6 forms that embed an IPv4 address);
  private and internal hosts are allowed — that is the point.
- **Ctrl-C** stops the container gracefully and the run ends `cancelled`. If the container
  dies, the CLI closes the run, so the scan is never left locked.
- A loopback server or target (`localhost`, `127.0.0.1`) is rewritten to
  `host.docker.internal`, since `localhost` inside a container is the container. Override
  with `--runner-server`, and join a Docker network with `--docker-network`. Repeat it (or
  separate names with commas) to join several: a stack whose own network is
  `internal: true` has no route to the server, so pass that network for the target and
  one with egress for the server — `--docker-network app_internal,app_egress`. Joining
  more than one needs Docker 25 or later.

## When a run looks wrong

After the findings, the CLI prints **what limited this run** — the few lines out of the
progress log that change what the findings mean, worst first:

- `✗ … answered 404, so this run never reached the API` — the routes do not exist on the
  target. The line shows the URL a request was sent to; when the target already ends with
  the spec's server path (`/api/v1`) and the route repeats it, set `target:` to the origin.
  Routes are re-derived from the spec at the start of every run, so a stale route left by
  an older server repairs itself once the server is upgraded. With no identity the line
  says so instead: some APIs answer 404 to a caller without a key, and only an identity
  tells the two apart.
- `✗ identity 'x' was rejected` — every request with that identity answered 401: its secret
  is wrong or expired, or it belongs in another header (`header:`).
- `✗ none of the requests got an answer` — the runner cannot reach the target; pass the
  target's network with `--docker-network`.
- `!` lines narrowed the run without voiding it (resource setup failed, a tool did not run,
  the budget ran out); one last line counts the checks with nothing to test in this API.

## Before the first scan: doctor and auth check

Two commands catch most of those lines before a run spends its budget:

```bash
runpentests doctor --docker-network staging_default   # server, key, Docker, images, networks — no traffic
runpentests auth check --authorized                     # is each identity's credential accepted?
```

`auth check` runs in the same runner container and network as a scan, with the same
secrets, pins and token minting, and sends a few GET requests per identity plus the same
ones anonymously — no payload, no write, no redirect followed, and no run opened. Per
identity it says **accepted** (a route that refuses anonymous callers answered 2xx),
**rejected** (every answer was 401/403), **unproven** (2xx only on routes anyone can
read: a public 200 is not proof), **inconclusive** (404s, 5xx, nothing), **missing
secret** or **grant failed**. It exits 0 when every identity is accepted, 1 when one is
not, and 3 when the target did not answer. It asks for consent like a run, and a public
target needs its ownership proof first.

For a multi-tenant API, `runpentests init --tenants` writes a tenant-a admin, a tenant-a
user and a tenant-b user: BOLA is then tested across tenants and BFLA inside tenant a,
and init prints which pair tests which (and what to add when one is missing).

The runner image is built by hand, so it can fall behind the CLI. A run warns when
`runpentests-runner:latest` was built from another version — rebuild it with
`make runner-image`. An old image is why `runpentests runs trace` can show no requests.

Release binaries pull a digest-pinned runner image, with a confirmation in
a terminal; CI needs to pull the image in the release's `runner.json` first.
See [install.md](install.md).

When a source directory is mounted, its PHP, Python, Kotlin, Java, Node.js and Go
version declarations are checked against live NVD CVEs. The runner reads supported
version/build files without executing project commands and sends only runtime
CPE identifiers to NVD. Dependency packages are not inspected. Findings are leads
with file/advisory references and upgrade guidance; incomplete lookups or uncertain
versions are explicit gaps and do not resolve older runtime CVE findings.

asdf declarations support inline comments and multiple fallback versions; an
unresolved fallback or a skipped symlinked version file makes coverage incomplete.
When several Docker stages in one file match the same CVE, one finding retains
every affected stage and version, with the existing fingerprint and triage.
