# Safety

runpentests is an active scanner: it sends real attack payloads to a live API. These rules
are part of the product, and no file, flag default or tool can turn them off.

- **The authorization gate stays.** `run` sends `authorized: true` only with `--authorized`
  or an interactive `y` to a prompt that names the target. With no terminal and no flag
  it refuses *before sending a single request*. There is no config option to skip it, and
  `runpentests.yml` has no `authorized:` key.
- **A public target needs proven ownership.** The workspace verifies a public host once —
  a DNS TXT record proves the name, an HTTP token served from the target proves the
  machine — before any scan reaches it, and every run proves it again live. Hosts that
  resolve only to private addresses are exempt (decided by the resolved address, never
  the name). From the terminal, a workspace admin runs:

  ```bash
  runpentests domains check SCAN              # does this target need proof? (no traffic to it)
  runpentests domains add api.example.com     # prints the TXT record and the HTTP token to publish
  runpentests domains verify api.example.com --wait 10m   # runs both proofs, says which failed
  ```

  The same records are under Workspace → Domains in the web. The CLI never edits DNS or
  uploads the token for you, and a verified domain never replaces `--authorized`.
- **Writes are opt-in.** A default scan only reads and fuzzes GET query and path
  parameters. Tests that change target data run only with `--writes` (`passes: [writes]`),
  and they restore or delete what they create. A level never turns writes on.
- **Secrets are never flags.** There is no `--key` or `--secret` — they would land in
  shell history and `ps`. Use the hidden prompt, `--key-stdin` / `--secret-stdin`, or
  `RUNPENTESTS_API_KEY`. Nothing the CLI prints contains a key or a credential secret.
- **Secrets are never in the project file.** `runpentests.yml` names the environment
  variable (`secret_env`, `token_env`, `password_env`); a key that looks like a secret is
  refused.
- The config file is written `0600` in a `0700` directory, and refused on read if anyone
  else can open it. Reports are written `0600` too — they list weaknesses in an API.
- `http://` is refused unless the host is loopback (the key travels in a header);
  `--insecure-http` overrides it deliberately.
- Deleting asks first, and refuses to guess when there is no terminal.
- **The request budget stays.** Every scan is capped (750 engine requests by default); the
  slow tools run on their own wall-clock budget.
