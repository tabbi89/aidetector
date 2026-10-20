# aidetector.yml — the project file

Commit this at the root of the repository, and `aidetector` alone (or
`aidetector --authorized` in CI) does the right thing:

```yaml
target: https://staging.example.com
spec: openapi.yaml            # relative to this file
# scan: 3f0c…                 # pin a scan instead of matching by target
# source: .                   # read this code for file:line evidence
rps: 5
level: standard               # quick | standard | deep
passes: [writes, ai]          # any run pass, without the dashes
checks: [bola, bfla]
fail_on: high
verified_only: true
new_only: true
identities:
  - { name: alice, role: user,  secret_env: ALICE_TOKEN }
  - { name: admin, role: admin, auth: header, header: X-Api-Key, secret_env: ADMIN_TOKEN }
# schema:                     # database schema context, read by local runs only
#   host: db.example.com
#   port: 5432                # default
#   database: appdb
#   username: scanner
#   password_env: DB_PASSWORD # the password stays on this machine
#   sslmode: verify-full      # or disable
#   sslrootcert: ca.pem       # required for verify-full, relative to this file
#   tables: [public.users, audit.*]
```

## Every key

| key | means |
| --- | --- |
| `target` | the API's base URL |
| `spec` | the OpenAPI / Swagger file (also HAR or Postman), relative to this file |
| `scan` | pin a scan by ID instead of matching one by `target` |
| `source` | read the code in this directory; makes the run local |
| `local` | send the scan traffic from this machine (see [local runs](local-runs.md)) |
| `rps` | requests per second, 1–100; the server's ceiling still applies |
| `level` | `quick`, `standard` or `deep` (see [levels and passes](levels-and-passes.md)) |
| `passes` | extra passes, without the dashes: `writes`, `ai`, `zap`, … |
| `checks` | only run these engine checks |
| `fail_on` | the CI gate: `info`, `low`, `medium`, `high` or `critical` |
| `verified_only` | the gate counts only verified findings (needs `fail_on`) |
| `new_only` | the gate counts only findings new since the previous run (needs `fail_on`) |
| `auth` | `public`: the API takes no identity |
| `token_env` | one API key, read from this environment variable |
| `token_auth` | how that key is sent (default `bearer`) |
| `token_header` | the header, query parameter or cookie name for that key |
| `identities` | one entry per account the scan acts as |
| `schema` | database schema context, read by local runs only (keys below) |

An identity takes:

| key | means |
| --- | --- |
| `name` | unique; identities match the scan's by name |
| `role` | `user`, `admin`, `viewer`, … |
| `rank` | explicit privilege, 0 (guest) … 3 (admin); without it the server infers it from `role` |
| `tenant` | the workspace (organisation, account) the identity belongs to; with tenants set, BOLA compares identities of different tenants and BFLA compares identities within one |
| `auth` | `bearer` (default), `header`, `api_key`, `basic`, `query`, `cookie` or `none` |
| `header` | the header, query parameter or cookie name, never the value (required for `query` and `cookie`) |
| `secret_env` | the environment variable that holds the secret (required unless `auth: none`) |
| `grant` | mint a fresh token at scan start instead of sending a static one |

A grant takes:

| key | means |
| --- | --- |
| `type` | `client_credentials`, `password` or `cookie` |
| `token_url` | the target's own token or login endpoint (http or https) |
| `client_id` | for `client_credentials` |
| `username` | for `password` and `cookie` |
| `scope` | requested scopes, space separated |
| `cookie_name` | the session cookie a `cookie` grant reads |
| `username_field` | the login body's username field name |
| `password_field` | the login body's password field name |
| `format` | the login body's encoding, `json` or `form` |
| `access_token_field` | the token's field in the token response (default `access_token`) |

With a grant, `secret_env` holds the grant's sensitive half (the client secret or the
password), and the scan mints its own token. A grant that fails to mint leaves that
identity unauthenticated rather than failing the scan.

A `schema` block takes `host`, `port`, `database`, `username`, `password_env`,
`sslmode`, `sslrootcert` and `tables`. Only a local run reads it, on the CLI machine.

## Describing how the API authenticates

`aidetector init [URL] [--spec FILE]` writes a starting file. It reads a spec from this
directory (`openapi.yaml`, `openapi.json`, `swagger.json`, … or `--spec`), never from the
target, asks the server what the spec's `securitySchemes` say, and asks one question —
public, one key, or several roles — with the spec's answer as the default (`--yes` takes
it). It writes environment variable names only and prints the ones to export.

Pick the shape that matches the API:

```yaml
# A public API — deliberately no identities, and no warning about it.
auth: public
```

```yaml
# One API key: shorthand for a single identity named "default" (role user).
token_env: API_TOKEN
token_auth: query             # optional: bearer (default), header, api_key, basic, query, cookie
token_header: api_key         # the header / query parameter / cookie name
```

```yaml
# Several roles. rank is the explicit privilege, 0 (guest) … 3 (admin); without it the
# server infers it from the role name (viewer 0, user 1, editor/manager 2, admin 3).
identities:
  - { name: vic,   role: viewer, rank: 0, secret_env: VIEWER_TOKEN }
  - { name: eddie, role: editor, rank: 2, secret_env: EDITOR_TOKEN }
  - name: ops
    role: admin
    rank: 3
    secret_env: OPS_CLIENT_SECRET   # the grant's client_secret / password
    grant:                          # mint a fresh token at scan start
      type: client_credentials      # or password, cookie
      token_url: https://auth.example.com/oauth/token
      client_id: scanner
      scope: admin
```

Two accounts are enough for the authorization checks: two tenants (cross-account BOLA) or
a user and an admin (BFLA). When the keys span workspaces, say which is which with
`tenant:`. Without it the checks pair identities by rank alone, so two keys of one
workspace reading the same object reads as BOLA:

```yaml
identities:
  - { name: a-read,  role: viewer, rank: 1, tenant: a, secret_env: A_READ_KEY }   # BFLA: a-read vs a-write
  - { name: a-write, role: editor, rank: 2, tenant: a, secret_env: A_WRITE_KEY }  # BOLA: a-write vs b-write
  - { name: b-write, role: editor, rank: 2, tenant: b, secret_env: B_WRITE_KEY }
```

Identities with no `tenant` sit out the cross-tenant pairing once any identity sets one. With more tiers, BFLA also tries each middle tier when the
lowest is refused; a middle-tier hit is reported as a lead, not a verified finding.
`auth: public`, `token_env:` and `identities:` are alternatives — a file uses one.

## Precedence and ownership

**Precedence is per setting:** CLI flags > `aidetector.yml` > the web's saved settings >
defaults. A key the file leaves out stays the web's. Each run tells the server which
settings the file owns (target, spec, identities, request rate, run options). The web then
shows those controls read-only, marked "set by aidetector.yml", until someone clicks
**Hand back to the web**. Each run also records the file's digest and commit, so a diff
between runs whose settings came from different places says so (`config_changed`).

**Identities match by name.** One the file lists is created or updated. One that exists
only in the web is left alone. A secret never leaves this machine: an identity the CLI has
to create is created **local-only** — the server stores its name, role and auth shape, and
nothing else — and each run reads the secret from its `secret_env` here.
`aidetector cred add ID --name N --role R --local-only` does the same by hand; add
`--privilege N` for an explicit rank, and `--update` to change an identity that already
exists instead of failing on the name.

## What the file can never hold

- **Secrets.** A key such as `token:`, `password:` or `secret:` is refused, with a pointer to
  `secret_env`.
- **Consent.** There is no `authorized:` key, and unknown keys are refused. A committed file
  travels into forks and branches, and the person running the command must answer the
  authorization gate.
- **More than the server allows.** The request budget, the rate ceiling, the target guard
  and premium entitlement are the server's. The file can ask for less, never more.

Triage stays with people: a finding dismissed in the web stays dismissed.
