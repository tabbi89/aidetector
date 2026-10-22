# Setting up runpentests for a project

This guide is for a coding agent (or a person) preparing a repository so that running
`runpentests` inside it scans the project's API. The result is a committed
`runpentests.yml` and a short list of commands for the person who will run the scan.

**You prepare; a person runs.** runpentests sends real attack payloads to a live API. The
person who runs the scan must confirm they are authorized to test the target, so do not
run `runpentests` with `--authorized` on their behalf, and never claim authorization for
them. Hand them the command instead.

## 1. Find the spec

Call `find_spec`. runpentests reads OpenAPI 3, Swagger 2, a HAR capture or a Postman
collection. If the repository has none:

- the framework may serve one at run time (FastAPI `/openapi.json`, springdoc
  `/v3/api-docs`, NestJS or drf-spectacular): leave `spec:` out and runpentests fetches it
  from the target;
- a Postman collection or a HAR recorded against staging works as the spec;
- do not write a spec by hand from the routes. A guessed spec scans guessed endpoints.

## 2. Find the target

Look for a staging or development base URL: deploy config, `.env.example`, the README,
CI workflows. Ask the person if it is unclear. Prefer staging to production, and never
choose production yourself. A public host must be verified by the workspace before it can
be scanned (Workspace → Domains); `localhost` and private addresses need no verification
and run from this machine (see `local-runs`).

## 3. Work out how the API authenticates

Read the code, not only the spec: auth middleware, how tokens are issued, the roles or
permissions enum, and how tenants or accounts are separated. Then pick one shape:

| the API… | write |
| --- | --- |
| takes no authentication | `auth: public` |
| takes one key or token | `token_env:` (plus `token_auth` / `token_header` if not bearer) |
| has users, roles or tenants | `identities:` with one entry per account |

The authorization checks (BOLA, BFLA) need **two identities**: a user and an admin, or
two accounts of the same role in different tenants. One identity scans, but those checks
are skipped. Give each identity a `rank` (0 guest … 3 admin) when the role name does not
say it.

When tokens expire, prefer a `grant` so the scan mints its own at start: a login endpoint
that returns a token is `password`, one that sets a session cookie is `cookie`, and an
OAuth client is `client_credentials`. Read the login handler to fill `token_url`,
`username_field`, `password_field`, `format` and `access_token_field`.

Call `suggest_config` with the `kind` you chose (`public`, `single` or `roles`) for a draft
in exactly the shape `runpentests init` writes; it also asks the runpentests server what the
spec's `securitySchemes` say when the person is logged in. Edit the draft with what the
code told you: real role names, the grant, the right header.

## 4. Never write a secret

`runpentests.yml` is committed. It names environment variables (`secret_env`,
`token_env`, `password_env`) and never holds a value: a key such as `token:` or
`password:` is refused. Do not put secret values in the file, in commands you suggest,
in `.env` files you create, or in your reply. The person exports them.

## 5. Validate, then write

Call `validate_config` with the draft's text. It runs the CLI's own loader and returns
the exact error, or a summary and warnings. Write `runpentests.yml` at the repository root
only when it is valid, then call `validate_config` with no arguments to check the file on
disk.

Leave these out unless the person asks for them:

- `passes: [writes]` — tests that **change target data**;
- `passes: [ai]` and the other AI passes — they spend tokens;
- `level: deep` — slow tools with far more traffic than the request budget.

`level: standard` is a sensible default for a first scan.

## 6. Hand over

Call `next_steps` and give the person its commands: logging in once, the environment
variables to export, and the command that runs the scan. For CI, point them at
`ci-gate`; the pipeline answers the authorization gate with `--authorized`, which is a
flag the person adds, never a file key.

## Reference

- `project-file` — every key in `runpentests.yml`
- `levels-and-passes` — what each level and pass does and costs
- `local-runs` — scanning from this machine, and reading the code
- `ci-gate` — gating a pipeline on the findings
- `safety` — the rules no setting can change
