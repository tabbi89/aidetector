# Public CLI and runner distribution

The source repository stays private. A separate public repository holds only CLI
release archives, checksums and `runner.json`. The CLI includes the MCP setup
helper (`runpentests mcp`); there is no separate plugin executable.

The public runner is built by `services/api/runner.Dockerfile`. Its exact source
allowlist is `services/api/runner-files.txt`: scanner, local runner and their
shared policy/configuration modules. The private API routes, database models,
Celery workers, migrations, AI provider implementations, tests and environment
files are not exported. Included scanner source is readable by image consumers.
Production continues to use its private API/worker image.

This guide lives outside `cli/docs` on purpose: everything there is compiled into
the public binary.

## One-time setup

Everything public is published by the organization and a GitHub App, so no
personal account appears on the release page, in the distribution repository's
history or in the image.

1. Create the GitHub organization and keep members' visibility private. Move this
   source repository into it (it stays private). The workflow pushes the runner
   with the source repository's own `GITHUB_TOKEN`, which can only write packages
   to its owner's namespace, so the image lands at
   `ghcr.io/<organization>/runpentests-runner` (or `RUNNER_IMAGE`, below).
2. Create an **empty** public distribution repository in the organization, such
   as `runpentests/runpentests` — no README, no source. The first publish writes
   its README as the app, so no personal commit or push ever lands there.
3. Create a GitHub App owned by the organization (no webhook; repository
   permission **Contents: read and write**, nothing else) and install it on the
   distribution repository only. Its name is what the release page shows
   (`<app-slug>[bot]`). Generate a private key.
4. In this source repository's Actions settings:
   - variable `DISTRIBUTION_REPOSITORY` = `owner/repository` of step 2;
   - variable `DISTRIBUTION_APP_ID` = the app's ID;
   - secret `DISTRIBUTION_APP_PRIVATE_KEY` = the app's private key (PEM);
   - optionally variable `RUNNER_IMAGE` = a GHCR name without a tag.
5. GHCR creates new packages privately. After the first reviewed push, set the
   runner package's visibility to **public**. Repository visibility remains private.
   Validate an anonymous pull before making the CLI release public.

## Preview and release

Run the **distribution** workflow manually with a version such as `v1.0.0-rc.1`.
Leave `publish` off to build private Actions artifacts: a multi-platform OCI
image archive and six CLI archives (macOS, Linux and Windows, AMD64 and ARM64).
The binaries point at that image digest; preview images are not available from
GHCR until published/imported. Artifacts expire after 7/14 days respectively.

For a release, create the matching tag in the private source repository and run
the workflow on that exact tagged commit, with `publish` enabled. It runs the
CLI tests, API lint/types and distribution/source tests, builds both runner
architectures (including import smoke checks), pushes a versioned image and
compiles the resulting immutable image digest into every CLI binary. It uploads
the binaries to a **draft** release in the public distribution repository.
Archives include third-party license notices. Checksums cover every archive and `runner.json`; no source checkout/archive is
uploaded. Inspect that draft and publish it when ready. Prerelease versions
should be marked as prereleases in the release editor.

Before publishing, check the draft the way a user will install it: follow
[cli/docs/install.md](../cli/docs/install.md) on a clean machine, signed out of
GHCR. Local development builds keep using `make runner-image` and
`runpentests-runner:latest`.

GHCR visibility: https://docs.github.com/en/packages/working-with-a-github-packages-registry/working-with-the-container-registry

## Local validation

```bash
make runner-image
make test-cli
cd services/api
.venv/bin/pytest tests/test_runner_distribution.py tests/test_source_audit.py -q
```

The runtime scan reads only language/version declarations, without invoking
project code. It queries NVD with runtime CPE identifiers; source, credentials
and package inventories are not sent to NVD. Lookups are bounded by request,
time and response-size limits and respect NVD's anonymous rate limit. An offline,
rate-limited or truncated lookup is a coverage gap, never a clean bill of health.
