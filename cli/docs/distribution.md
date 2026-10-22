# Public CLI and runner distribution

The source repository stays private. A separate public repository holds only CLI
release archives, checksums and `runner.json`. The CLI includes the MCP setup
helper (`aidetector mcp`); there is no separate plugin executable.

The public runner is built by `services/api/runner.Dockerfile`. Its exact source
allowlist is `services/api/runner-files.txt`: scanner, local runner and their
shared policy/configuration modules. The private API routes, database models,
Celery workers, migrations, AI provider implementations, tests and environment
files are not exported. Included scanner source is readable by image consumers.
Production continues to use its private API/worker image.

## One-time setup

1. Create a separate public distribution repository, such as
   `tabbi89/aidetector-releases`, with an initial README commit. Do not copy source.
2. Set source-repository Actions variable `DISTRIBUTION_REPOSITORY` to that
   `owner/repository`. Optionally set `RUNNER_IMAGE` to a GHCR name without a tag
   (default: `ghcr.io/<source-owner>/aidetector-runner`).
3. Set Actions secret `DISTRIBUTION_TOKEN` to a token with contents write access
   only to the distribution repository. The source repository's `GITHUB_TOKEN`
   publishes the container with `packages:write`.
4. GHCR creates new packages privately. After the first reviewed push, set the
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

On a clean machine, download the matching CLI archive and `SHA256SUMS`, verify
its checksum, extract the executable and place it on PATH. Confirm
`aidetector version`, then configure `aidetector mcp` as in the CLI README.
On the first scan, the CLI offers to pull the pinned runner. CI must pull the
image recorded in `runner.json` beforehand. `--image` and
`AIDETECTOR_RUNNER_IMAGE` remain explicit overrides. Local development builds
continue to use `make runner-image` and `aidetector-runner:latest`.

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
