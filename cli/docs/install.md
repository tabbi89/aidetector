# Installing runpentests

Each release publishes six CLI archives (macOS, Linux and Windows, AMD64 and
ARM64), a `SHA256SUMS` file and `runner.json`. The MCP setup helper
(`runpentests mcp`) is part of the same binary; there is nothing else to install.

## The CLI

1. Download the archive for your platform and `SHA256SUMS` from the release.
2. Verify the archive before extracting it:

   ```bash
   sha256sum --check --ignore-missing SHA256SUMS
   ```

   (`shasum -a 256 --check --ignore-missing SHA256SUMS` on macOS.)
3. Extract `runpentests` (`runpentests.exe` on Windows) and put it on your PATH.
4. Confirm it runs: `runpentests version`.

Each archive also carries `THIRD_PARTY_NOTICES.txt`, the licences of the libraries
compiled into the binary.

## The runner image

Every scan runs in a locked-down container started from the runner image. A
release binary has the image's exact digest compiled in, so the CLI always runs
the runner it was released with, never a moving tag. The same reference is in the
release's `runner.json`.

- **In a terminal**, the first scan offers to pull the image and asks before it
  does.
- **In CI** there is no one to ask, so pull the image from `runner.json` before
  the run:

  ```bash
  docker pull "$(jq -r .image runner.json)"
  ```

`--image` and `RUNPENTESTS_RUNNER_IMAGE` choose a different runner image
explicitly. The image contains the scanner and the tools it drives (sqlmap,
testssl, commix, dalfox, interactsh-client), with their licences.

Next: [setup.md](setup.md) takes a repository to a validated `runpentests.yml`.
