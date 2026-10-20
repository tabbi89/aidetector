#!/usr/bin/env bash
# make deploy — ship this checkout to the production host and restart the stack.
#
#   DEPLOY_HOST  ssh alias (default prod-runpentests)
#   DEPLOY_DIR   where the tree lives on the host (default /opt/runpentests)
#   SITE_DOMAIN  public domain, used only when the host's env file is first
#                written (default runpentests.com)
#   ALLOW_DIRTY=1  deploy uncommitted changes (the REVISION gets a -dirty suffix)
set -euo pipefail

HOST="${DEPLOY_HOST:-prod-runpentests}"
DIR="${DEPLOY_DIR:-/opt/runpentests}"
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

rev="$(git rev-parse --short HEAD)"
if [ -n "$(git status --porcelain)" ]; then
  if [ "${ALLOW_DIRTY:-0}" != "1" ]; then
    echo "working tree has uncommitted changes; commit them or run ALLOW_DIRTY=1 make deploy" >&2
    exit 1
  fi
  rev="$rev-dirty"
fi

echo "==> deploying $rev to $HOST:$DIR"
ssh "$HOST" "sudo mkdir -p '$DIR' && sudo chown \"\$(id -un):\$(id -gn)\" '$DIR'"
rsync -az --delete --exclude-from=deploy/rsync-exclude ./ "$HOST:$DIR/"
ssh "$HOST" "printf '%s\n' '$rev' > '$DIR/REVISION' && SITE_DOMAIN='${SITE_DOMAIN:-runpentests.com}' bash '$DIR/deploy/remote.sh'"
