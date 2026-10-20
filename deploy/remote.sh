#!/usr/bin/env bash
# Runs ON the production host, invoked by scripts/deploy.sh after the rsync.
# Idempotent: installs Docker once, writes /etc/runpentests.env once, then
# (re)builds and (re)starts the stack.
set -euo pipefail

DIR="$(cd "$(dirname "$0")/.." && pwd)"
ENV_FILE=/etc/runpentests.env
SITE_DOMAIN="${SITE_DOMAIN:-runpentests.com}"
COMPOSE=(sudo docker compose -f "$DIR/deploy/compose.prod.yml" --env-file "$ENV_FILE")

# The vulnerable target must never run here. rsync-exclude keeps it out; this
# catches a hand-copied tree.
if [ -e "$DIR/services/target" ]; then
  echo "refusing to deploy: $DIR/services/target exists (it must never be deployed)" >&2
  exit 1
fi

if ! command -v docker >/dev/null 2>&1 || ! sudo docker compose version >/dev/null 2>&1; then
  echo "==> installing Docker (Ubuntu packages)"
  sudo apt-get update -q
  sudo DEBIAN_FRONTEND=noninteractive apt-get install -y -q docker.io docker-compose-v2 docker-buildx
  sudo systemctl enable --now docker
fi

if ! sudo test -f "$ENV_FILE"; then
  echo "==> writing $ENV_FILE (secrets generated here, never synced)"
  pg_password="$(openssl rand -hex 24)"
  vault_key="$(python3 -c 'import base64,os;print(base64.urlsafe_b64encode(os.urandom(32)).decode())')"
  sudo install -m 600 -o root -g root /dev/null "$ENV_FILE"
  sudo tee "$ENV_FILE" >/dev/null <<EOF
# runpentests production settings. Generated $(date -u +%FT%TZ) by deploy/remote.sh.
# Secrets live only in this file. Edit it here, then re-run make deploy.
SITE_DOMAIN=$SITE_DOMAIN
ENV=prod
AUTH_REQUIRED=true

# Fernet key for credentials at rest. Losing it makes stored secrets unreadable;
# rotate by prepending a new key (comma-separated, first encrypts).
VAULT_KEY=$vault_key

POSTGRES_PASSWORD=$pg_password
DATABASE_URL=postgresql+psycopg://aidetector:$pg_password@postgres:5432/aidetector
REDIS_URL=redis://redis:6379/0

# Hosted posture: no private/loopback targets (the compose network holds
# Postgres and Redis), and a public target needs proven ownership.
TARGET_ALLOW_PRIVATE=false
TARGET_REQUIRE_VERIFICATION=true
NOTIFICATION_ALLOW_PRIVATE=false
LOCAL_RUNNER_ENABLED=false

ENGINE_REQUESTS_PER_SECOND=10
SESSION_HOURS=12
PLANNER_PROVIDER=deepseek
DEEPSEEK_API_KEY=
EOF
fi

echo "==> building and starting the stack"
"${COMPOSE[@]}" up -d --build --remove-orphans
# Compose does not restart Caddy when only the Caddyfile changed; reload it
# in place (graceful, keeps connections and certificates).
"${COMPOSE[@]}" exec -T caddy caddy reload --config /etc/caddy/Caddyfile --adapter caddyfile
sudo docker image prune -f >/dev/null

echo "==> waiting for the API"
for _ in $(seq 1 60); do
  if "${COMPOSE[@]}" exec -T api python -c \
      "import urllib.request;urllib.request.urlopen('http://127.0.0.1:8000/health',timeout=2)" \
      >/dev/null 2>&1; then
    "${COMPOSE[@]}" ps
    echo "==> deployed $(cat "$DIR/REVISION" 2>/dev/null || echo unknown) to https://$SITE_DOMAIN"
    exit 0
  fi
  sleep 3
done
echo "API did not become healthy; recent logs:" >&2
"${COMPOSE[@]}" logs --tail 60 api >&2
exit 1
