#!/usr/bin/env bash
# Local dev: Postgres in Docker, web (next dev, hot reload) and worker on the host. Ctrl-C stops all of it.
set -euo pipefail

cd "$(dirname "$0")/.."

# Compose requires POSTGRES_PASSWORD (from the environment or .env); reuse it for DATABASE_URL.
if [ -z "${POSTGRES_PASSWORD:-}" ] && [ -f .env ]; then
  POSTGRES_PASSWORD="$(sed -n 's/^POSTGRES_PASSWORD=//p' .env | tail -1)"
fi
if [ -z "${POSTGRES_PASSWORD:-}" ]; then
  echo "Set POSTGRES_PASSWORD (e.g. echo \"POSTGRES_PASSWORD=\$(openssl rand -hex 16)\" > .env)" >&2
  exit 1
fi
export POSTGRES_PASSWORD
export DATABASE_URL="${DATABASE_URL:-postgres://sbom:${POSTGRES_PASSWORD}@localhost:5432/sbom}"

if lsof -iTCP:3000 -sTCP:LISTEN >/dev/null 2>&1; then
  echo "Port 3000 is in use (is the compose web container still running? docker compose stop web worker)" >&2
  exit 1
fi

echo "==> postgres"
docker compose up -d --wait db
echo "==> migrate"
pnpm run db:migrate

echo "==> web (http://localhost:3000) and worker; Ctrl-C to stop"
trap 'kill 0' EXIT INT TERM
pnpm run dev &
pnpm run worker &
wait
