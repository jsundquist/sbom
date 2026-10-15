#!/usr/bin/env bash
# Session bootstrap and baseline verification. Run at the start of every agent session.
# Exits non-zero if the baseline is red, so broken state is fixed before new work starts.
set -euo pipefail

cd "$(dirname "$0")/.."

echo "==> node $(node --version), pnpm $(pnpm --version)"
pnpm install --frozen-lockfile

echo "==> type-check"
pnpm run lint

echo "==> unit + API tests (PGlite, no database needed)"
pnpm test

if [ -n "${DATABASE_URL:-}" ] && [ "${RUN_E2E:-0}" = "1" ]; then
  echo "==> build + e2e"
  pnpm run build
  pnpm run test:e2e
else
  echo "==> skipping e2e (set DATABASE_URL and RUN_E2E=1 to include it)"
fi

echo "==> baseline OK"
git status --short
git log --oneline -5
