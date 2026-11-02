# Two runtime targets from one build: `web` (Next standalone, traced files only) and `worker` (worker + migrations).
# Build with `--target web` or `--target worker` (see docker-compose.yml).
FROM node:22-bookworm-slim@sha256:c3de60bf2f9dd0ac6370e6117950ff62d6e339527e7472301c9c78a017978392 AS deps
WORKDIR /app
RUN corepack enable
COPY package.json pnpm-lock.yaml pnpm-workspace.yaml ./
RUN pnpm install --frozen-lockfile

FROM deps AS build
COPY . .
ENV NEXT_TELEMETRY_DISABLED=1
RUN pnpm run build

# Prod-only node_modules for the worker, minus Next: the worker never imports it, and next/dist/compiled is large.
FROM build AS worker-modules
RUN pnpm prune --prod && rm -rf node_modules/next node_modules/.pnpm/next@*

FROM node:22-bookworm-slim@sha256:c3de60bf2f9dd0ac6370e6117950ff62d6e339527e7472301c9c78a017978392 AS base
WORKDIR /app
# Links the GHCR package to this repo.
LABEL org.opencontainers.image.source="https://github.com/jsundquist/sbom"
# The pinned base image lags Debian security fixes (Trivy flags perl-base); pull patched packages at build time.
RUN apt-get update && apt-get install -y --no-install-recommends --only-upgrade perl-base && rm -rf /var/lib/apt/lists/*
ENV NODE_ENV=production NEXT_TELEMETRY_DISABLED=1
# Numeric so Kubernetes runAsNonRoot can verify it (the node image's node user is 1000:1000).
USER 1000:1000

FROM base AS web
ENV PORT=3000 HOSTNAME=0.0.0.0
# Standalone output holds server.js plus only the node_modules files Next's tracing found; static assets are copied separately.
COPY --from=build /app/.next/standalone ./
COPY --from=build /app/.next/static ./.next/static
EXPOSE 3000
# Run node directly: npm and its sh wrapper do not relay SIGTERM, so the server would be killed instead of draining.
CMD ["node", "server.js"]

FROM base AS worker
COPY --from=build /app/package.json /app/tsconfig.json ./
COPY --from=worker-modules /app/node_modules ./node_modules
COPY --from=build /app/src ./src
COPY --from=build /app/scripts ./scripts
COPY --from=build /app/drizzle ./drizzle
CMD ["node", "--import", "tsx", "src/worker/main.ts"]
