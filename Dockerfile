# One image runs the web app, the worker and migrations (see docker-compose.yml).
FROM node:22-bookworm-slim@sha256:c3de60bf2f9dd0ac6370e6117950ff62d6e339527e7472301c9c78a017978392 AS deps
WORKDIR /app
RUN corepack enable
COPY package.json pnpm-lock.yaml pnpm-workspace.yaml ./
RUN pnpm install --frozen-lockfile

FROM deps AS build
COPY . .
ENV NEXT_TELEMETRY_DISABLED=1
RUN pnpm run build && pnpm prune --prod

FROM node:22-bookworm-slim@sha256:c3de60bf2f9dd0ac6370e6117950ff62d6e339527e7472301c9c78a017978392
WORKDIR /app
# The pinned base image lags Debian security fixes (Trivy flags perl-base); pull patched packages at build time.
RUN apt-get update && apt-get install -y --no-install-recommends --only-upgrade perl-base && rm -rf /var/lib/apt/lists/*
ENV NODE_ENV=production NEXT_TELEMETRY_DISABLED=1 PORT=3000
COPY --from=build /app/package.json /app/tsconfig.json /app/next.config.ts ./
COPY --from=build /app/node_modules ./node_modules
COPY --from=build /app/.next ./.next
COPY --from=build /app/src ./src
COPY --from=build /app/scripts ./scripts
COPY --from=build /app/drizzle ./drizzle
# Numeric so Kubernetes runAsNonRoot can verify it (the node image's node user is 1000:1000).
USER 1000:1000
EXPOSE 3000
# Run next directly (same as `npm start`): npm and its sh wrapper do not relay SIGTERM, so the server would be killed
# instead of draining. pnpm is only needed to install/build.
CMD ["node", "node_modules/next/dist/bin/next", "start"]
