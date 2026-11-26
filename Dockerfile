# Two runtime targets from one build: `web` (Next standalone, traced files only) and `worker` (worker + migrations).
# Build with `--target web` or `--target worker` (see docker-compose.yml).
FROM node:26-bookworm-slim@sha256:5df79989ed685e09f0a98019db4cebfb22fb9df1a53c0161664a011f7ff6b0f1 AS deps
WORKDIR /app
# Node 25+ no longer bundles corepack, so install it before enabling the pnpm shim.
RUN npm install --global corepack && corepack enable
COPY package.json pnpm-lock.yaml pnpm-workspace.yaml ./
RUN pnpm install --frozen-lockfile

FROM deps AS build
COPY . .
ENV NEXT_TELEMETRY_DISABLED=1
RUN pnpm run build

# Prod-only node_modules for the worker, minus Next: the worker never imports it, and next/dist/compiled is large.
FROM build AS worker-modules
RUN pnpm prune --prod && rm -rf node_modules/next node_modules/.pnpm/next@*

# Runtime base is distroless: no shell, apt, dpkg, util-linux, gzip, tar or bundled npm/corepack, so the CVEs those
# carry (and the stock node image's npm node_modules) never ship. Pinned by digest.
FROM gcr.io/distroless/nodejs26-debian13:nonroot@sha256:a84242e747fbb5aaaa0180c273b6f7130ca34b3300082192ef58eea96089eb3c AS distroless

# Distroless keeps node at /nodejs/bin/node, off PATH. Manifests run `node` by name, so add a symlink for it.
FROM deps AS node-link
RUN mkdir -p /out/usr/local/bin && ln -s /nodejs/bin/node /out/usr/local/bin/node

FROM distroless AS base
WORKDIR /app
# Links the GHCR package to this repo.
LABEL org.opencontainers.image.source="https://github.com/jsundquist/sbom"
ENV NODE_ENV=production NEXT_TELEMETRY_DISABLED=1
COPY --from=node-link /out/ /
# Distroless sets ENTRYPOINT to node; clear it so CMD and compose/k8s `command: ["node", ...]` behave as before.
ENTRYPOINT []
# Numeric so Kubernetes runAsNonRoot can verify it.
USER 1000:1000

FROM base AS web
ENV PORT=3000 HOSTNAME=0.0.0.0
# Standalone output holds server.js plus only the node_modules files Next's tracing found; static assets are copied separately.
COPY --from=build /app/.next/standalone ./
COPY --from=build /app/.next/static ./.next/static
EXPOSE 3000
# Run node directly: npm and its sh wrapper do not relay SIGTERM, so the server would be killed instead of draining.
CMD ["/nodejs/bin/node", "server.js"]

FROM base AS worker
COPY --from=build /app/package.json /app/tsconfig.json ./
COPY --from=worker-modules /app/node_modules ./node_modules
COPY --from=build /app/src ./src
COPY --from=build /app/scripts ./scripts
COPY --from=build /app/drizzle ./drizzle
CMD ["/nodejs/bin/node", "--import", "tsx", "src/worker/main.ts"]
