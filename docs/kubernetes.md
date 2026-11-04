# Running on Kubernetes (k3s, Argo CD)

Handoff for whoever writes the manifests. Two images run three workloads (web; worker and migrate share one). No secret values live in this repo; every
value below is a placeholder.

Images: `ghcr.io/jsundquist/sbom:<short-sha>-<run_number>` (web, Next standalone) and `ghcr.io/jsundquist/sbom-worker:<same tag>` (worker and migrate), linux/amd64, published by `.github/workflows/release.yml` on every push
to main (Trivy HIGH/CRITICAL gate first). The Dockerfile carries `org.opencontainers.image.source`, which links the package to
this repo.

**Manual step after the first push:** a new GHCR package is private, and no API or workflow can change that. Open
github.com -> your profile -> Packages -> `sbom` -> Package settings -> Danger Zone -> Change visibility -> Public. Until
then the cluster cannot pull it (no pull secret is configured). This is a one-time step; later tags inherit it.

Image contents (checked before going public): the final stage copies only `package.json`, `tsconfig.json`,
`next.config.ts`, `node_modules`, `.next`, `src`, `scripts` and `drizzle`. There are no `ARG`s and the only `ENV`s are
`NODE_ENV`, `NEXT_TELEMETRY_DISABLED` and `PORT`. `.dockerignore` excludes `.env`, every `.env.*` (except `.env.example`),
`.git` and `.claude`. A scan of the built image found no `.env`, key, `.npmrc` or `.git` files and no token, private-key or
credential-bearing connection-string patterns in the app files (the only matches were help text and dev scripts).

## Workloads

Run node directly in the container `command`, **not** `npm start` / `npm run worker`. npm launches `sh -c`, which does not
relay SIGTERM, so on pod termination the process is killed instead of shutting down (measured: exit 1 and an in-flight
enrichment run lost). The image `CMD` is already the direct form for both images.

| Workload | Kind | `command` (exec form) | Needs |
|---|---|---|---|
| migrate (`sbom-worker` image) | Job, Argo CD PreSync hook | `["node", "--import", "tsx", "scripts/migrate.ts"]` (the runtime image is distroless, so there is no `npm`) | `DATABASE_URL` only |
| web (`sbom` image) | Deployment, port 3000 | image default, i.e. `["node", "server.js"]` | DB, auth, upload, rate-limit vars |
| worker (`sbom-worker` image) | Deployment, no port | `["node", "--import", "tsx", "src/worker/main.ts"]` | DB and worker vars; egress to the hosts below |

Working directory is `/app` in all three. Keep web at **1 replica** (see Known limitations). Grace periods are under
Known limitations.

The migrate Job needs **only `DATABASE_URL`**. `scripts/migrate.ts` reads the shared env schema, but every other variable
has a default, and the concurrent-migration test above ran with `DATABASE_URL` alone. Give it no auth, upload or worker
values; ideally a Secret holding only that key (or a database role with just the DDL rights it needs).

Worker egress (HTTPS 443): `api.osv.dev`, `api.deps.dev`, `www.cisa.gov`, `api.first.org`. Web egress: `github.com` and
`api.github.com` only, for sign-in (ADR 0001). The web app never calls the worker or the reverse.

## Environment variables

All config is runtime; nothing is baked in at build time (no `NEXT_PUBLIC_*`), so the image is the same in every
environment. Parsed and validated with Zod in `src/lib/env.ts`; invalid values crash the process at first use.

| Name | Required | Secret | Used by | Example placeholder |
|---|---|---|---|---|
| `DATABASE_URL` | yes (default is localhost, so a missing value fails at connect time) | **yes** | web, worker, migrate | `postgres://sbom:<password>@postgres:5432/sbom` |
| `NEXTAUTH_SECRET` | yes in prod, 32+ chars | **yes** | web | `<openssl rand -hex 32>` |
| `GITHUB_CLIENT_SECRET` | yes in prod | **yes** | web | `<oauth app client secret>` |
| `UPLOAD_TOKENS` | yes unless `ALLOW_OPEN_UPLOADS=true` | **yes** | web | `<token1>,<token2>` |
| `GITHUB_CLIENT_ID` | yes in prod | no | web | `<oauth app client id>` |
| `OWNER_GITHUB_ID` | yes in prod; the numeric GitHub user id, not the login | no | web | `1234567` |
| `NEXTAUTH_URL` | yes in prod; http(s) URL | no | web | `https://sbom.digital-portfolio.net` |
| `TRUST_PROXY` | set `true` behind Traefik | no | web | `true` |
| `ALLOW_OPEN_UPLOADS` | no, default `false` | no | web | `false` |
| `ALLOW_OPEN_READS` | no, default `false`; leave `false` | no | web | `false` |
| `WRITE_RATE_LIMIT` / `WRITE_RATE_WINDOW_SECONDS` / `AUTH_RATE_LIMIT` | no, `60` / `60` / `60` (`0` disables) | no | web | `60` |
| `MAX_UPLOAD_BYTES` | no, 52428800 | no | web | `52428800` |
| `SBOM_HISTORY_LIMIT` | no, `20` | no | web | `20` |
| `WORKER_POLL_SECONDS` | no, `21600`; floor 300 | no | worker | `21600` |
| `VULN_TTL_HOURS` / `LATEST_TTL_HOURS` / `KEV_TTL_HOURS` / `EPSS_TTL_HOURS` | no, `12` / `24` / `24` / `24` | no | worker | `24` |
| `OSV_API_URL` / `DEPS_DEV_API_URL` / `KEV_URL` / `EPSS_API_URL` | no, public defaults | no | worker | leave unset |
| `NODE_ENV`, `PORT`, `NEXT_TELEMETRY_DISABLED` | set by the Dockerfile (`production`, `3000`, `1`) | no | all | leave unset |

Fail-closed defaults in production (`NODE_ENV=production`): reads return 503 unless all five auth vars are set and valid
(or `ALLOW_OPEN_READS=true`), and uploads are rejected when `UPLOAD_TOKENS` is empty (unless `ALLOW_OPEN_UPLOADS=true`).
A pod that starts "healthy" but answers 503 to everything usually has a missing or short auth value.

### Exact values for https://sbom.digital-portfolio.net

```
NEXTAUTH_URL=https://sbom.digital-portfolio.net
TRUST_PROXY=true
```

Do **not** set `AUTH_TRUST_HOST` (or `VERCEL`). next-auth v4 has no `trustHost` option, and in the installed 4.24.15
`detectOrigin` returns `NEXTAUTH_URL` first and only falls back to `X-Forwarded-Host` when `AUTH_TRUST_HOST` is set and
`NEXTAUTH_URL` is not. So with `NEXTAUTH_URL` set, a proxy that rewrites `Host` cannot change the OAuth redirect or cookie
settings, and no extra header config is needed. The one place that does read forwarded headers is `src/server/origin.ts`
(the absolute `url` returned by an upload); Traefik sets `X-Forwarded-Host` and `X-Forwarded-Proto` by default, and a
rewritten `Host` only affects that link, not authentication.

## Health endpoints

Both are open (no session), JSON, and exempt from the owner gate in `src/proxy.ts`.

| Probe | Path | Touches DB | Response |
|---|---|---|---|
| liveness | `GET /api/livez` | no | `200 {"ok":true}` |
| readiness | `GET /api/healthz` | yes (`select 1`) | `200 {"ok":true}`, or `503 {"ok":false}` (detail only in the pod log) |

Recommended probes (the server is ready in well under a second; each endpoint answers in a few milliseconds):

| Workload | Probe | Path | Period | Timeout | Other |
|---|---|---|---|---|---|
| web | `startupProbe` | `/api/livez` | 2 s | 2 s | `failureThreshold: 15` (30 s to start) |
| web | `livenessProbe` | `/api/livez` | 20 s | 3 s | `failureThreshold: 3` |
| web | `readinessProbe` | `/api/healthz` | 10 s | 3 s | `failureThreshold: 3`, `successThreshold: 1` |
| worker | none needed | | | | see below |

Worker: it serves no HTTP, so there is nothing to probe over the network and none is needed. It exits when it hits a
fatal error and Kubernetes restarts it; a dropped Postgres listener connection is retried every 5 s inside the process,
and enrichment errors are logged and retried on the next poll. An exec probe could not tell a healthy worker from a stuck
one without new code, so don't add one.

Verified: with Postgres stopped, `livez` stays 200 and `healthz` returns 503 in about 20 ms. Use `livez` for
`livenessProbe` so a database outage never restarts web pods. There is no HTTP endpoint for the worker; if you want a
probe, use the process (restart on exit; it reconnects its LISTEN connection itself).
Starting from cold the web server is ready in under a second; `initialDelaySeconds: 5` is plenty.

## Security context and writable paths

The image runs as `1000:1000` (the `node` user, numeric so `runAsNonRoot` verifies). It works with
`readOnlyRootFilesystem: true`, `allowPrivilegeEscalation: false`, `capabilities.drop: [ALL]` and `seccompProfile:
RuntimeDefault` (verified under compose with `read_only: true`, `cap_drop: ALL`, `no-new-privileges`). Mount `emptyDir`s at:

- `/tmp` (tsx compile cache, used by migrate and worker)
- `/app/.next/cache` (Next.js runtime cache, web)

Nothing else is written. With the direct commands above npm never runs, so the `/home/node/.npm/_logs` write errors you
would see under `npm start` do not occur.

## Database

- `DATABASE_URL` is a plain `postgres://user:pass@host:port/db` URL. The `pg` driver is not given any SSL option, so
  TLS is neither required nor forced; in-cluster plaintext works. For an external database append `?sslmode=require`.
- No extensions are needed; the migrations are plain tables and indexes. The role needs `CREATE` on schema `public` (it
  owns the tables) and normal DML. Migrations are tracked in `drizzle.__drizzle_migrations`.
- The worker uses `LISTEN`/`NOTIFY sbom_uploaded`, so it needs a direct connection (no transaction-pooling proxy).
  Each process holds up to 10 pool connections (web, worker) plus one dedicated listener (worker).
- Migrations run from the runtime image: `tsx` and `drizzle-orm` are production dependencies, and `scripts/` and `drizzle/`
  are copied in. `drizzle-kit` is a devDependency and is **not** in the image or needed. Re-running is a no-op (idempotent),
  a connection or SQL error exits non-zero (verified with a bad password), and two concurrent runs against an empty
  database both exited 0 with a correct journal (no advisory lock is taken, so a single Job per sync is still the safe
  shape). Migrations are forward-only; keep the web and worker compatible with the previous schema for one rollout.

## Behind Traefik

- TLS ends at Traefik. The app sees HTTP plus `X-Forwarded-Proto/Host`, which `src/server/origin.ts` uses for absolute URLs.
- `NEXTAUTH_URL=https://sbom.digital-portfolio.net` is what makes the session cookie `__Secure-` and fixes the OAuth
  redirect. The GitHub OAuth app's callback URL must be exactly
  `https://sbom.digital-portfolio.net/api/auth/callback/github`.
- Rate limiting keys on the leftmost `X-Forwarded-For` entry, else `X-Real-IP`, only when `TRUST_PROXY=true`. That is
  correct only if (a) Traefik overwrites an inbound `X-Forwarded-For` rather than appending to it (its default unless
  `forwardedHeaders.trustedIPs` / `insecure` is set), and (b) the client address survives to Traefik. On k3s the bundled
  ServiceLB can SNAT, in which case every client looks like one node IP and shares a single bucket (including the
  `/api/auth/*` bucket, so a flood there can rate-limit sign-in). Check what Traefik receives (`externalTrafficPolicy:
  Local` on the Traefik service is the usual fix).
- Do not expose the app on a path that bypasses Traefik with `TRUST_PROXY=true`: a client could then set its own
  `X-Forwarded-For`.

## Resources

Measured with `docker stats` under compose (colima, **arm64**; expect amd64 within roughly 10 %), after uploading a
505-component SBOM and letting the worker enrich it, then loading each page and API route a few times:

| Process | Idle | Steady / peak observed | CPU |
|---|---|---|---|
| web | ~97 MiB | 115 MiB, 155 MiB after page renders | ~0-6 % of a core |
| worker | ~108 MiB | 160 MiB while enriching | one short burst (~33 % for a few seconds), idle otherwise |
| postgres | ~70 MiB | 70 MiB | negligible |

Suggested starting points (the 50 MB upload cap is parsed in memory, so web gets headroom):

| | requests | limits |
|---|---|---|
| web | `cpu: 50m`, `memory: 192Mi` | `cpu: 500m`, `memory: 512Mi` |
| worker | `cpu: 25m`, `memory: 192Mi` | `cpu: 500m`, `memory: 384Mi` |
| migrate | `cpu: 50m`, `memory: 128Mi` | `memory: 256Mi` |
| postgres | `cpu: 50m`, `memory: 256Mi` | `memory: 512Mi` |

Not measured: a worst-case 50 MB SBOM upload, or thousands of packages. Revisit the web limit if it gets OOM-killed on a
large upload.

## Known limitations

- **No web drain on SIGTERM.** `next start` exits immediately (143), so in-flight requests, such as a long upload, are cut
  off during a rollout. Accepted; no wrapper. Suggested `terminationGracePeriodSeconds: 15` for web (30, the default, also works, since it exits
  at once).
- **Worker drain.** It waits up to 25 s for the current enrichment run, then closes its connections. Suggested
  `terminationGracePeriodSeconds: 40` (25 s drain plus about 15 s margin for pool shutdown and scheduling). A run that
  outlasts the drain is abandoned; the next poll or upload re-enriches, so nothing is corrupted.
- **Migrate has no advisory lock.** Run exactly one migrate Job at a time (Argo CD PreSync gives that). Two concurrent runs
  against an empty database both succeeded in testing, but that is not guaranteed for every migration.
- **In-memory rate limiter.** Upload, delete and `/api/auth/*` limits live in each web pod's memory, so web must stay at 1
  replica; with more, the limits multiply and reset on every restart.
- **X-Forwarded-For caveat.** With `TRUST_PROXY=true` the client IP is the leftmost `X-Forwarded-For` value. That is
  trustworthy only if Traefik replaces (not appends to) an inbound header and the real client address reaches Traefik; k3s
  ServiceLB can SNAT it (see Behind Traefik). With `TRUST_PROXY=false` all clients share one bucket.
- **No image retention.** Old `ghcr.io/jsundquist/sbom` versions are never pruned. Only pushes to `main` build an image, so
  they accumulate slowly; delete old versions by hand in GHCR if it matters. If a prune job is added, it must protect the
  tag pinned in `apps/sbom/kustomization.yaml` of `jsundquist/k8s-gitops`.
- The live GitHub OAuth round trip has not been verified yet (E-003).

## Deploy bump and GITOPS_TOKEN

After the image is pushed, the `bump` job in `release.yml` checks out `jsundquist/k8s-gitops`, sets `.images[0].newTag` in
`apps/sbom/kustomization.yaml` and pushes `chore(sbom): deploy <tag>` to its default branch; Argo CD syncs from there. It
retries the push 3 times and does nothing if that tag is already pinned.

`GITOPS_TOKEN` (repository secret on this repo) is a **fine-grained personal access token** with:

- Repository access: **only** `jsundquist/k8s-gitops`
- Permissions: **Contents: read and write**, nothing else

When it expires or is revoked, `bump` fails at checkout (the image is still published, but the cluster keeps running the
old tag), and `token-expiry` fails. That job runs on every release, calls the GitHub API with the token and fails on a 401
or when fewer than 14 days remain. Fix: create a new PAT with the same scope and replace the secret. Then re-run the
failed `bump` job, or the next push to `main` pins its newer tag anyway.

## Surprises

- `npm start`, `npm run worker` and `npm run db:migrate` all run through `sh -c`; only the last is safe to use in a pod
  (see Workloads). The compose worker uses the direct command for the same reason.
- `/api/healthz` was the only health endpoint before this change and doubles as the compose healthcheck, which is
  why a Postgres outage marks the web container unhealthy there.
- The image is built and scanned in CI, but a push only happens from `main`; branches build nothing publishable.
