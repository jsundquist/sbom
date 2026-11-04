# Architecture

Keep this file true. If a change alters anything below, update it in the same commit.

## System

```
GitHub Action ──POST /api/v1/sboms──▶ Next.js app ──▶ Postgres ◀── worker ──▶ OSV.dev (CVEs)
                                         ▲            (NOTIFY)              └─▶ deps.dev (latest versions)
                               browser ──┘
```

Three runtime processes, one shared database:

| Process | Entry | Responsibility |
|---|---|---|
| Web app | `src/app/**` (Next.js App Router) | Upload API, read API, server-rendered pages |
| Worker | `src/worker/main.ts` | LISTENs for `sbom_uploaded`, polls every `WORKER_POLL_SECONDS`, runs `enrich()` |
| Migrator | `scripts/migrate.ts` | Applies `drizzle/*.sql` (compose `migrate` service) |

**Postgres is the only contract between app and worker.** The database is the job queue: package versions with a null or
stale `vulns_checked_at`, and packages with a null or stale `latest_checked_at`, are "due". The worker can be replaced
without touching the app.

## Source layout and dependency direction

```
src/app/        routes: pages (server components) + api/v1 route handlers      -> server/, components/, lib/
src/components/ MUI client/presentational components                            -> lib/ (types only from server/)
src/server/     ingest.ts (writes), inventory.ts (reads), api.ts (auth/errors)  -> db/, sbom/, lib/
src/sbom/       CycloneDX/SPDX parsing into a neutral ParsedSbom                -> lib/
src/worker/     enrich.ts, osv.ts, depsdev.ts, http.ts, main.ts                 -> db/, lib/
src/db/         schema.ts (source of truth), index.ts (getDb/setDb)             -> nothing app-level
src/lib/        pure helpers: env, purl, version, severity, params, routes      -> nothing app-level
```

Shared constants live in `src/lib/` (`ecosystems.ts` for the OSV/deps.dev ecosystem maps, `channels.ts` for the NOTIFY
channel), so `server/` and `worker/` never import each other. ESLint enforces the import directions (`no-restricted-imports`
blocks in `eslint.config.mjs`); `components/` may import only types from `db/` and `server/`.

## Data model (`src/db/schema.ts`)

| Table | Meaning | Notes |
|---|---|---|
| `projects` | An application or library | `name` unique; `latest_sbom_id` points at newest SBOM |
| `sboms` | One uploaded document | Raw `document` jsonb kept; pruned to `SBOM_HISTORY_LIMIT` per project |
| `components` | Package entries of one SBOM | Cascade-deleted with the SBOM; `package_key` = `<ecosystem>:<name>` |
| `component_edges` | "parent depends on child" within one SBOM | Null `parent_id` = the application depends on the child directly; no null rows = direct dependencies unknown. Cascade-deleted with the SBOM |
| `packages` | Distinct package, version independent | Holds `latest_version`, `latest_checked_at` |
| `package_versions` | A version in use | `vulns_checked_at` drives the scan queue |
| `vulnerabilities` | OSV record (GHSA/CVE/...) | `severity` enum, CVSS `score`/`vector` |
| `version_vulnerabilities` | Which version is hit, plus `fixed_versions` | FK to `package_versions` and `vulnerabilities` |
| `kev_entries` | CISA Known Exploited Vulnerabilities catalog, keyed by CVE id | Replaced wholesale on each sync; matched to vulns by id or CVE alias |
| `epss_scores` | FIRST EPSS score and percentile per CVE | Only CVEs we track; null score = looked up, none yet; fresh per CVE via `fetched_at` |
| `feed_syncs` | One row per feed: `synced_at`, `attempted_at`, `error` | TTL and retry backoff via `src/worker/feeds.ts` (KEV uses both; EPSS only the backoff) |

Invariants:

- Only the **latest SBOM per project** counts toward packages, vulnerabilities and stats. Older SBOMs exist for history/diff.
- `garbageCollect()` removes packages/versions/vulnerabilities no longer referenced. Run it after any delete or prune.
- `package_key` is derived from the purl (`src/lib/purl.ts`). Components without a purl have a null key and are shown as
  "unsupported" (no vuln/version lookup).
- Schema change = `pnpm run db:generate` and commit the migration. CI fails if the schema and migrations diverge.

## Flows

**Upload** (`POST /api/v1/sboms`): `checkUploadToken` -> size limit -> JSON parse -> Zod metadata (query params or
`X-Sbom-*` headers) -> `ingestSbom()`: parse SBOM, upsert project, insert SBOM + components + packages + versions in one
transaction, point `latest_sbom_id`, prune history, `NOTIFY sbom_uploaded`, then garbage-collect. Returns 201 with ids and a
dashboard URL. Parse/ingest errors are 400.

**Enrichment** (`enrich()` in `src/worker/enrich.ts`): independent jobs so one upstream outage does not block the others:
1. Vulnerability scan: due package versions -> OSV `querybatch` -> fetch each new vuln -> write `vulnerabilities` and
   `version_vulnerabilities`, stamp `vulns_checked_at` (or `vulns_error`).
2. Latest-version check: due packages -> deps.dev -> `latest_version` (or `latest_error`).
3. KEV sync (`src/worker/kev.ts`): when `feed_syncs.kev` is older than `KEV_TTL_HOURS`, download the CISA catalog and replace
   `kev_entries`. Skipped when `kevUrl` is not passed to `enrich()` (tests opt in). Failures keep old data and retry after 15 min.
4. EPSS sync (`src/worker/epss.ts`): CVEs of stored vulnerabilities with no score or one older than `EPSS_TTL_HOURS` are looked up
   in batches of 50. Runs after the vulnerability scan so new CVEs are scored in the same run. Same opt-in rule (`epssUrl`).

**Read**: pages and `GET /api/v1/*` both call `src/server/inventory.ts` (`listProjects`, `getProject`, `listPackages`,
`getPackage`, `listVulnerabilities`, `getVulnerability`, `getOverview`, `getSbomDocument`). `loadComponents()` is the core
join; aggregation (`aggregatePackages`, `aggregateVulnerabilities`, `summarize`) is pure and done in TypeScript.
Pages use `export const dynamic = 'force-dynamic'`.

## API surface (`/api/v1`)

`POST sboms` (auth), `GET sboms/[id]`, `GET projects[/id]`, `DELETE projects/[id]` (auth), `GET packages[/key]`,
`GET vulnerabilities[/id]`, `GET summary`, `GET /api/healthz` (readiness, pings the database), `GET /api/livez` (liveness, no database). Errors are `{ "error": string }` via `jsonError`.

## Configuration

All env vars are declared and validated in `src/lib/env.ts` (Zod) and documented in the README. Add new ones there, in
`.env.example`, and in the README table.

## Testing strategy

| Layer | Where | How |
|---|---|---|
| Pure logic | `tests/unit/lib.test.ts` | Vitest, no DB |
| Ingest, inventory, enrichment, API routes | `tests/unit/api.test.ts` | Vitest + in-process Postgres (PGlite) via `createTestDb()`; `fakeFetch()` stands in for OSV/deps.dev; routes called as functions |
| UI journeys | `tests/e2e/dashboard.spec.ts` | Playwright against a built app and real Postgres, seeded in `global-setup.ts` (auth off) |
| Owner-only gate | `tests/e2e/auth.spec.ts` | Playwright `authed` project: second server with auth on, forged session cookie |

Fixtures in `tests/fixtures/`. Tests never touch the network.

## Security

Implemented: upload bearer tokens (constant-time compare); fail-closed uploads (503) in production without
`UPLOAD_TOKENS` unless `ALLOW_OPEN_UPLOADS=true`; `MAX_UPLOAD_BYTES` enforced while streaming (413); in-memory write rate
limit (`WRITE_RATE_LIMIT`, 429, keyed on `X-Forwarded-For` only with `TRUST_PROXY=true`; per web process); CSP and
baseline headers from `src/lib/security-headers.ts` (`'unsafe-inline'` for Next bootstrap scripts and MUI styles); Zod on all
external input; compose requires `POSTGRES_PASSWORD`, binds Postgres to loopback, and runs containers with `cap_drop: ALL`,
`no-new-privileges` and a read-only rootfs (tmpfs for `/tmp`, `.next/cache`); web `healthcheck`; CI least-privilege
permissions with SHA-pinned actions; Dependabot; gitleaks; `pnpm audit`; actionlint, zizmor, dependency-review (PRs) and a
Trivy image scan (HIGH/CRITICAL, npm's bundled modules skipped).

Owner-only reads (E-004; ADR 0001): `src/server/auth.ts` holds the next-auth v4 options (pinned 4.24.15, JWT, `session.maxAge` and
`jwt.maxAge` both 604800, `NEXTAUTH_URL` assigned to `process.env` from `env()`, `AUTH_TRUST_HOST` never set) and `requireOwner(req)`,
called first in every `GET /api/v1/*` handler: 401 no session, 403 non-owner (numeric GitHub id compared as a string against
`OWNER_GITHUB_ID`, re-checked per request), 503 in production without full auth config unless `ALLOW_OPEN_READS=true`; open in
dev/test when auth is unconfigured. GitHub egress only through the injectable `FetchFn` in that module. Pages (E-005): every `page.tsx` starts with `requireOwnerPage()` (same `ownerState()` decision) and renders `AccessGate` (sign-in button, Access denied with login and sign-out link, or reads-disabled) in place; `tests/unit/page-auth.test.ts` fails if a page or route lacks the guard or an allow-list entry. Proxy (E-006, `src/proxy.ts`): first line, same `ownerState()`; open only `/api/auth/*`, `/api/healthz`, `/api/livez`, `/_next/static/*`, `/_next/image`, `/icon.svg` and, by method+exact path, `POST /api/v1/sboms` and `DELETE /api/v1/projects/[id]`; everything else (unknown paths included) is gated. Machine paths get JSON 401/403/503; page URLs other than `/` redirect to `/` (query dropped; `/` passes through so the in-place gate renders and nothing loops); production without config answers 503 to all gated requests. Auth routes are rate-limited by the `[...nextauth]` handler only (the proxy does not count), in their own bucket (`AUTH_RATE_LIMIT`, default 60 per window) separate from the write bucket, so `/api/auth/*` traffic can never exhaust uploads or deletes. Hardening from review: `NEXTAUTH_SECRET` must be at least 32 characters and `NEXTAUTH_URL` an http(s) URL, otherwise auth counts as not configured (503 in production unless `ALLOW_OPEN_READS=true`), because the owner id is public; sessions are read from the cookie only (`Authorization: Bearer` is ignored); the jwt callback sets `sub` from the GitHub id explicitly; `/api/healthz` returns a generic body and logs failures server-side; page metadata is neutral for gated viewers; `OwnerState` maps to HTTP via one `denial()` function.

Owner-only gate summary (E-002, fail-closed): reads (pages and `GET /api/v1/*`) require the single owner's GitHub session; uploads and
deletes stay on bearer tokens; production without full auth config answers 503 unless `ALLOW_OPEN_READS=true`. GitHub egress from the web
app (token exchange, `/user`) is a documented exception to "external HTTP only from the worker" (ADR 0001), confined to `src/server/auth.ts`
behind `FetchFn`. Covered end to end (E-007) by the `authed` Playwright project (`tests/e2e/auth.spec.ts`): a second server on its own port
with dummy GitHub credentials and a session cookie forged with `next-auth/jwt`, so nothing contacts GitHub. Setup: README "Owner-only sign-in".

Worker SSRF audit (E-003, 2026-11-04): the worker's only outbound hosts are `OSV_API_URL`, `DEPS_DEV_API_URL`, `KEV_URL` and
`EPSS_API_URL`, all operator-set via `env()` (Zod `.url()`); nothing a request or an SBOM can supply chooses the host. Uploaded
data only reaches URL paths and queries behind those fixed hosts: package names are `encodeURIComponent`-encoded (deps.dev), OSV ids
likewise, and EPSS CVE ids are now encoded too. Residual risk was redirect-following (a compromised upstream steering the worker at
internal addresses such as the metadata service or the k8s API); `fetchJson` now sets `redirect: 'error'` (none of the four default
endpoints redirect). Remaining: a misconfigured env URL is trusted, so keep those vars out of untrusted hands; NetworkPolicy egress
limits for the worker pod belong in the GitOps repo.

Known limits: the rate limit is in-memory and not shared across replicas; next-auth is v4 (pinned 4.24.15) because v5 is still beta,
so watch for v4 security releases and revisit when v5 is stable. Image signing and provenance are covered in SECURITY.md.

## Decisions that constrain future work

- **Postgres as queue and contract** (no Redis/broker). Keep worker logic in table state, not in-process memory.
- **Drizzle migrations are generated, never hand-written.**
- **Tests use PGlite, not a Postgres container**, so `pnpm test` is fast and dependency-free. Do not use Postgres-only
  features PGlite lacks in code paths covered by unit tests.
- **pnpm, not npm.** The runtime image runs scripts with the bundled `npm` on purpose (pnpm is build-time only).
- **MUI + MUI X DataGrid (MIT edition) + Recharts.** Do not add Pro/Premium DataGrid features.

## Roadmap

Planned work lives in `docs/features.json` (epics A-E, with `depends_on`). Two structural changes it will introduce:
a generic `reports` upload (C-001) alongside SBOMs, and persisted `project_snapshots` / `vulnerability_findings` tables
(A-005, A-007) because SBOM history is pruned. Thresholds and lists (SLA days, license rules) are plain env settings read
through `env()`; there is no separate policy file. Document each here when
it is built, not before.
