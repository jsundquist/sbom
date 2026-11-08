# Progress log

Newest first. Format and rules: `docs/WORKFLOW.md#progress-md-entry-format`.

## Current state

- Main has the full dashboard (upload, projects, packages, vulnerabilities, worker, CI hardening) and uses pnpm (#7).
- Baseline: owner-only auth (E-004..E-007) lives on `feat/owner-auth`; review fixes on `fix/owner-auth-review`. See the newest entries.
- Next: pick the lowest-priority `todo` in `docs/features.json`.

## 2026-11-08: A-005 Daily snapshots
- Done (branch `feat/a-005-daily-snapshots`, off main): `project_snapshots` (unique project + UTC day; components, vulnerable components, distinct vulnerabilities by severity, outdated total and major); `snapshotCounts()` in `src/lib/snapshot.ts`; `writeSnapshots()` in `src/worker/snapshots.ts` runs last in every `enrich()`.
- Verified: `pnpm run lint` and `pnpm test` (239, new `snapshots.test.ts`) green. Not run: e2e (no page or route change).
- Decisions: built without A-004, so no libyears column. Keyed by project, not SBOM, so pruning cannot delete it. "On upload" is the NOTIFY-woken enrich run; with the worker down no snapshot is written.
- Not done: KEV/exploited count, backfill (not required), any read API (A-006).
- Gotchas: migration `0004` is also taken by the B-003 and B-002 branches; whichever merges after the first must rebase and rerun `pnpm run db:generate`.

## 2026-11-08: B-004 Container image scans
- Done (branch `feat/b-004-image-scans`): action `image` input (Syft scans the image instead of the checkout), README row and example; worker now queries OSV by `Alpine:vX.Y` + name for `apk` packages, with the release read from the component purl `distro` qualifier (`osvEcosystem()` in `src/lib/ecosystems.ts`, `distrosFor()` in `enrich.ts`).
- Verified: `pnpm run lint` and `pnpm test` (241, new `os-packages.test.ts`) green. Not run: e2e (no UI or route change); the action's `image` path (needs a real workflow run); live OSV after deploy.
- Why: a bare purl lookup returned `{}` for `musl` even with `?distro=`; the same name + `Alpine:v3.20` returned `ALPINE-CVE-2025-26519`. Image SBOMs from `k8s-gitops/cluster-sbom.yml` therefore showed no OS-package CVEs.
- Not done: the same version in two Alpine releases (a version row holds one vuln set, so only the newest release is queried; needs the release on `package_versions`); deb/rpm (advisories use source package names), apk packages whose binary name differs from the origin package (e.g. `musl-utils`), a project "kind" column, and an `apk` package with no `distro` qualifier still returns nothing silently.
- Next: after deploy, check `musl` on the sbom image page; B-003.

## 2026-11-04: Inventory deepening refactor
- Done (branch `refactor/inventory-depth`, one commit each): (1) `src/server/exploit-signals.ts` replaces the loadKev/loadEpss/kevFor/epssFor twins, and `src/lib/cve.ts` holds the CVE-alias rule shared with the EPSS worker; (2) `src/lib/coverage.ts` owns scannable/version-checkable and the vuln/version status, used by `loadComponents` and the worker due queries; (3) `loadComponents(db, scope)` takes `sbomIds`/`packageKey`/`vulnerabilityId`, so `getPackage` and `getVulnerability` no longer load the whole inventory.
- Verified: `pnpm run lint` and `pnpm test` (233, incl. new `inventory-scope.test.ts`) green after each commit. Not run: `pnpm run test:e2e` (no UI or route changes).
- Not done (review candidates 4 and 5): extract the vuln-scan persistence step from `scanVulnerabilities`; share feed-sync scaffolding between KEV and EPSS.
- Gotchas: `KevInfo`/`EpssInfo` now live in `exploit-signals.ts`, not `inventory.ts`.

## 2026-11-01: Dogfood SBOM upload
- Done (branch `ci/dogfood-sbom`): `.github/workflows/sbom.yml` runs this repo's own action (`uses: ./`) on push to main and manual dispatch, uploading to https://sbom.digital-portfolio.net.
- Verified: actionlint and zizmor clean, Prettier clean. Not verified: a real run (needs the secret below and a push to main).
- Next: add Actions secret `SBOM_DASHBOARD_TOKEN` (one of the server's `UPLOAD_TOKENS`), then run the workflow once via workflow_dispatch.
- Gotchas: zizmor wants `$/` for same-repo actions but the pinned actionlint rejects it, so `./` carries an inline `zizmor: ignore[self-repository]`; switch when actionlint supports `$/`.

## 2026-11-01: E-008 Kubernetes readiness
- Done (branch `chore/k8s-readiness`, off `feat/owner-auth`): numeric `USER 1000:1000`; `GET /api/livez` (no DB) beside `/api/healthz` (readiness); worker waits up to 25 s for the in-flight enrichment run on SIGTERM and closes its LISTEN client; web `CMD` and the compose worker `command` run node directly; `.github/workflows/release.yml` (build amd64, Trivy, push `ghcr.io/jsundquist/sbom:<short-sha>-<run_number>`); `docs/kubernetes.md`.
- Verified: typecheck, eslint and `pnpm test` (224) green; under compose with read-only rootfs and `cap_drop: ALL`: livez 200 / healthz 503 with Postgres stopped, worker SIGTERM mid-run exits 0 after logging its result, two concurrent `db:migrate` runs both exit 0, bad password exits 1; actionlint and zizmor clean on `release.yml`.
- Also verified: `pnpm run test:e2e` 13 passed against a throwaway Postgres 16; image scanned for secrets (no `.env`, keys, ARGs or credential patterns); label `org.opencontainers.image.source` present; `.dockerignore` now excludes every `.env.*` and `.claude`; Q-005 fixed (`.claude` in `.prettierignore`, `.claude/worktrees/` gitignored).
- Not verified: the release workflow itself (runs on push to main), amd64 memory (measured on arm64).
- Next: Kubernetes manifests live in the GitOps repo; E-003 still needs the live OAuth round trip.
- Gotchas: `npm start` and `npm run worker` go through `sh -c` and never relay SIGTERM (exit 1, run lost), so use node directly in pod commands. `next start` exits 143 on SIGTERM without draining. `pnpm run lint` fails while untracked `.claude/worktrees/*` exist (Q-005).

## 2026-10-31: Retro tickets queued
- Done: turned the retro of the owner-auth session into tickets Q-004 (self-provisioning e2e script plus e2e in done), Q-005 (exclude agent worktrees), Q-006 (stale `.next`), Q-007 (CODING_STANDARDS.md), Q-008 (implementer contract, blocked by Q-005), Q-009 (progress.md order check). All at priority 24.5 so they run after E-003 (the owner-auth deploy checklist, priority 24) and before D-004.
- Next: E-003 (HITL: OAuth app registration, live sign-in), then Q-004, Q-005, Q-006.

## 2026-10-30: Owner-auth review fixes
- Done (branch `fix/owner-auth-review`, on top of `feat/owner-auth`): secret must be >= 32 chars and `NEXTAUTH_URL` http(s), else auth counts as not configured (503 in production); `/api/auth/*` has its own rate-limit bucket (`AUTH_RATE_LIMIT`, default 60) so it cannot exhaust uploads/deletes; `/api/healthz` returns `{ok:false}` and logs the detail server-side; layout metadata is neutral for gated viewers; `Authorization: Bearer` is ignored for sessions (cookie only); jwt callback sets `token.sub` from `String(profile.id)` explicitly; one `denial()` mapping shared by `requireOwner`, `proxy()` (and `requireOwnerPage` via `ownerState(Headers)`); `FetchFn` single definition in `src/lib/fetch.ts`.
- Gotchas: the older E-004 note below about passing `new NextRequest(req)` to `getToken` is superseded: wrapping throws in the Next runtime, so `ownerState` hands `getToken` a plain cookie record and empty headers. With `TRUST_PROXY` off all clients still share one bucket per scope, so an anonymous flood of `/api/auth/*` can still rate-limit sign-in itself (not uploads); set `TRUST_PROXY=true` behind a proxy for per-client limits. v4's github provider already maps `sub` to `profile.id.toString()`; the explicit set is hardening, not a bug fix.

## 2026-10-30: E-007 verified, E-002 done
- e2e (13 tests) run for the first time against a throwaway postgres container; found and fixed: `new NextRequest(req)` in `ownerState` throws "Cannot read private member #state" in the Next runtime (owner got 500, unit tests passed because they use plain `Request`; regression test added with a real `NextRequest`); existing chromium e2e server now sets `ALLOW_OPEN_READS=true` since `next start` is production.
- Gotcha: a stale gitignored `.next/` from another branch can break `tsc` (`.next/types/validator.ts`); delete it. Worktrees inside the repo (`.claude/worktrees/`) make `pnpm run lint` fail on Prettier/ESLint while they exist.
- Not verified: live GitHub OAuth round trip (E-003).

## 2026-10-30: E-007 authed e2e and security docs
- Done: `authed` Playwright project (own port 3101, auth on, dummy GitHub creds, session forged with `next-auth/jwt`) in `playwright.config.ts` + `tests/e2e/auth.spec.ts`; existing `chromium` project unchanged (auth off, ignores auth spec). README owner-sign-in section, `.env.example`, compose env passthrough, ARCHITECTURE.md#security, AGENTS.md pointer to ADR 0001. `pnpm run lint` and `pnpm test` (210) green.
- Superseded: the e2e run that was blocked here later passed against a throwaway Postgres (see the entry above).
- Branch `feat/owner-auth`.

## 2026-10-30: E-006 Proxy gate
- Done: `src/proxy.ts` (Next 16 proxy, reuses `ownerState()`), `tests/unit/proxy.test.ts` (38 tests, calls `proxy()` with `NextRequest`). Non-owner page URLs redirect to `/`, which passes through to render the gate. Branch `feat/owner-auth`.
- Verified: typecheck, eslint, prettier --check, `pnpm test`, `pnpm run build`. No e2e, no live round trip.
- Gotchas: `NextRequest.nextUrl` rewrites `/_next/data/<build>/x.json` to `/x`, so the proxy reads the raw `req.url`. Rate limit on auth routes was already in the E-004 handler; test mocks `next-auth` because the real handler needs a request scope.

## 2026-10-30: E-005 Gated pages
- Done: `ownerState()`/`requireOwnerPage()` in `src/server/auth.ts` (shared with `requireOwner`), `AccessGate` + `SignInButton` components, guard first in all 7 pages, NavBar hidden when gated (layout), coverage test in `tests/unit/page-auth.test.ts`. Branch `feat/owner-auth`.
- Verified: typecheck, eslint, prettier --check, `pnpm test` (172 tests), `pnpm run build`. No e2e, no live GitHub round trip; gate renders in place with HTTP 200 (proxy/redirects are later tickets).
- Gotchas: signIn callback must admit non-owners or they never get a session to show their login; owner check is per request.

## 2026-10-30: E-004 Owner-gated read API
- Done: `src/server/auth.ts` (next-auth 4.24.15 options, `requireOwner(req)`, injectable-fetch GitHub token/userinfo), env vars
  `OWNER_GITHUB_ID`, `NEXTAUTH_SECRET`, `NEXTAUTH_URL`, `GITHUB_CLIENT_ID/SECRET`, `ALLOW_OPEN_READS`; guard on all 9 `GET /api/v1/*` handlers;
  `/api/auth/[...nextauth]` handler with the write rate limiter. Branch `feat/owner-auth`.
- Verified: `pnpm run lint`, `pnpm test` (130 tests, 49 new). No live GitHub round trip, no pages/proxy/e2e (E-005..E-007).
- Gotchas: `getToken` needs `req.cookies` (do NOT wrap in `new NextRequest(req)`: it throws in the Next runtime; superseded, see E-007 verified); cookie name follows `NEXTAUTH_URL` scheme (`__Secure-` on https).
  GET handlers now take a `Request` argument.

## 2026-10-16: Worker poll interval
- Done: `WORKER_POLL_SECONDS` default 30s -> 6h, with a 300s floor (`MIN_WORKER_POLL_SECONDS`, clamped in `src/lib/env.ts`) so a
  low override such as 5s cannot hammer OSV, deps.dev, CISA or FIRST. Uploads still wake the worker via NOTIFY. Branch `fix/worker-poll-interval`.
- Verified: `pnpm run lint`, `pnpm test` (81 tests, 3 new in `tests/unit/env.test.ts`). No UI or route change, e2e not run.
- Gotchas: the repo default was already 30s, so the 5s in production comes from a deploy-time env var; remove or raise it. Package
  versions whose vulnerability detail lookups fail keep a null `vulns_checked_at` and are retried on every run (each upload and
  poll) with no backoff; not changed here.
- Next: A-004, then B-001.

## 2026-10-16: Q-001, Q-002 layering
- Done: shared constants moved to `src/lib/ecosystems.ts` (OSV_TYPES, depsDevSystem) and `src/lib/channels.ts`
  (SBOM_UPLOADED_CHANNEL); `no-restricted-imports` layer rules in `eslint.config.mjs` (type-only imports allowed from components);
  AGENTS.md and ARCHITECTURE.md updated.
- Verified: `pnpm run lint`, `pnpm test` (78 tests), rule fires on temporary lib->server and components->db imports. No UI or
  route behavior changed, so e2e and build were not run.
- Gotchas: the new rule caught a second cross-edge (worker/main.ts importing the channel name from server/ingest), also fixed.
- Next: A-004, then B-001.

## 2026-10-16: B-006 Dependency graph
- Done: parser keeps dependency edges (`ParsedSbom.edges`/`direct`; CycloneDX `dependencies`, SPDX `DEPENDS_ON` and reversed
  `DEPENDENCY_OF`); `component_edges` table (migration `0003`, null parent = direct dependency); `getDependencyGraph` and
  `GET /api/v1/projects/:id/dependencies`; pure `src/lib/dependency-tree.ts` (roots, tree items with "shown above" repeats and
  cycle safety, vulnerable-only filter, paths to a package); Dependencies tab on the application page (`@mui/x-tree-view`)
  with a path/versions side panel; demo data now has edges for web-storefront and payments-api.
- Verified: lint, 78 unit tests, build, 9 e2e tests; screenshots in the dev server (demo data and the real GitHub fixture).
- Gotchas: edges are only stored for uploads made after this change, so existing applications need a re-upload (empty-state text
  says so). Syft output has no root entry, so the top level is "packages nothing depends on" and includes orphans. A
  stale `.next` from a production build makes `next dev` reload in a loop; delete `.next` first. Item ids in the tree are
  path-based (`parent/child`) because a shared dependency appears under several parents.
- Next: A-004, then B-001. Phase 2 (which parent to upgrade, from deps.dev per-version dependencies) is not ticketed.

## 2026-10-16: P-003 Dependency graph ticket
- Done: added B-006 (priority 12.5, so it runs before A-004) for storing SBOM dependency edges and a dependency tree per
  application. Tree UI is `@mui/x-tree-view`; React Flow is deferred. Feasibility measured on this repo's own SBOMs (see the ticket notes).
- Verified: JSON parses, ids unique, dependencies keep lower priority numbers. No code changed.
- Next: B-006, then A-004.

## 2026-10-16: P-002 Roadmap scoped to the dashboard
- Done: marked C-004/C-005/C-006 (CI health, coverage, DORA), D-003 (ownership) and E-001 (policy file) `superseded`; kept E-002
  (auth is required for a standalone tool) and added a visibility-model decision to it; B-001 now flags EOL runtimes (for example
  Node.js 22 past EOL) as a security risk. A-007, A-008, D-001 no longer depend on E-001 and read thresholds from env.
- Verified: JSON parses, all `depends_on` resolve, dependencies keep lower priority numbers. No code changed.
- Open: where the runtime for B-001 comes from (explicit Action input vs image scans) is decided when it is picked up.
- Next: B-001.

## 2026-10-16: A-003 Priority ordering
- Done: `comparePriority` in `src/lib/priority.ts` (KEV, then EPSS, then severity, then CVSS; unscored EPSS counts as 0);
  `aggregateVulnerabilities` sorts with it and adds a 1-based `rank`; the vulnerabilities grid defaults to a Priority column
  (ascending); `getOverview` returns `fixFirst` (top 5) rendered by `FixFirstList` on the overview.
- Verified: lint, 58 unit tests, build, 7 e2e tests, and a screenshot check against `pnpm run dev:all`.
- Gotchas: rank is per list, so on a project or package page it is the position within that page's vulnerabilities. One CVE
  that appears under several advisory ids (GHSA, GO) shows as separate rows. Next: B-001 (EOL) should feed this order.
- Next: B-001, or the Backstage-driven roadmap changes.

## 2026-10-16: S-001, S-002, S-003, S-005 security hardening
- Done (one commit each, branch `security/hardening`): security headers + CSP (`src/lib/security-headers.ts`); streaming 413 and
  per-client write rate limit (`checkRateLimit`/`readBodyLimited` in `src/server/api.ts`); compose hardening; actionlint, zizmor,
  dependency-review and Trivy in `security.yml`.
- Verified: lint, 52 unit tests, build, 6 e2e tests (incl. CSP console check); parallel compose stack healthy on a read-only
  rootfs; actionlint, zizmor and Trivy clean locally.
- Gotchas: compose now fails without `POSTGRES_PASSWORD` (existing `pgdata` volumes keep their old password; the variable only
  seeds new DBs). Trivy flagged perl-base in the pinned base image, so the runtime stage runs `apt-get --only-upgrade perl-base`;
  it also skips npm's bundled modules. Without a proxy all clients share one rate-limit bucket. Dependency-review needs the
  repo's dependency graph enabled.
- Next: A-003, or Q-001/Q-002.

## 2026-10-15: Q-003 ESLint + Prettier
- Done: ESLint 9 (eslint-config-next, typescript-eslint with type-aware `no-floating-promises`/`no-misused-promises`, `curly`),
  Prettier (single quotes, width 140), `pnpm run lint` = typecheck + eslint + prettier check, CI runs all three on every push,
  codebase formatted, braces enforced. Two real findings fixed (async callbacks in the worker, setState in an effect).
- Decision: TypeScript is pinned to 6.x. typescript-eslint hard-fails on TS 7 and supports TS <6.1 only; Dependabot ignores TS
  majors. Revisit when typescript-eslint adds TS 7 support (typescript-eslint#10940).
- Accepted audit finding: `braces` GHSA-vfj7-8cjw-p6xm (dev-only, via eslint-config-next > fast-glob > micromatch; no patched release
  exists) is ignored in `pnpm-workspace.yaml` `auditConfig`. Remove the entry once braces >= 3.0.4 ships. The `esbuild` moderate finding via
  drizzle-kit is pre-existing and below the `high` gate.
- Gotchas: pnpm 11 errors on unreviewed install scripts, so `unrs-resolver` is set to `false` in `pnpm-workspace.yaml`. Markdown and
  `docs/features.json` are excluded from Prettier. The two mechanical commits are listed in `.git-blame-ignore-revs` (GitHub
  squash-merge drops those SHAs; use a merge or rebase merge to keep them).

## 2026-10-15: A-002 EPSS scores
- Done: `epss_scores` table (migration `0002_epss_scores`), `src/worker/epss.ts` (per-CVE FIRST API, 50 per request, per-CVE
  TTL `EPSS_TTL_HOURS`), shared `src/worker/feeds.ts` (TTL and retry backoff, now used by KEV too), `epss` on
  `ComponentVuln` and the vulnerability APIs, EPSS column (sortable/filterable) and detail row, `formatEpss`, demo data.
- Verified: lint, 47 unit tests, build, 5 e2e tests, live stack (75 CVEs scored; 87/87 vulns have EPSS).
- Next: A-003 (rank by KEV > EPSS > CVSS) is unblocked once A-001 and A-002 are merged.
- Gotchas: EPSS is gated per CVE, not by the feed-level TTL, otherwise newly found CVEs would wait up to 24h; `feed_syncs`
  only provides failure backoff for it. A CVE with several CVE aliases shows the highest score. `fetchJson` retries 5xx twice,
  so one failed run makes 3 requests. Stacked on A-001's branch; if A-001 changes in review, renumber/rebase the migration.

## 2026-10-15: A-001 CISA KEV ingestion
- Done: `kev_entries` and `feed_syncs` tables (migration `0001_kev_and_feed_syncs`), `src/worker/kev.ts` daily sync (TTL
  `KEV_TTL_HOURS`, 15 min backoff after failures, existing data kept on failure), `kev` on `ComponentVuln`/vulnerability
  APIs, `stats.exploited`, `KevChip`, Exploited column (boolean filter) in the vulnerabilities grid, detail-page row, overview
  chip, demo/e2e data (Log4Shell), README and `.env.example`.
- Verified: lint, 39 unit tests, build, 5 e2e tests, and the live compose stack (1745 entries; 2 exploited vulns).
- Next: A-002 (EPSS) can reuse `feed_syncs`; A-003 then ranks by KEV > EPSS > CVSS.
- Gotchas: a vulnerability matches KEV via its own id or any CVE alias (GHSA records carry the CVE as an alias).
  E2E needs `pnpm exec playwright install chromium` after a Playwright upgrade and a `sbom_e2e` database.

## 2026-10-15: P-001 Roadmap triage
- Done: split the "software health" roadmap into 26 tickets in `docs/features.json` (epics A prioritization/freshness, B dependency
  health, C reports and repo health, D tools that act, E foundations). Added `epic`, `size`, `depends_on`, `notes` fields;
  `S-004` is superseded by `E-002`.
- Verified: JSON parses, ids unique, all `depends_on` resolve, dependencies always have a lower priority number.
- Order: A-001, A-002, A-003 (KEV/EPSS) -> A-004..A-006 (libyears, trends) -> B-001 (EOL) -> C-001, C-002 (reports, Scorecard).
- Open: engineering-process scope (C-003..C-006) needs decisions on token and event sources; feed URLs/fields in A-001, A-002,
  A-004, B-001, B-002 are unverified until picked up. Do S-001/S-002 before C-001 widens the upload surface.

## 2026-10-15: H-001 Agent harness setup
- Done: added `AGENTS.md` (canonical), `CLAUDE.md` (imports it), `docs/ARCHITECTURE.md`, `docs/WORKFLOW.md`,
  `docs/features.json`, `docs/progress.md`, `scripts/init.sh`. Based on walkinglabs/learn-harness-engineering
  (instructions, state, verification, scope, session lifecycle).
- Verified: type-check and 32 unit/API tests green (first via `pnpm run`, later via `node_modules/.bin/tsc` and `vitest` because pnpm
  blocked). No code changed.
- Failed / blocked: a mid-session `pnpm install` failure (minimumReleaseAge) was caused by running on `main`, which has no
  `pnpm-workspace.yaml`/pnpm lockfile. On `build/pnpm` install, lint and tests pass (32 tests).
- Next: A-003 (see `features.json`).
- Gotchas: Dockerfile/compose intentionally run scripts with `npm` in the runtime stage; that is not a leftover from the pnpm
  migration. Do not commit `pnpm-lock.yaml` churn unrelated to a dependency change.

## 2026-11-02: Ship only needed Next files (build/next-standalone-image)
- Done: `output: 'standalone'`; Dockerfile split into `web` (standalone, `node server.js`) and `worker` (prod node_modules without
  `next`, runs worker and migrate); compose, release.yml and security.yml build/scan both; docs/kubernetes.md updated.
- Verified: `pnpm run build`; both targets build; web image has 54 `next/dist/compiled` entries (was 146), worker has no `next`;
  web serves `/icon.svg`, SIGTERM exits 143 like `next start` (same handler).
- Blocked before merge: `jsundquist/k8s-gitops` must point worker and migrate at `ghcr.io/jsundquist/sbom-worker` (add an
  `images` entry; the bump job updates it by name once present) and web's command is now `node server.js`. Merging first breaks the cluster worker.
- Gotcha: worker target removes `next` with `rm -rf node_modules/next node_modules/.pnpm/next@*`; revisit if pnpm layout changes.
