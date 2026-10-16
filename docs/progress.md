# Progress log

Newest first. Format and rules: `docs/WORKFLOW.md#progress-md-entry-format`.

## Current state

- Main has the full dashboard (upload, projects, packages, vulnerabilities, worker, CI hardening) and uses pnpm (#7).
- Baseline: `pnpm run lint` and `pnpm test` pass (32 unit/API tests). `scripts/init.sh` passes on main; e2e not run.
- Next: pick the lowest-priority `todo` in `docs/features.json`.

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
