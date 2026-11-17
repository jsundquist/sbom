# Progress log

Newest first. Format and rules: `docs/WORKFLOW.md#progress-md-entry-format`.

## Current state

- Main has the full dashboard (upload, projects, packages, vulnerabilities, worker, CI hardening) and uses pnpm (#7).
- Baseline: owner-only auth (E-004..E-007) lives on `feat/owner-auth`; review fixes on `fix/owner-auth-review`. See the newest entries.
- Next: L-002 (pagination and filters; its dependencies G-001, G-002, G-003 and F-003 are done), which unblocks I-002 and the MCP tools, and G-004/G-005. Decide M-007 (local vs remote MCP) before M-002. The backlog order is in the 2026-11-16 backlog entry. Pick the lowest-priority `todo` in `docs/features.json` as usual.

## 2026-11-17: L-002 Pagination and filters on list endpoints
- Done (branch `feat/l-002-list-pagination`, off main; no migration): `parsePage`/`parse*Filter` in `src/lib/params.ts` (Zod), `src/server/list-filters.ts` (in-memory filters and `paginate`), `list{Projects,Packages,Vulnerabilities}Page` in `inventory.ts`, `listJson` in `server/api.ts` (bare array + `X-Total-Count`). The three list routes stay thin. Pages unchanged. Tests: `tests/unit/list-query.test.ts`.
- Verified: see commands in the final report; `pnpm run lint` and `pnpm test` green. `pnpm run test:e2e` NOT run (no Postgres available in this environment), so the ticket stays `in_progress`; no page changed.
- Next: run e2e where Postgres exists, then mark L-002 done. Unblocks I-002 and the MCP tools.
- Gotchas: blank params (`?kind=`) count as absent; `tag`/`ecosystem` match lower-case, `severity`/`kind` are case-insensitive; `q` is a case-insensitive substring (projects: name or repository; packages: name or key; vulns: id, summary or aliases). J-003 adds the scope filter later.

## 2026-11-17: G-003 Project tags
- Done (branch `feat/g-003-project-tags`, off main): `projects.tags` (jsonb string array, NOT NULL, default `[]`; migration `0010`, generated). `POST /api/v1/sboms` reads `tags` (comma-separated) from the query or `X-Sbom-Tags`; `parseTags` in `src/lib/tags.ts` trims, lower-cases, de-duplicates and validates (at most 20 distinct, each 1-40 of `a-z 0-9 : _ -`); a bad tag or too many is a 400 that names the problem. `ingestSbom` replaces the tags on every upload, so one that omits them clears them. `ProjectSummary.tags` is in `GET /api/v1/projects[/id]`. `TagChips`, a Tags column (a joined string, so quick search and the column filter match tag text) and chips on the project page. `action.yml` input `tags` (newlines become commas, so a multi-line input works and cannot inject headers; sent only when non-empty); README, example workflow and ARCHITECTURE updated. Demo data tags two projects. No UI or API edits tags.
- Verified: new `tests/unit/project-tags.test.ts` failed first (module missing), then 19 green; `pnpm run lint`, `pnpm test` (401) and `pnpm run test:e2e` (15, after a rebuild) green; the e2e overview row checks the `team:payments` tag.
- Decisions: the limit of 20 counts distinct tags after lower-casing, so duplicates never cause a 400. Invalid input is rejected rather than truncated, so a typo in CI is visible. Omitting `tags` clears them, matching `kind` and the CONTEXT.md "replaced on every upload".
- Not done: the Action's tags handling was only checked as a shell snippet, not in a real workflow; the Tags column filter was not exercised in a browser. G-004 (overview filters and group rollups) is now unblocked.
- Gotchas: e2e runs against the existing `.next` build, so rebuild first. L-002 (pagination and filters) now has all its dependencies (G-001, G-002, G-003, F-003) done.

## 2026-11-17: G-005 Sibling Projects
- Done (branch `feat/g-005-sibling-projects`, off main): `getSiblingProjects(db, projectId)` in `src/server/inventory.ts` returns the other Projects with the same normalised repository, by name, as `ProjectSummary` (kind and severity counts included); nothing for a Project with no usable repository. It reuses `listProjects(db, { repository })` from G-002, so it loads only that repository's SBOMs and matches rows stored in an older spelling. `SiblingProjects` renders "Other projects in <repository>" on the project page (name link, kind chip, severity counts) and nothing when there are none. The Projects grid has a Repository column (replacing the caption under the name) so it filters and sorts by repository. No schema change, no API change, no DataGrid Pro grouping.
- Verified: new `tests/unit/sibling-projects.test.ts` failed first, then 6 green; `pnpm run lint`, `pnpm test` (392) and `pnpm run test:e2e` (16, after a rebuild) green. The new e2e test uploads three Projects through the API (two spellings of one remote and one elsewhere) and checks the sibling list, the click-through and the Repository column.
- Decisions: page only, not `GET /api/v1/projects/[id]`; `?repository=` on the list endpoint already answers the same question for scripts. A Project whose stored repository text cannot be normalised has no siblings rather than matching on raw text.
- Not done: the Repository column filter was not exercised in a browser.
- Gotchas: chose G-005 over G-006 (higher priority) because G-006 adds a migration and would collide with G-003's `0010` while #74 is open.

## 2026-11-17: M-001 mcp/ scaffold
- Done (branch `feat/m-001-mcp-scaffold`, off main): `mcp/` is a stdio MCP server over `/api/v1` with its own `package.json`, lockfile and `pnpm-workspace.yaml`. `src/config.ts` is the one place that reads `DASHBOARD_URL`, `DASHBOARD_READ_TOKEN` (and `DASHBOARD_TIMEOUT_MS`); `src/client.ts` is a GET-only bearer client with `AbortSignal.timeout`, an injectable `fetch` and a Zod schema per call; `src/server.ts` registers one `ping` tool (GET `/api/v1/summary`); `src/index.ts` wires stdio. `@modelcontextprotocol/sdk` 1.32.2 pinned exactly (latest, published 2026-10-23, past `minimumReleaseAge`). ESLint `no-restricted-imports` for `mcp/**` blocks `@/` and `src/` paths; the root `tsconfig.json` and `.dockerignore` exclude `mcp/`. New CI job `mcp` (own lockfile, audit, typecheck, build, test) and a Dependabot entry for `/mcp`. README section with a Claude Code / Claude Desktop config; ARCHITECTURE updated.
- Verified: `mcp/tests` (12) and `tests/unit/mcp-isolation.test.ts` (4, lints a bad import as if in `mcp/`) failed first, then green; `pnpm run lint` and `pnpm test` (344) green; in `mcp/`: typecheck, build, `pnpm test` (12) and `pnpm audit --prod` clean; `docker build --target web .` succeeded with `Dockerfile`, root `pnpm-lock.yaml` and root `pnpm-workspace.yaml` unchanged. Not run: e2e (`src/` untouched), the built binary in a real MCP client, the CI job on GitHub, the worker image target.
- Decisions: not a workspace member. Joining would add `mcp/` to the root lockfile, and the Dockerfile installs with `--frozen-lockfile` from only the root manifests, so the app image build would break or need an extra COPY. Standalone means two lockfiles to keep current (Dependabot covers both) and `mcp/` repeats the supply-chain settings in its own `pnpm-workspace.yaml`. The smoke test drives the real `StdioServerTransport` over in-memory streams (newline-delimited JSON-RPC) rather than spawning a process, so the fake `fetch` can be injected.
- Next: M-002 adds the real tools once G-003 and L-002 land; it needs the project lookup by git remote (G-002).
- Gotchas: `mcp/` must be built (`pnpm run build`) before a client can run `dist/index.js`. The root ESLint lints `mcp/**` type-aware through `mcp/tsconfig.json`; the root lint and the isolation test also pass with `mcp/node_modules` absent (checked), as in CI's root job. stdout carries the protocol; never `console.log` in `mcp/src`.


## 2026-11-17: G-002 Normalise repository
- Done (branch `feat/g-002-normalise-repository`, off main): `normalizeRepository()` in `src/lib/repository.ts` turns https/http/git/ssh URLs, `.git`, trailing slash, `git@host:path`, ports, credentials and a bare `owner/repo` into `host/path` (`github.com/owner/repo`). `ingestSbom` stores it (COALESCE kept, so an upload without one keeps the old value). `projects.repository` is indexed (migration `0009`, generated). `GET /api/v1/projects?repository=` normalises the input (400 if it is not a repository) and also matches the old raw spellings (`legacyRepositoryForms`, case-insensitive) until a Project is re-uploaded. README and ARCHITECTURE updated.
- Verified: new `tests/unit/repository.test.ts` failed first (module missing, index test red), then green; `pnpm run lint`, `pnpm test` (382) and `pnpm run test:e2e` (15) green. `api.test.ts` now expects `github.com/acme/web` where it expected `acme/web`.
- Decisions: a dotted first segment is a host, otherwise two segments are `owner/repo` on GitHub (owners cannot contain dots). GitHub paths are cut to owner/repo and lowercased; other hosts keep path case and only lowercase the host. An unparseable upload value is ignored (old value kept), but an unparseable `?repository=` is a 400. `listProjects(db, { repository })` loads components only for the matched Projects.
- Not done: no backfill (ADR 0004). The legacy match uses `lower(repository)`, so it cannot use the new index; the table is small. Drop that arm once old rows are gone. The Action was not run in a real workflow.
- Gotchas: M-002 should pass the git remote straight to `?repository=`; no client-side normalising needed. The migration is a plain `CREATE INDEX` in a transaction and briefly blocks writes to `projects`.

## 2026-11-17: J-001 Research: prod-only SBOM from Syft
- Done (branch `docs/j-001-prod-only-sbom`, off main): `docs/research/prod-only-sbom.md`, linked from J-002's notes. Syft 1.57.1 emits no `scope` and its `javascript.include-dev-dependencies` setting has no effect on pnpm lockfile scans; `pnpm install --prod` does not help because Syft reads `pnpm-lock.yaml`. Recommendation: derive the prod set with `pnpm sbom --sbom-format cyclonedx --lockfile-only --prod` and stamp CycloneDX `scope` into the document in the Action (excluded = dev, required = runtime, absent = unknown), not into a header.
- Verified: measured, not estimated. Checkout: 655 components full (628 npm); pnpm gives 628 all, 266 prod, 369 dev (80 in both); Syft and pnpm purls identical. Images from the repo Dockerfile: web 1,460, worker 1,870, build stage 5,121 (293 dev npm packages; none in web or worker). Docs only, so lint and tests not required.
- Not done: the Action in a real workflow, the Syft version inside `anchore/sbom-action` v0.24.3, npm and yarn projects, the stamping step itself, Syft release notes.
- Gotchas: the ticket's "1,975 components" did not reproduce (a clean checkout is 655). The 55 Next-vendored npm purls in the web image are not in the lockfile and stay `unknown`. `pnpm sbom` needs pnpm on the runner.

## 2026-11-17: L-001 READ_TOKENS
- Done (PR #67, off main): `READ_TOKENS` (comma-separated) in `src/lib/env.ts`, `.env.example`, README and docker-compose. One `checkReadToken(req)` in `src/server/api.ts` returns null (not a read-token attempt), `'ok'` or a rejection; `proxy()` calls it before the session gate and `requireOwner()` calls it before `ownerState`. It applies only to `GET /api/v1/*` with an `Authorization` header and a configured list. Pages (`requireOwnerPage`), `/api/auth/*`, writes and sessions are untouched, so a read token opens nothing else and sessions still ignore `Authorization`. `docs/ARCHITECTURE.md#security` updated. No schema change.
- Verified: new `tests/unit/read-token.test.ts` failed first (5 of 17), then green; page-guard test added to `tests/unit/page-auth.test.ts`; `pnpm run lint`, `pnpm test` (326) and `pnpm run test:e2e` (15) green. The new authed e2e test checks read token 200, wrong token 401, DELETE and POST not opened, and the page still showing sign-in.
- Decisions: a present but wrong bearer gets 401 and never falls back to the session gate; with no `READ_TOKENS` a bearer is ignored. The auth bucket is checked before comparing and spent only by failures, so guessing is throttled (429, even for a correct token) and a busy script does not throttle itself. Production fail-closed comes from the unchanged session gate.
- Not done: `/metrics` (L-004). The e2e DELETE check expects 503, not 401, because the e2e server has no `ADMIN_TOKENS`.
- Gotchas: without `TRUST_PROXY` all clients share one auth bucket, so failed token guesses can also throttle owner sign-in; set `TRUST_PROXY` behind a proxy. Rotating a token is a redeploy. ESLint now ignores `.claude/**`: agent worktrees under `.claude/worktrees/` made `pnpm run lint` fail from the main checkout (Prettier and git already ignored them).

## 2026-11-17: I-001 aggregateUpgrades()
- Done (PR #66, off main): `aggregateUpgrades(list, graphs?)` in `src/server/inventory.ts` returns `{ upgrades, unfixed }`. Per package version, `sameMajor` is the lowest fixed version in the current major that clears the most CVEs and `clearsAll` the lowest that clears every CVE (null when any CVE has no fix); each carries the CVEs cleared and the affected Projects. Transitives report their immediate `parents` and the shortest `path` from a direct dependency, with no claim that upgrading the parent drops the package. Packages with no fixed version go in `unfixed`. No schema change, route or UI (I-002).
- Verified: new `tests/unit/upgrades.test.ts` failed first (13 of 13), then 14 green, one on PGlite with the SPDX graph fixture; `pnpm run lint` and `pnpm test` (322) green. Not run: e2e (nothing visible changed).
- Decisions: prereleases and fixes at or below the current version are never targets. Risk is summed over the CVEs the ranked target clears (`sameMajor`, else `clearsAll`) and compared by KEV count, then EPSS, then summed severity rank, then CVSS, in its own comparison because `comparePriority` takes single CVEs, not sums.
- Open: because severity rank is summed, three mediums outrank one critical, and a test pins that. It follows the ticket's "summed over cleared CVEs" but may not be the ranking wanted; decide before I-002 shows it (worst-CVE-first is the alternative).
- Gotchas: the graphs argument is optional so the function stays pure; the caller loads `getDependencyGraph` per Project (ADR 0005 keeps scoped in-memory loads).

## 2026-11-17: Q-006 Clear stale Next types
- Done (PR #65, off main): `scripts/init.sh` runs `rm -rf .next/types .next/dev/types` before the type-check, so a `.next/` left by another branch no longer turns the session-start baseline red.
- Verified: reproduced with a fabricated stale `.next/types/validator.ts` (`pnpm run typecheck` failed TS2307), then `scripts/init.sh` green (tsc, eslint, prettier, 308 tests). Not run: `next build` and `next dev` (no Next config changed; Next regenerates the types).
- Decisions: clear in `init.sh` rather than excluding `.next` in `tsconfig`, because an exclude would also stop `next build` validating route types.
- Gotchas: a bare `pnpm run lint` with a stale file still fails; only `init.sh` clears it, which is what the session-start protocol runs.

## 2026-11-17: G-001 Project kind
- Done (branch `feat/g-001-project-kind`, off main): `projects.kind` (`project_kind` enum: application, library, image, host; NOT NULL, default application; migration `0008`, generated). `POST /api/v1/sboms` reads `kind` from the query or `X-Sbom-Kind`, validated by Zod against `PROJECT_KINDS` in `src/lib/kinds.ts` (400 otherwise); `ingestSbom` replaces it on every upload, so an upload that omits it resets to application. `ProjectSummary.kind` is in `GET /api/v1/projects[/id]`. `KindChip`, a Kind column (singleSelect, so the grid's filter works) and a chip on the project page. `action.yml` input `kind` (empty means application, or image when `image` is set); README, example workflow and ARCHITECTURE updated. UI headers, nav and e2e say Project; Application appears only as a kind value.
- Verified: new `tests/unit/project-kind.test.ts` failed first (7 of 7), then green; `pnpm run lint`, `pnpm test` (308) and `pnpm run test:e2e` (14) green.
- Decisions: Postgres enum rather than text so the database also rejects bad values (adding a kind is a one-line migration). No backfill: the column default makes old rows read as application.
- Not done: the Kind filter was not exercised in a browser; the Action's kind logic was not run in a real workflow. `W-006` should send `kind=host`.
- Gotchas: e2e runs against the existing `.next` build, so rebuild after any UI string change or it fails on stale text. Without a local Postgres, run one with `docker run -p 5433:5432 -e POSTGRES_USER=sbom -e POSTGRES_PASSWORD=sbom -e POSTGRES_DB=sbom_e2e postgres:16` and set `E2E_DATABASE_URL` and `DATABASE_URL`.

## 2026-11-16: K-001 Cheaper whole-inventory reads
- Done (branch `perf/k-001-whole-inventory-reads`, off main): `loadComponents` in `src/server/inventory.ts` no longer joins package, version and vulnerability facts onto every component row. It reads the components' own columns, loads the package, version and vulnerability facts from the small tables by package key (blocks of 5,000), and works out everything that depends only on a `package@version` once and shares it (28k versions cover 200k components). No schema change, no worker job, no migration.
- Verified: new `tests/unit/load-components-golden.test.ts` pins the old output (and its four scopes) and was committed first; the refactor reproduces it exactly. `pnpm run lint` and `pnpm test` (301) green. On the 100 x 2,000 x 20 dataset: projects grid 1,672 -> 729 ms, overview 1,898 -> 911, vulnerabilities 1,629 -> 725, packages 1,817 -> 906 (target 1,000); peak RSS 1,208 -> 838 MB (target 1,024).
- Decisions: chose a cheaper load over per-project rollups because profiling showed repeated work, not row volume, was the cost (query 1 630 ms, query 2 553 ms, per-row `updateType`/`maintenanceFlags` 334 ms; 28k distinct versions). ADR 0005 has an update saying so; rollups remain the next step if a page goes over again. L-004 no longer depends on K-001 and reads `listProjects`.
- Not done: the margin on the overview and packages grid is about 9%, on an M1 Pro with Postgres local; a smaller server will be slower. Remaining cost: ~235 ms to move the component rows, ~250 ms in `aggregatePackages`, the per-row object spread. One-subject pages got ~20 ms slower (separate queries instead of one join), still far under 500 ms.
- Gotchas: the golden test caught a flaw in my own first version of it: scope subjects were picked from load order, which is whatever the database returns and differs between the old and new queries. They are now picked from the id-sorted list. Do not join per-package facts back onto the component query. `UPDATE_GOLDEN=1` regenerates the golden file on purpose; review the diff.

## 2026-11-16: F-006 Index component_edges foreign keys
- Done (branch `perf/f-006-edge-indexes`, stacked on the F-004 branch): `component_edges` is now indexed on `parent_id` and `child_id` (migration `0007`, generated). Both are cascading foreign keys to `components`; without an index, pruning an old SBOM scanned every edge once per deleted component.
- Verified: new `tests/unit/schema-indexes.test.ts` failed first, then green; `pnpm run lint` and `pnpm test` (299) green. Re-seeded 100 x 2,000 x 20 through the migration and measured uploads: 383 ms identical re-upload, 377 ms with 5 components changed (were over 120 s); database 1.26 -> 1.45 GB. Numbers are in `docs/benchmark.md`.
- Decisions: indexes, not dropping the redundant cascades (edges are always deleted with their own SBOM, but the foreign keys also guard integrity, and the indexes are the smaller change).
- Gotchas: the migration runs in a transaction, so `CREATE INDEX` is not concurrent and blocks writes to `component_edges` while it builds: seconds at today's size, minutes at the benchmark size. Run the migrate Job when no upload is in flight.

## 2026-11-16: E-009 Batch deploys
- Done (branch `ci/batch-release-deploys`, off main): `release.yml` now runs on `cron: '17 */4 * * *'` and `workflow_dispatch` instead of every push to `main`, so a burst of merges becomes one `chore(sbom): deploy` commit in `jsundquist/k8s-gitops`. A new `changes` job decides: a scheduled run releases only if GHCR has no image tagged `<short-sha>-*` for the head of `main`; a manual run always releases; any run from a branch other than `main` fails before building. `image` and `token-expiry` wait on it; `sign`, `bump` and `prune` follow `image`.
- Verified: the decide step's script, extracted with `yq`, against a fake `gh` for 7 cases (see the E-009 evidence in `features.json`); `zizmor --offline`, `actionlint` and `prettier` clean. Not run: a real workflow run on GitHub.
- Decisions: "already released" is read from GHCR, not from the GitOps repo (a rollback there would be undone at the next tick) and not from the last successful run (`token-expiry` fails by design for 14 days before the token expires, which would rebuild every tick). Manual runs are restricted to `main` because the cosign identity in `SECURITY.md` pins `refs/heads/main` and `bump` pushes to production.
- Not done: `sbom.yml` still uploads this repo's SBOM to the dashboard on every push (it does not touch the GitOps repo). Skipping releases whose only changes are docs, tests and scripts is a possible follow-up.
- Gotchas: after merging, run the workflow by hand once (Actions > Release image > Run workflow on `main`) to confirm the GHCR lookup works with `GITHUB_TOKEN` and `packages: read`; if it fails the `changes` job goes red with the API error. A scheduled run on an unchanged `main` is green with every other job skipped.

## 2026-11-16: F-004 Scale benchmark
- Done (branch `feat/f-004-benchmark`, off main): `scripts/benchmark-seed.ts` (deterministic synthetic data: packages, versions, vulnerabilities with KEV and EPSS, Projects with 20 SBOMs each, edges, 90 days of snapshots) and `scripts/benchmark.ts` (`pnpm run bench seed|measure [--only reads|uploads]`, `BENCH_DATABASE_URL` only, refuses a database that already has Projects). Results, targets and decision rules are in `docs/benchmark.md`.
- Verified: new `tests/unit/benchmark-seed.test.ts` failed first (module missing), then 4 green; `pnpm run lint` and `pnpm test` (289) green. Ran the real thing on Postgres 16: 100 Projects x 2,000 components x 20 SBOMs in 163 s (4.0M component rows, 4.3M edges, 1.26 GB).
- Findings: (1) the projects grid, overview, vulnerabilities grid and packages grid take 1.6-1.9 s against a 1 s target, peak RSS 1,208 MB against 1,024, and all four are bound by one `loadComponents()` of ~200k rows (1.7 s; aggregation is 8-255 ms). (2) Uploads do not finish within 120 s as the schema ships: pruning the oldest SBOM cascades to components, and the foreign keys from `component_edges` have no index, so each deleted component scans every edge. With two indexes an upload takes ~410 ms. (3) Single-subject pages are fast (6-27 ms).
- Decisions: K-001 is built and rescoped to all four pages (per-project rollups alone would not fix the packages and vulnerabilities grids); K-002 and K-003 are `superseded` (upload is fine once indexed; 1.26 GB against 5 GB); new ticket F-006 for the indexes, ahead of K-001.
- Not done: the worker at this size, concurrent requests, browser rendering, a tuned Postgres (listed in `docs/benchmark.md`).
- Gotchas: run `measure` in a fresh process after `seed`, or the memory figure includes seeding. A statement timeout surfaces as `error.cause.code === '57014'` because drizzle wraps driver errors. The uploads add SBOMs to the throwaway database, so reseed an empty one before comparing runs. Rebased onto main after F-003 merged (#59); the only conflict was the Next line in this file.

## 2026-11-16: F-003 Stale SBOM flag
- Done (branch `feat/f-003-stale-sbom`, off main after F-002 merged in #58): `STALE_AFTER_DAYS` (default 14, `0` disables); `isStale()` in `src/lib/stale.ts`; `ProjectSummary.stale` and `getOverview().staleProjects`, both derived at read time (nothing stored). `StaleChip` on a new sortable boolean Stale column of the projects grid, beside "uploaded" on the project page, and as an "N stale" chip in the overview's Applications tile. The flag also appears in `GET /api/v1/projects[/id]`.
- Verified: new `tests/unit/stale.test.ts` failed first (module missing), then 8 green; `pnpm run lint`, `pnpm test` (293) and `pnpm run test:e2e` (14) green. Also checked on the built app with one project backdated 30 days (overview tile, project page chip, API flag, no chip on a fresh project).
- Decisions: older than the threshold means strictly greater (exactly 14 days is not stale). The chip describes the latest SBOM, so it shows even when an older SBOM from history is being viewed. A project with no SBOM is never stale.
- Not done: the grid's Stale column was not checked in a browser (client-rendered DataGrid; the e2e seed has no old uploads). Missing `commit_sha`/`ref` is a separate, smaller signal left out of scope by the ticket. No filter yet: L-002 adds `?stale=` to the list API.
- Gotchas: F-002 was squash-merged while this branch was stacked on it, so the branch was rebased with `git rebase --onto origin/main <old F-002 commit>`; a plain rebase would have replayed the F-002 commit.

## 2026-11-16: F-002 ADMIN_TOKENS for delete
- Done (branch `feat/f-002-admin-tokens`, off main): `DELETE /api/v1/projects/[id]` now needs a token from `ADMIN_TOKENS`; an upload token gets 401 and an admin token cannot upload. `checkUploadToken` and the new `checkAdminToken` share one `checkBearer` (same rate-limit bucket, same fail-closed rule: 503 in production when the list is empty unless `ALLOW_OPEN_UPLOADS=true`). Env, `.env.example`, compose, README, kubernetes.md, ARCHITECTURE and WORKFLOW updated.
- Verified: new `tests/unit/admin-token.test.ts` failed first (5 of 8), then passed; `pnpm run lint`, `pnpm test` (285) and `pnpm run test:e2e` (14) green.
- Decisions: reused `ALLOW_OPEN_UPLOADS` as the single "open writes in production" switch rather than adding a second flag. The proxy allow-list is unchanged (method + exact path); only the token it checks differs.
- Breaking change: anything that deleted with an upload token now gets 401 (503 in production with no `ADMIN_TOKENS`). Set `ADMIN_TOKENS` on the web deployment before upgrading.
- Gotchas: e2e needs `pnpm exec playwright install chromium` after a Playwright bump (the browser build is versioned), and reads `E2E_DATABASE_URL`. The existing delete test in `api.test.ts` passed by accident (deletes were open with no admin token); it now sends an admin token.

## 2026-11-16: F-001 null-version key collision
- Done (branch `fix/f-001-null-version-key`, off main): `componentKey` in `src/sbom/parse.ts` now gives a missing version an empty suffix (`npm:leftpad@`) instead of the text `null`, so it no longer collides with a component whose version is the string "null". Before, `dedupe()` silently dropped one of the two.
- Verified: new `tests/unit/component-key.test.ts` failed first (2 of 4), then passed; `pnpm run lint` and `pnpm test` (277) green. Not run: e2e (no page or route change).
- Decisions: versioned keys are unchanged (`name@1.2.3`). Keys are in-memory only (dedupe, edge resolution in ingest), so nothing stored needs migrating.
- Gotchas: the empty suffix is safe because `normalize()` turns an empty version into null, so no real version is empty.

## 2026-11-16: Backlog from the codebase review (docs only)
- Done (branch `docs/spec-hierarchy-consumption-mcp`, off main): a review of what the code structure is missing, grilled into 21 decisions and written up as ADRs 0002-0005, new CONTEXT.md terms (Project, Kind, Repository, Tag, Read token, Admin token, Stale SBOM, Scope, Upgrade, Rollup) and 35 tickets in `docs/features.json`. No code changed.
- New epics: F foundations and trust, G organising Projects, I remediation, J dependency scope, K scale, L consuming the data (read tokens, pagination, CSV, `/metrics`, OpenAPI), M MCP server, N audit. Priorities 1-12 run ahead of the old `todo` items; four deferred ideas sit at 40+ labelled `needs-triage`.
- Order: F-001..F-004 (bug, `ADMIN_TOKENS`, stale flag, 100-Project benchmark), then K (only what the benchmark justifies), G, L, N, I/J, M.
- Decisions: single Owner stays; scale target is about 100 Projects x 2,000 components (this repo's own Syft SBOM is 1,975); repository is a column, not a table; kind and tags come from the Action on every upload, no UI editing; read tokens and admin tokens are env vars; MCP v1 is read-only over tracked data. A-004 marked `superseded`.
- Corrections found while grilling: Syft emits no dependency scope, so J-001 researches how to get one; `check_before_adding` and `diff_working_tree` cannot be read-only (the app may not call OSV), so they became M-006 instead of MCP v1; the list routes take no query params today.
- Verified: `features.json` parses, ids unique, every `depends_on` exists, no dependency cycles, F-001 is the first ready ticket. Not run: `pnpm test` (no code changed).
- Not done: the Action inputs, schema and API are all unbuilt. UI wording still says "Application"; G-001 changes it.

## 2026-11-15: Node 26 upgrade
- Done (branch `build/node-26`, off main): Dockerfile build and distroless runtime stages, CI and security workflows, `engines`, README/AGENTS and `.trivyignore` moved from Node 22 to 26. Dependabot's docker `node` entry ignores odd majors (25.x, 27.x, ...). Supersedes Dependabot PR #43 (25, failed `image-scan`).
- Verified: `pnpm run lint` and `pnpm test` (273) green, but on local Node 24. Not run locally: docker build (daemon down) and e2e; CI's `image-scan` and `test` jobs on Node 26 are the evidence.
- Gotchas: Node 25+ ships no corepack, so the Dockerfile runs `npm install --global corepack` first. `.trivyignore` entries were for the 22 distroless digest; drop them if the 26 image is clean (they expire 2026-11-22).

## 2026-11-08: A-006 Trend charts
- Done (branch `feat/a-006-trend-charts`, stacked on `feat/a-005-daily-snapshots`): `getProjectTrend` / `getSummaryTrend` in `src/server/trends.ts`, routes `GET /api/v1/projects/[id]/trends` and `/summary/trends`, `VulnerabilityTrendChart` on the overview and application pages.
- Verified: `pnpm run lint`, `pnpm test`, `pnpm run test:e2e` (14: populated via the seeded worker run, empty via an API upload) green.
- Decisions: the summary carries each project's last snapshot forward, so a day the worker missed one project does not drop it from the total. `?days` is a window ending today, default 90, clamped to 1..365. Lines, not stacked areas, so a single day still shows as dots.
- Not done: outdated/libyears charts (snapshots store the counts, nothing plots them yet).

## 2026-11-08: A-005 Daily snapshots
- Done (branch `feat/a-005-daily-snapshots`, off main): `project_snapshots` (unique project + UTC day; components, vulnerable components, distinct vulnerabilities by severity, outdated total and major); `snapshotCounts()` in `src/lib/snapshot.ts`; `writeSnapshots()` in `src/worker/snapshots.ts` runs last in every `enrich()`.
- Verified: `pnpm run lint` and `pnpm test` (239, new `snapshots.test.ts`) green. Not run: e2e (no page or route change).
- Decisions: built without A-004, so no libyears column. Keyed by project, not SBOM, so pruning cannot delete it. "On upload" is the NOTIFY-woken enrich run; with the worker down no snapshot is written.
- Not done: KEV/exploited count, backfill (not required), any read API (A-006).
- Gotchas: migration is `0006` (after B-003's `0004` and B-002's `0005`); a new `0004`-numbered file would clash with the journal.

## 2026-11-08: B-002 Deprecated and abandoned packages
- Done (branch `feat/b-002-abandoned-packages`, off main): `packages` gains `latest_released_at`, `deprecated`, `deprecated_reason`, filled by the existing latest-version job from the same deps.dev call (`publishedAt`, `isDeprecated`, `deprecatedReason`); `maintenanceFlags()` in `src/lib/maintenance.ts` derives `abandoned` at read time from `ABANDONED_AFTER_YEARS` (2); `MaintenanceChip` on the packages grid (sortable column) and package page.
- Verified: `pnpm run lint`, `pnpm test` (238), `pnpm run test:e2e` (13) green; deps.dev fields checked live (`request` is deprecated, with a reason).
- Decision: did not build A-004 first. B-002 only needs the latest version's publish date, so there is no libyears and no per-version `released_at`; the ticket's dependency is satisfied without it.
- Gotchas: a package with an unknown release date is never abandoned. A failed lookup keeps the last known date and deprecation. The chip shows nothing for maintained packages.
- Not done: abandoned/deprecated counts on the overview, and the per-component grid.

## 2026-11-08: B-003 OpenSSF Scorecard per package
- Done (branch `feat/b-003-scorecard`, off main): `packages` gains `source_repo`, `scorecard_score`, `scorecard_checks`, `scorecard_checked_at`, `scorecard_error` (migration 0004); worker job `checkScorecards` runs after the latest-version check (latest version -> deps.dev `relatedProjects` SOURCE_REPO -> `/v3/projects/<repo>` scorecard) on `SCORECARD_TTL_HOURS` (168); `getPackage` returns `scorecard {status, score, sourceRepo, weakest[3], checkedAt}`; Scorecard tile on the package page.
- Verified: `pnpm run lint`, `pnpm test` (242, new `scorecard.test.ts`), `pnpm run test:e2e` (13) green. Live deps.dev shapes checked with curl (lodash: SOURCE_REPO + scorecard.overallScore/checks).
- Gotchas: e2e reads `E2E_DATABASE_URL`, not `DATABASE_URL`. The demo seed runs enrichment, so seeded packages show "No source repository or scorecard found". Scorecard `-1` means a check could not run and is excluded from "weakest". A failed lookup keeps the last good score and stays due, so it retries next run (it is not marked checked).
- Not done: Scorecard in the packages grid or overview; packages whose source repo is not on a host Scorecard covers show as unsupported.

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
