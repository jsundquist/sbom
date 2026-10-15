# Progress log

Newest first. Format and rules: `docs/WORKFLOW.md#progress-md-entry-format`.

## Current state

- Main has the full dashboard (upload, projects, packages, vulnerabilities, worker, CI hardening) and uses pnpm (#7).
- Baseline: `pnpm run lint` and `pnpm test` pass (32 unit/API tests). `scripts/init.sh` passes on main; e2e not run.
- Next: pick the lowest-priority `todo` in `docs/features.json`.

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
- Next: A-002, then A-003 (see `features.json`).
- Gotchas: Dockerfile/compose intentionally run scripts with `npm` in the runtime stage; that is not a leftover from the pnpm
  migration. Do not commit `pnpm-lock.yaml` churn unrelated to a dependency change.
