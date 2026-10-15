# SBOM Dashboard: agent operating manual

Next.js + MUI dashboard for SBOMs, with a separate worker that enriches packages from OSV.dev and deps.dev.
This file is the entry point for any coding agent. `CLAUDE.md` imports it. Keep it short; details live in `docs/`.

## Session start (do this first, every session)

1. Read this file, then `docs/progress.md` (what happened last, what is next) and `docs/features.json` (scope).
2. Run `scripts/init.sh`. It installs deps, type-checks and runs unit tests. If it fails, fix that before new work.
3. Run `git log --oneline -10` and `git status`. Do not build on a dirty or red baseline without saying so.
4. Pick **one** feature (`status: "todo"` or `"in_progress"`, lowest `priority`) whose `depends_on` are all `done`. Do not start a second.

## Where things are

| Need | Read |
|---|---|
| Components, data flow, schema, invariants | `docs/ARCHITECTURE.md` |
| How to add a feature, endpoint, page, migration | `docs/WORKFLOW.md` |
| Definition of done and verification commands | `docs/WORKFLOW.md#definition-of-done` |
| Session log and handoff | `docs/progress.md` |
| Feature scope and status | `docs/features.json` |
| Security posture and open hardening items | `docs/ARCHITECTURE.md#security` |

## Commands (pnpm only, Node 22+)

| Command | Purpose |
|---|---|
| `pnpm run lint` | Type-check (`tsc`, TypeScript 6), ESLint and Prettier check; CI runs the same three on every push |
| `pnpm run format` | Prettier write; run it before committing (`format:check` is what CI enforces) |
| `pnpm test` | Vitest unit and API tests on in-process PGlite, no Postgres needed |
| `pnpm run test:e2e` | Playwright; needs Postgres (`DATABASE_URL`) and a build |
| `pnpm run db:generate` | Generate a migration after editing `src/db/schema.ts` |
| `pnpm run db:migrate` / `db:seed` | Apply migrations / load demo data |
| `pnpm run dev` / `pnpm run worker` | Web app on :3000 / enrichment worker |

## Layering rules (enforce these)

- `src/db/schema.ts` is the single source of truth for tables. Never hand-edit `drizzle/*.sql` or `drizzle/meta`; regenerate.
- Dependency direction: `app/` and `components/` -> `server/` -> `db/` + `lib/`. `worker/` -> `db/` + `lib/`. `lib/` and `sbom/` import nothing from `server/`, `worker/`, `app/`.
- Route handlers (`src/app/api/v1/**/route.ts`) stay thin: validate input, call a function in `src/server/`, return JSON. No SQL in routes, pages, or components.
- Reads go through `src/server/inventory.ts`; writes through `src/server/ingest.ts`. Pages and API routes share these functions.
- The app and worker communicate **only through Postgres** (tables plus `NOTIFY sbom_uploaded`). The app must never import worker enrichment to run it; the worker must never call app routes.
- All external input is validated with Zod (env in `src/lib/env.ts`, upload metadata, SBOM documents, OSV/deps.dev responses). Read config via `env()`, never `process.env` directly.
- External HTTP only from `src/worker/`, always through the injectable `FetchFn` so tests can fake it. Tests never hit the network.

## Code style

- TypeScript strict. ESLint enforces braces on every `if` (so `return` is never inline) and handled promises; Prettier owns formatting.
- TypeScript stays on 6.x until typescript-eslint supports 7 (tracked in typescript-eslint#10940); Dependabot ignores TS majors.
- Match the surrounding code: terse comments that explain why, `@/` path alias for `src/`.
- New dependencies need a reason in the PR/commit; keep the supply-chain posture (pinned actions, `pnpm audit` in CI).

## Commits

Conventional Commits with a scope: `feat(vulns): ...`, `fix(ingest): ...`, `docs(arch): ...`. One feature per commit/PR.

## Done means verified

Never report a feature complete from reading code. Run `pnpm run lint && pnpm test` (plus `pnpm run test:e2e` when UI or
routes changed), record the evidence in `docs/progress.md`, and set the feature status in `docs/features.json`.
See `docs/WORKFLOW.md`.

## Session end

Update `docs/progress.md` (done, failed, next, gotchas) and `docs/features.json`. Leave the tree green and committed, or
state clearly in `progress.md` why it is not. Do not commit `pnpm-lock.yaml` churn unrelated to a dependency change.
