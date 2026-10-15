# Feature workflow

One feature at a time, verified before it is called done. Scope lives in `docs/features.json`; state lives in
`docs/progress.md`.

## The loop

1. **Select.** Take one entry from `docs/features.json` (lowest `priority` that is not `done`). Set it `in_progress`.
   If the work is not in the list, add an entry first (id, title, acceptance criteria) so scope is explicit.
2. **Understand.** Read `docs/ARCHITECTURE.md` and the files the feature touches. Check the layering rules in `AGENTS.md`.
3. **Test first** where logic is involved (`mattpocock-skills:tdd`): write a failing unit/API test using
   `createTestDb()` and `fakeFetch()` from `tests/unit/helpers.ts`.
4. **Implement** along the checklist below for the kind of change.
5. **Verify** with the commands in the Definition of Done. If anything fails, fix and re-run the whole set.
6. **Record.** Update `docs/features.json` (status, `evidence`), `docs/progress.md` (entry at the top), and
   `docs/ARCHITECTURE.md` if structure, schema, flows or decisions changed.
7. **Commit** one Conventional Commit with scope. Leave the tree green.

If you discover unrelated problems, add them to `docs/features.json` as `todo`; do not fix them in this change.

## Checklists by change type

### New or changed table/column
- [ ] Edit `src/db/schema.ts`
- [ ] `pnpm run db:generate`; commit the new `drizzle/*.sql` and `drizzle/meta/*`
- [ ] Check `garbageCollect()` and cascade behavior still hold
- [ ] Update the data model table in `docs/ARCHITECTURE.md`

### New read endpoint or page
- [ ] Add the query in `src/server/inventory.ts` returning a typed shape (no SQL elsewhere)
- [ ] Route handler in `src/app/api/v1/<name>/route.ts`: thin, `NextResponse.json`, `jsonError` for failures, `parseId` for ids
- [ ] Page in `src/app/<name>/page.tsx` with `export const dynamic = 'force-dynamic'`; call the same server function
- [ ] Link helpers in `src/lib/routes.ts`; nav entry in `src/components/NavBar.tsx` if top-level
- [ ] API test in `tests/unit/api.test.ts`; e2e journey in `tests/e2e/dashboard.spec.ts` if user-visible

### New write endpoint
- [ ] Call `checkUploadToken(req)` first
- [ ] Validate all input with Zod; enforce size limits
- [ ] Logic in `src/server/`, transactional, ends with `garbageCollect` if it removes rows
- [ ] Tests for success, 400, 401/503, and 413 paths

### Worker / enrichment change
- [ ] External calls go through `FetchFn` and a Zod schema for the response
- [ ] Failures are recorded per row (`*_error`), never thrown past `enrich()`'s per-job guard
- [ ] Cover with `fakeFetch()`; assert on `calls` to prove no extra network traffic
- [ ] Idempotent: re-running with no new work changes nothing

### New environment variable
- [ ] `src/lib/env.ts` schema, `.env.example`, README config table, `docker-compose.yml` if needed

### New UI component
- [ ] Presentational component in `src/components/`; data fetched in the page, passed as props
- [ ] Reuse `chips.tsx`, `grid.tsx`, `StatTile.tsx`, `PageHeader.tsx` before creating new primitives
- [ ] Severity colors and ordering come from `src/lib/severity.ts`

### New dependency
- [ ] Justify it; prefer existing deps. `pnpm add`, commit the lockfile with the change, `pnpm audit --prod` stays clean

## Definition of done

A feature is `done` only when all are true, with output you actually saw:

```sh
pnpm run lint            # tsc, ESLint and Prettier check all pass (pnpm run format fixes formatting)
pnpm test                # all unit + API tests pass
pnpm run test:e2e        # required if pages, routes or ingest changed (needs DATABASE_URL + build)
pnpm run build           # required if app/ or next.config.ts changed
```

and: acceptance criteria in `features.json` are met; new behavior has a test that failed before the change; docs updated;
`progress.md` entry records the commands run and results; no unrelated files changed.

If e2e could not be run, say so in `progress.md` and keep the feature `in_progress`, not `done`.

## progress.md entry format

```
## YYYY-MM-DD: <feature id> <title>
- Done: ...
- Verified: <commands and results>
- Failed / blocked: ...
- Next: ...
- Gotchas: ...
```

Newest entry first. Keep entries short; promote anything lasting into `ARCHITECTURE.md`.
