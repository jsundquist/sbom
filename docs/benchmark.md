# Scale benchmark

Measures the read model and an upload at the size ADR 0005 designs for, and decides which of the scale tickets (K-001 to
K-003) to build. Ticket: F-004. Rerun it after any change to the read model, the schema or ingest.

## How to run

```bash
docker run -d --rm --name sbom-bench-pg -e POSTGRES_PASSWORD=pw -e POSTGRES_USER=sbom -e POSTGRES_DB=bench -p 55433:5432 postgres:16
export BENCH_DATABASE_URL=postgres://sbom:pw@localhost:55433/bench
pnpm run bench seed                 # 100 Projects x 2,000 components x 20 SBOMs; about 3 minutes
pnpm run bench measure              # reads, then two uploads; run it in a fresh process after seeding
pnpm run bench measure --only reads # or --only uploads
```

`BENCH_DATABASE_URL` is deliberately not `DATABASE_URL`, and `seed` refuses a database that already has Projects. Data is
synthetic and deterministic (`scripts/benchmark-seed.ts`, fixed seed), and nothing touches the network. `tests/unit/benchmark-seed.test.ts`
checks that the seeded data is something the real read model understands.

## What the data looks like

| | |
|---|---|
| Projects | 100, each with 20 retained SBOMs (the default `SBOM_HISTORY_LIMIT`), one a day |
| Components per SBOM | 2,000 (this repo's own Syft scan is 1,975); history churns about 1% dropped, 1% added, 3% bumped |
| Distinct packages | 6,000 (88% npm, 12% PyPI), 6 versions each; the 400 most popular are in every Project |
| Vulnerabilities | 720, affecting about 3% of package versions; one in forty is KEV-listed; all have EPSS |
| Edges | one parent per component, 8% have two, a tenth are direct |
| SBOM documents | CycloneDX with licences, CPE and Syft properties per component, stored in `sboms.document` |
| Trend snapshots | 90 days per Project |

## Targets (fixed before measuring)

Server-side time of the read-model function behind each page, median of 5 runs after one warm-up, against Postgres 16 on the same machine.
Browser rendering and network are not included.

| Case | Target |
|---|---:|
| Projects grid, overview, vulnerabilities grid, packages grid (whole inventory) | 1,000 ms |
| Application, package, vulnerability, dependency tree, trend chart (one subject) | 500 ms |
| Upload of a 2,000-component SBOM (parse, insert, prune history, garbage-collect) | 2,000 ms |
| Peak memory of the reads | 1,024 MB RSS |
| Database size at the target scale | 5 GB |

One second keeps a dashboard page feeling immediate, and half a second leaves room for rendering on top of it. A CI upload can take
longer than a page load, but not so long that a push pipeline waits on it. The memory and size limits are what a small k3s node can
carry next to the other workloads.

## Decision rules

| Ticket | Build when |
|---|---|
| K-001 per-project rollups | any whole-inventory read is over its target, or peak memory is over |
| K-002 skip identical SBOMs | the upload is over its target |
| K-003 history cost | the database is over its size target |

A ticket whose rule is not met is marked `superseded` with these numbers. The rules do not cover a result that is outside the
tickets' scope, such as the upload finding below; those get their own ticket.

## Environment

Apple M1 Pro (10 cores), 8 GB given to Docker Desktop, `postgres:16` with its default configuration (`shared_buffers` 128 MB), Node 24.18.
A server with more memory and tuned Postgres will be faster; the shape of the results, which cases are slow and why, is what carries over.

## Results (2026-11-16)

Seeded in 163 s: 100 Projects, 2,000 SBOMs, 4.0M component rows and 4.3M edges.

### Reads

| Case | Median ms | Max ms | Target ms | |
|---|---:|---:|---:|---|
| listProjects (projects grid) | 1672 | 1698 | 1000 | **over** |
| getOverview (overview page) | 1898 | 1924 | 1000 | **over** |
| listVulnerabilities (vulnerabilities grid) | 1629 | 1641 | 1000 | **over** |
| listPackages (packages grid) | 1817 | 1833 | 1000 | **over** |
| getProject (application page) | 24 | 26 | 500 | ok |
| getProject, older SBOM from history | 24 | 25 | 500 | ok |
| getPackage (package page) | 6 | 6 | 500 | ok |
| getVulnerability (vulnerability page) | 7 | 7 | 500 | ok |
| getDependencyGraph (dependency tree) | 23 | 24 | 500 | ok |
| getSummaryTrend (overview chart, 90 days) | 27 | 30 | 500 | ok |

Peak RSS of the reads: **1,208 MB** (target 1,024 MB). The same four cases came out at 1.67-1.92 s in two earlier runs, so the numbers are stable.

All four slow pages call `loadComponents()` for the whole inventory (about 200k rows). Timed on its own it takes 1.7 s; the
aggregation on top is `summarize` 8 ms, `aggregateVulnerabilities` 10 ms and `aggregatePackages` 255 ms. The cost is that one
join and the mapping of its rows, not the TypeScript aggregation. Every page scoped to one Project, package or vulnerability is
fast because `ComponentScope` narrows the join in SQL.

### Uploads

| Case | Target ms | Before F-006 | After F-006 (migration 0007, fresh seed) |
|---|---:|---:|---:|
| ingestSbom, identical re-upload | 2000 | **timed out after 120 s** | 383 ms |
| ingestSbom, 5 components changed | 2000 | **timed out after 120 s** | 377 ms |

The upload is not slow for the reason K-002 assumed (re-inserting 2,000 components). Every upload prunes the Project's oldest
SBOM, and deleting an SBOM cascades to its components. `component_edges.parent_id` and `child_id` are foreign keys to
`components` with `ON DELETE CASCADE` and have no index, so Postgres scans all 4.3M edges for each of the 2,000 deleted
components. One prune ran for over 9 minutes in the first attempt; the failing statement was
`DELETE FROM ONLY "public"."component_edges" WHERE $1 = "child_id"`. Two indexes fix it (F-006, migration 0007): about 380 ms per upload. Before the migration existed the same two
indexes were created by hand on the seeded database and measured 416 and 406 ms.

The seed never deletes, so this only shows up when an upload prunes. The cost grows with the total number of edges in the
database, not with the size of the SBOM being uploaded, so it was not measured at smaller sizes and may already be noticeable on a
smaller inventory with a full history. Fixed by F-006.

### Size

| Table | Rows | Total | of which indexes |
|---|---:|---:|---:|
| components | 4.0M | 719 MB | 154 MB |
| component_edges | 4.3M | 503 MB | 322 MB (was 305 MB and 123 MB before F-006) |
| sboms | 2,000 | 246 MB | 0.1 MB |
| everything else | | under 10 MB | |

Database: **1.45 GB** (was 1.26 GB before F-006; the indexes cost about 200 MB when built during the seed, 160 MB when created afterwards on a populated table). `sboms.document` is 246 MB for 2,000 documents because Postgres compresses large
`jsonb` values; it is not the biggest table.

## After K-001 (2026-11-16)

Profile of the 1,779 ms `loadComponents` before the change, on the same dataset:

| Part | Time |
|---|---:|
| Query 1: components joined to sboms, projects, packages and package_versions (200,000 rows, 17 columns) | 630 ms |
| &nbsp;&nbsp;the same rows with only the components' own columns | 235 ms |
| Query 2: vulnerabilities joined to every in-scope component, to find 972 rows | 553 ms |
| `updateType` over every row, and `maintenanceFlags` over every row | 186 ms and 148 ms |
| Distinct `package@version` among those rows | 27,987 of 200,000 |

The cost was repeated work, not volume: package facts re-joined and re-parsed (three timestamps per row) 200,000 times, a join that
visited every component to find a thousand vulnerabilities, and per-row calculations that depend only on the package version.
K-001 therefore changed `loadComponents` and nothing else: it loads components' own columns, loads package, version and
vulnerability facts from the small tables by package key (in blocks of 5,000 keys), and works out everything that depends only on
a `package@version` once and shares it. No schema change, no worker job, no new table. Output is unchanged:
`tests/unit/load-components-golden.test.ts` pins it, including all four scopes.

| Case | Before | After | Target |
|---|---:|---:|---:|
| listProjects (projects grid) | 1,672 ms | **729 ms** | 1,000 |
| getOverview (overview page) | 1,898 ms | **911 ms** | 1,000 |
| listVulnerabilities (vulnerabilities grid) | 1,629 ms | **725 ms** | 1,000 |
| listPackages (packages grid) | 1,817 ms | **906 ms** | 1,000 |
| getProject (application page) | 24 ms | 44 ms | 500 |
| getDependencyGraph (dependency tree) | 23 ms | 45 ms | 500 |
| Peak RSS of the reads | 1,208 MB | **838 MB** | 1,024 |

The one-subject pages got about 20 ms slower because the facts now come from separate small queries instead of one join. They are
far inside their target.

The margin on the overview and packages grid is about 9%, on an M1 Pro with Postgres on the same machine. A smaller server will be
slower, and the inventory is expected to grow. What is left, from the profile: about 235 ms of driver time to move the 200,000
component rows, about 250 ms in `aggregatePackages`, and the object spread per row. If a page goes over target again, per-Project
rollups written by the worker (the original K-001 plan, ADR 0005) are the next step; they would avoid loading components at all.

## Decisions

| Ticket | Rule | Result | Decision |
|---|---|---|---|
| K-001 cheaper whole-inventory reads | any whole-inventory read over target, or memory over | four reads at 1.6-1.9 s, 1,208 MB | **done without rollups**: a cheaper `loadComponents` brought all four under 1 s (below) |
| K-002 skip identical SBOMs | upload over target | about 380 ms after F-006 | **drop**; the cost was the prune, fixed by F-006 |
| K-003 history cost | database over 5 GB | 1.45 GB | **drop**; revisit at about 3x this size |
| F-006 | outside the rules | upload did not finish without the indexes | **done**: two indexes, migration 0007 |

K-001 as written covers the overview and projects grid. The packages and vulnerabilities grids are just as slow and read the same
load, and per-Project rollups do not help them, because they aggregate across Projects. The ticket now says what has to be true
instead: all four pages under 1 s and peak memory under 1 GB, by whatever combination of rollups (per Project, per package, per
vulnerability) or a cheaper load gets there. The detail pages stay as they are.

K-002 and K-003 are marked `superseded` by this result. K-004 (worker concurrency, OSV change feed) is untouched: this benchmark
does not exercise the worker.

## Not measured

- The worker's enrichment run at this size (it reads `package_versions` and `packages`, both small here).
- Concurrent requests: each case ran alone. Two people loading the overview at once is about twice the load.
- A Postgres tuned for the box, or a remote one; network latency would add to every case.
- Browser rendering of a 100-row projects grid or a 6,000-row packages grid.
