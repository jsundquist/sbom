// Scale benchmark (F-004, ADR 0005): seeds a throwaway Postgres at the target size, then times the read model and an upload.
//   BENCH_DATABASE_URL=postgres://... pnpm run bench seed [--projects 100 --components 2000 --history 20]
//   BENCH_DATABASE_URL=postgres://... pnpm run bench measure [--runs 5]
// Uses BENCH_DATABASE_URL, never DATABASE_URL, and refuses to seed a database that already has projects.
// Measure in a fresh process after seeding so the peak memory it reports belongs to the reads alone.
import path from 'node:path';
import { performance } from 'node:perf_hooks';
import { sql } from 'drizzle-orm';
import { drizzle } from 'drizzle-orm/node-postgres';
import { migrate } from 'drizzle-orm/node-postgres/migrator';
import { Pool } from 'pg';
import { schema, type Db } from '@/db';
import { getProjectTrend, getSummaryTrend } from '@/server/trends';
import { ingestSbom } from '@/server/ingest';
import {
  getDependencyGraph,
  getOverview,
  getPackage,
  getProject,
  getVulnerability,
  listPackages,
  listProjects,
  listVulnerabilities,
} from '@/server/inventory';
import { DEFAULTS, seedBenchmark } from './benchmark-seed';

/** Fixed before measuring. Server-side read-model time per page load, median of the measured runs. */
export const TARGETS_MS = {
  'listProjects (projects grid)': 1000,
  'getOverview (overview page)': 1000,
  'listVulnerabilities (vulnerabilities grid)': 1000,
  'listPackages (packages grid)': 1000,
  'getProject (application page)': 500,
  'getProject, older SBOM from history': 500,
  'getPackage (package page)': 500,
  'getVulnerability (vulnerability page)': 500,
  'getDependencyGraph (dependency tree)': 500,
  'getSummaryTrend (overview chart, 90 days)': 500,
  'ingestSbom, identical re-upload': 2000,
  'ingestSbom, 5 components changed': 2000,
} as const;
export const PEAK_RSS_TARGET_MB = 1024;
export const DB_SIZE_TARGET_GB = 5;
/** A case that runs longer than this is cut off and reported as timed out instead of hanging the run. */
const TIMEOUT_MS = 120_000;

const url = process.env.BENCH_DATABASE_URL;
const [, , command, ...rest] = process.argv;
if (!url || !['seed', 'measure'].includes(command ?? '')) {
  console.error(
    'Usage: BENCH_DATABASE_URL=postgres://... pnpm run bench <seed|measure> [--projects N --components N --history N --runs N]',
  );
  process.exit(1);
}
const flag = (name: string, fallback: number) => {
  const i = rest.indexOf(`--${name}`);
  return i >= 0 ? Number(rest[i + 1]) : fallback;
};
/** `--only reads` or `--only uploads` runs half of the cases; the default runs both. */
const only = rest.includes('--only') ? rest[rest.indexOf('--only') + 1] : 'all';

const pool = new Pool({ connectionString: url, max: 8, statement_timeout: command === 'measure' ? TIMEOUT_MS : 0 });
const db = drizzle(pool, { schema }) as unknown as Db;

async function sizes() {
  const rows = await pool.query<{ table: string; rows: string; total: string; indexes: string }>(`
    SELECT c.relname AS table, c.reltuples::bigint AS rows,
           pg_total_relation_size(c.oid) AS total, pg_indexes_size(c.oid) AS indexes
    FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
    WHERE n.nspname = 'public' AND c.relkind = 'r' ORDER BY total DESC`);
  const { rows: sized } = await pool.query<{ size: string }>('SELECT pg_database_size(current_database()) AS size');
  return { tables: rows.rows, database: Number(sized[0].size) };
}

const mb = (n: number) => `${(n / 1024 / 1024).toFixed(1)} MB`;

function printSizes(s: Awaited<ReturnType<typeof sizes>>) {
  console.log('\n### Table and index sizes\n');
  console.log('| Table | Rows (estimate) | Total | of which indexes |\n|---|---:|---:|---:|');
  for (const t of s.tables.filter((t) => Number(t.total) > 1024 * 1024)) {
    console.log(`| ${t.table} | ${Number(t.rows).toLocaleString()} | ${mb(Number(t.total))} | ${mb(Number(t.indexes))} |`);
  }
  console.log(`\nDatabase: **${(s.database / 1024 ** 3).toFixed(2)} GB** (target at most ${DB_SIZE_TARGET_GB} GB)`);
}

if (command === 'seed') {
  await migrate(drizzle(pool), { migrationsFolder: path.resolve(import.meta.dirname, '..', 'drizzle') });
  if ((await db.select({ id: schema.projects.id }).from(schema.projects).limit(1)).length) {
    console.error('Refusing to seed: the database already has projects. Point BENCH_DATABASE_URL at an empty one.');
    process.exit(1);
  }
  const started = performance.now();
  await seedBenchmark(db, {
    projects: flag('projects', DEFAULTS.projects),
    components: flag('components', DEFAULTS.components),
    history: flag('history', DEFAULTS.history),
    log: (line) => console.error(line),
  });
  await pool.query('ANALYZE');
  console.log(`Seeded in ${((performance.now() - started) / 1000).toFixed(0)} s`);
  printSizes(await sizes());
} else {
  const runs = flag('runs', 5);
  const results: { name: string; ms: number[]; timedOut?: boolean }[] = [];
  const time = async (name: keyof typeof TARGETS_MS, fn: () => Promise<unknown>) => {
    const ms: number[] = [];
    try {
      await fn();
      for (let i = 0; i < runs; i++) {
        const t = performance.now();
        await fn();
        ms.push(performance.now() - t);
      }
    } catch (error) {
      // 57014 = query_canceled, raised by statement_timeout. Drizzle wraps the driver error, so look at its cause too.
      const code = (error as { code?: string; cause?: { code?: string } }).code ?? (error as { cause?: { code?: string } }).cause?.code;
      if (code !== '57014') {
        throw error;
      }
      results.push({ name, ms: [TIMEOUT_MS], timedOut: true });
      console.error(`${name}: timed out after ${TIMEOUT_MS / 1000} s`);
      return;
    }
    results.push({ name, ms });
    console.error(`${name}: median ${median(ms).toFixed(0)} ms`);
  };
  const median = (xs: number[]) => [...xs].sort((a, b) => a - b)[Math.floor(xs.length / 2)];

  // Pick the subjects once, outside the timings: a typical Project, an older SBOM of it, the busiest package and vulnerability.
  const [project] = await listProjects(db);
  const detail = await getProject(db, project.id);
  const older = detail!.history[Math.floor(detail!.history.length / 2)].id;
  const reads = only !== 'uploads';
  const busiest = reads ? (await listPackages(db)).sort((a, b) => b.projectCount - a.projectCount)[0] : null;
  const worst = reads ? (await listVulnerabilities(db))[0] : null;

  if (reads) {
    await time('listProjects (projects grid)', () => listProjects(db));
    await time('getOverview (overview page)', () => getOverview(db));
    await time('listVulnerabilities (vulnerabilities grid)', () => listVulnerabilities(db));
    await time('listPackages (packages grid)', () => listPackages(db));
    await time('getProject (application page)', () => getProject(db, project.id));
    await time('getProject, older SBOM from history', () => getProject(db, project.id, older));
    await time('getPackage (package page)', () => getPackage(db, busiest!.key));
    await time('getVulnerability (vulnerability page)', () => getVulnerability(db, worst!.id));
    await time('getDependencyGraph (dependency tree)', () => getDependencyGraph(db, project.id));
    await time('getSummaryTrend (overview chart, 90 days)', () => getSummaryTrend(db, 90));
    await getProjectTrend(db, project.id, 90);
  }
  const peakRssMb = reads ? process.resourceUsage().maxRSS / 1024 : null;

  // Writes last: they add SBOMs and prune old ones.
  const [{ document }] = await db
    .select({ document: schema.sboms.document })
    .from(schema.sboms)
    .where(sql`${schema.sboms.id} = ${detail!.latest!.id}`);
  const doc = document as { components: unknown[] };
  const meta = { project: project.name, version: 'bench' };
  if (only !== 'reads') {
    await time('ingestSbom, identical re-upload', () => ingestSbom(db, doc, meta));
    const changed = { ...doc, components: doc.components.slice(5) };
    await time('ingestSbom, 5 components changed', () => ingestSbom(db, changed, meta));
  }

  const projectsN = (await listProjects(db)).length;
  const comps = (await pool.query<{ n: string }>('SELECT count(*) AS n FROM components')).rows[0].n;
  console.log(`## Benchmark: ${projectsN} projects, ${Number(comps).toLocaleString()} component rows\n`);
  console.log(`Median of ${runs} runs after one warm-up.\n`);
  console.log('| Case | Median ms | Max ms | Target ms | |\n|---|---:|---:|---:|---|');
  const failed: string[] = [];
  for (const r of results) {
    const target = TARGETS_MS[r.name as keyof typeof TARGETS_MS];
    const ok = median(r.ms) <= target;
    if (!ok) {
      failed.push(r.name);
    }
    console.log(
      r.timedOut
        ? `| ${r.name} | >${TIMEOUT_MS} | | ${target} | **timed out** |`
        : `| ${r.name} | ${median(r.ms).toFixed(0)} | ${Math.max(...r.ms).toFixed(0)} | ${target} | ${ok ? 'ok' : '**over**'} |`,
    );
  }
  if (peakRssMb !== null) {
    console.log(`\nPeak RSS of the reads: **${peakRssMb.toFixed(0)} MB** (target at most ${PEAK_RSS_TARGET_MB} MB)`);
  }
  const s = await sizes();
  printSizes(s);

  if (only === 'all') {
    const over = (names: string[]) => names.some((n) => failed.includes(n));
    const readsOver = over([
      'listProjects (projects grid)',
      'getOverview (overview page)',
      'listVulnerabilities (vulnerabilities grid)',
      'listPackages (packages grid)',
    ]);
    console.log('\n### Verdict against the rules in docs/benchmark.md\n');
    console.log(`- K-001 per-project rollups: **${readsOver || (peakRssMb ?? 0) > PEAK_RSS_TARGET_MB ? 'build' : 'drop'}**`);
    console.log(`- K-002 skip identical SBOMs: **${over(['ingestSbom, identical re-upload']) ? 'build' : 'drop'}**`);
    console.log(`- K-003 history cost: **${s.database / 1024 ** 3 > DB_SIZE_TARGET_GB ? 'shrink' : 'drop'}**`);
  }
}
await pool.end();
