import { afterEach, beforeEach, describe, expect, test } from 'vitest';
import { eq } from 'drizzle-orm';
import { schema, type Db } from '@/db';
import { formatEpss } from '@/lib/epss';
import { ingestSbom } from '@/server/ingest';
import { getVulnerability, listVulnerabilities, loadComponents } from '@/server/inventory';
import { enrich } from '@/worker/enrich';
import { callsTo, createTestDb, enrichOptions, epssOptions, fixture, LODASH_VULN } from './helpers';

let db: Db;
let close: () => Promise<void>;
beforeEach(async () => {
  ({ db, close } = await createTestDb());
});
afterEach(() => close());

const quiet = { info() {}, warn() {}, error() {} };
const run = (apis: Parameters<typeof enrichOptions>[0] = {}, extra: { force?: boolean } = {}) =>
  enrich(db, { ...enrichOptions(apis), ...epssOptions, ...extra, logger: quiet });
const epssCalls = (calls: string[]) => callsTo(calls, 'epss.test');
const SCORE = { 'CVE-2020-8203': { epss: 0.05213, percentile: 0.92373 } };

async function addVulns(ids: string[]) {
  await db.insert(schema.vulnerabilities).values(ids.map((id) => ({ id })));
}

describe('EPSS sync', () => {
  const APIS = {
    vulns: { 'pkg:npm/lodash@4.17.15': ['GHSA-p6mc-m468-83gw'] },
    osvVulns: { 'GHSA-p6mc-m468-83gw': LODASH_VULN },
  };

  test('looks up the CVE alias of a vulnerability found in the same run', async () => {
    await ingestSbom(db, fixture('cyclonedx.json'), {});
    const calls: string[] = [];
    await run({ ...APIS, epss: SCORE, calls });
    expect(epssCalls(calls)).toHaveLength(1);
    expect(decodeURIComponent(epssCalls(calls)[0])).toContain('cve=CVE-2020-8203');
    const [row] = await db.select().from(schema.epssScores);
    expect(row).toMatchObject({ cveId: 'CVE-2020-8203', modelDate: '2026-10-14' });
    expect(row.score).toBeCloseTo(0.05213);
    expect(row.percentile).toBeCloseTo(0.92373);
  });

  test('records CVEs without a score so they are not queried again', async () => {
    await addVulns(['CVE-2099-0001', 'GHSA-aaaa-bbbb-cccc']);
    const calls: string[] = [];
    await run({ epss: {}, calls });
    const [row] = await db.select().from(schema.epssScores);
    expect(row).toMatchObject({ cveId: 'CVE-2099-0001', score: null, percentile: null });
    await run({ epss: {}, calls });
    expect(epssCalls(calls)).toHaveLength(1);
  });

  test('refreshes stale scores and splits large lookups into batches', async () => {
    const ids = Array.from({ length: 120 }, (_, i) => `CVE-2030-${String(i).padStart(4, '0')}`);
    await addVulns(ids);
    const calls: string[] = [];
    await run({ epss: {}, calls });
    expect(epssCalls(calls)).toHaveLength(3);

    await db
      .update(schema.epssScores)
      .set({ fetchedAt: new Date(Date.now() - 48 * 3600e3) })
      .where(eq(schema.epssScores.cveId, ids[0]));
    await run({ epss: {}, calls });
    expect(epssCalls(calls)).toHaveLength(4);
  });

  test('a failing API keeps existing scores, counts an error and backs off', async () => {
    await addVulns(['CVE-2020-8203']);
    await run({ epss: SCORE });
    await db.update(schema.epssScores).set({ fetchedAt: new Date(Date.now() - 48 * 3600e3) });
    const calls: string[] = [];
    const stats = await run({ epss: null, calls });
    expect(stats.errors).toBe(1);
    expect((await db.select().from(schema.epssScores))[0].score).toBeCloseTo(0.05213);
    const [sync] = await db.select().from(schema.feedSyncs).where(eq(schema.feedSyncs.name, 'epss'));
    expect(sync.error).toContain('503');

    // fetchJson retries 5xx responses, so one failed run makes several requests; a second run makes none.
    const afterFailure = epssCalls(calls).length;
    expect(afterFailure).toBeGreaterThan(0);
    await run({ epss: null, calls });
    expect(epssCalls(calls)).toHaveLength(afterFailure);
  });

  test('is skipped when no URL is configured', async () => {
    await addVulns(['CVE-2020-8203']);
    const calls: string[] = [];
    await enrich(db, enrichOptions({ epss: SCORE, calls }));
    expect(epssCalls(calls)).toHaveLength(0);
  });
});

describe('EPSS in the inventory', () => {
  const APIS = {
    vulns: { 'pkg:npm/lodash@4.17.15': ['GHSA-p6mc-m468-83gw'] },
    osvVulns: { 'GHSA-p6mc-m468-83gw': LODASH_VULN },
  };

  test('exposes score and percentile on vulnerabilities', async () => {
    await ingestSbom(db, fixture('cyclonedx.json'), {});
    await run({ ...APIS, epss: SCORE });
    const [vuln] = await listVulnerabilities(db);
    expect(vuln.epss?.score).toBeCloseTo(0.05213);
    expect(vuln.epss?.percentile).toBeCloseTo(0.92373);
    expect((await getVulnerability(db, 'GHSA-p6mc-m468-83gw'))?.epss?.score).toBeCloseTo(0.05213);
    expect((await loadComponents(db)).flatMap((c) => c.vulns)[0].epss).not.toBeNull();
  });

  test('is null when unscored', async () => {
    await ingestSbom(db, fixture('cyclonedx.json'), {});
    await run({ ...APIS, epss: {} });
    expect((await listVulnerabilities(db))[0].epss).toBeNull();
  });
});

describe('formatEpss', () => {
  test('formats probabilities as percentages', () => {
    expect(formatEpss(0.05213)).toBe('5.2%');
    expect(formatEpss(0.99999)).toBe('100%');
    expect(formatEpss(0.0004)).toBe('<0.1%');
    expect(formatEpss(0.5)).toBe('50%');
  });
});
