import { afterEach, beforeEach, describe, expect, test } from 'vitest';
import { eq } from 'drizzle-orm';
import { schema, type Db } from '@/db';
import { ingestSbom } from '@/server/ingest';
import { getVulnerability, listVulnerabilities, loadComponents, summarize } from '@/server/inventory';
import { enrich } from '@/worker/enrich';
import { callsTo, createTestDb, enrichOptions, fixture, kevOptions, LODASH_VULN, type KevFeedEntry } from './helpers';

let db: Db;
let close: () => Promise<void>;
beforeEach(async () => {
  ({ db, close } = await createTestDb());
});
afterEach(() => close());

const LODASH_KEV: KevFeedEntry = {
  cveID: 'CVE-2020-8203',
  vendorProject: 'Lodash',
  product: 'lodash',
  vulnerabilityName: 'Lodash Prototype Pollution',
  dateAdded: '2024-01-02',
  dueDate: '2024-01-23',
  knownRansomwareCampaignUse: 'Known',
};
const OTHER_KEV: KevFeedEntry = { cveID: 'CVE-2099-0001', dateAdded: '2025-05-05' };

const run = (extra: Parameters<typeof enrichOptions>[0] & { force?: boolean; ttl?: number } = {}) =>
  enrich(db, {
    ...enrichOptions(extra),
    ...kevOptions,
    kevTtlHours: extra.ttl ?? kevOptions.kevTtlHours,
    force: extra.force,
    logger: { info() {}, warn() {}, error() {} },
  });

describe('CISA KEV sync', () => {
  test('stores the catalog and skips the download while it is fresh', async () => {
    const calls: string[] = [];
    await run({ kev: [LODASH_KEV, OTHER_KEV], calls });
    const rows = await db.select().from(schema.kevEntries);
    expect(rows.map((r) => r.cveId).sort()).toEqual(['CVE-2020-8203', 'CVE-2099-0001']);
    expect(rows.find((r) => r.cveId === 'CVE-2020-8203')).toMatchObject({
      vendor: 'Lodash',
      dateAdded: '2024-01-02',
      dueDate: '2024-01-23',
      knownRansomwareUse: true,
    });
    expect(rows.find((r) => r.cveId === 'CVE-2099-0001')).toMatchObject({ dueDate: null, knownRansomwareUse: false });

    const before = callsTo(calls, 'kev.test').length;
    expect(before).toBe(1);
    await run({ kev: [LODASH_KEV], calls });
    expect(callsTo(calls, 'kev.test').length).toBe(1);
    expect(await db.select().from(schema.kevEntries)).toHaveLength(2);
  });

  test('re-syncs when stale and drops entries removed from the catalog', async () => {
    await run({ kev: [LODASH_KEV, OTHER_KEV] });
    await db
      .update(schema.feedSyncs)
      .set({ syncedAt: new Date(Date.now() - 48 * 3600e3) })
      .where(eq(schema.feedSyncs.name, 'kev'));
    await run({ kev: [LODASH_KEV] });
    expect((await db.select().from(schema.kevEntries)).map((r) => r.cveId)).toEqual(['CVE-2020-8203']);
  });

  test('a failing feed keeps existing data, records the error and backs off', async () => {
    await run({ kev: [LODASH_KEV] });
    await db
      .update(schema.feedSyncs)
      .set({ syncedAt: new Date(Date.now() - 48 * 3600e3) })
      .where(eq(schema.feedSyncs.name, 'kev'));
    const calls: string[] = [];
    const stats = await run({ kev: null, calls });
    expect(stats.errors).toBe(1);
    expect(await db.select().from(schema.kevEntries)).toHaveLength(1);
    const [sync] = await db.select().from(schema.feedSyncs);
    expect(sync.error).toContain('503');

    // Right after a failure the feed is not hammered again.
    const retryCalls: string[] = [];
    await run({ kev: null, calls: retryCalls });
    expect(callsTo(retryCalls, 'kev.test')).toHaveLength(0);
  });

  test('is skipped entirely when no feed URL is configured', async () => {
    const calls: string[] = [];
    await enrich(db, { ...enrichOptions({ calls }) });
    expect(calls.filter((c) => c.includes('kev'))).toHaveLength(0);
    expect(await db.select().from(schema.feedSyncs)).toHaveLength(0);
  });
});

describe('KEV in the inventory', () => {
  const APIS = {
    vulns: { 'pkg:npm/lodash@4.17.15': ['GHSA-p6mc-m468-83gw'] },
    osvVulns: { 'GHSA-p6mc-m468-83gw': LODASH_VULN },
  };

  async function seed(kev: KevFeedEntry[]) {
    await ingestSbom(db, fixture('cyclonedx.json'), {});
    await run({ ...APIS, kev });
  }

  test('flags vulnerabilities whose CVE alias is in the catalog', async () => {
    await seed([LODASH_KEV]);
    const list = await listVulnerabilities(db);
    expect(list).toHaveLength(1);
    expect(list[0].kev).toEqual({ dateAdded: '2024-01-02', dueDate: '2024-01-23', ransomware: true });

    const detail = await getVulnerability(db, 'GHSA-p6mc-m468-83gw');
    expect(detail?.kev).toMatchObject({ dateAdded: '2024-01-02' });
    expect(summarize(await loadComponents(db)).exploited).toBe(1);
  });

  test('leaves vulnerabilities that are not in the catalog unflagged', async () => {
    await seed([OTHER_KEV]);
    expect((await listVulnerabilities(db))[0].kev).toBeNull();
    expect((await getVulnerability(db, 'GHSA-p6mc-m468-83gw'))?.kev).toBeNull();
    expect(summarize(await loadComponents(db)).exploited).toBe(0);
  });
});
