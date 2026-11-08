import { afterEach, beforeEach, describe, expect, test } from 'vitest';
import { eq } from 'drizzle-orm';
import { schema, setDb, type Db } from '@/db';
import { snapshotCounts } from '@/lib/snapshot';
import { ingestSbom } from '@/server/ingest';
import { enrich } from '@/worker/enrich';
import { createTestDb, enrichOptions, LODASH_VULN, type FakeApis } from './helpers';

describe('snapshotCounts', () => {
  test('counts distinct vulnerabilities by severity and outdated components', () => {
    const shared = { id: 'GHSA-1', severity: 'HIGH' as const };
    expect(
      snapshotCounts([
        { version: '1.0.0', latestVersion: '2.0.0', vulns: [shared, { id: 'GHSA-2', severity: 'CRITICAL' }] },
        { version: '1.0.0', latestVersion: '1.0.1', vulns: [shared] },
        { version: '1.0.0', latestVersion: '1.0.0', vulns: [] },
        { version: null, latestVersion: null, vulns: [] },
      ]),
    ).toEqual({
      components: 4,
      vulnerableComponents: 2,
      vulnerabilities: 2,
      critical: 1,
      high: 1,
      medium: 0,
      low: 0,
      unknown: 0,
      outdatedComponents: 2,
      outdatedMajor: 1,
    });
  });
});

describe('daily snapshots', () => {
  let db: Db;
  let close: () => Promise<void>;
  beforeEach(async () => {
    ({ db, close } = await createTestDb());
    setDb(db);
  });
  afterEach(() => close());

  const sbom = (version: string) => ({
    bomFormat: 'CycloneDX',
    specVersion: '1.5',
    components: [{ type: 'library', name: 'lodash', version, purl: `pkg:npm/lodash@${version}` }],
  });
  const APIS: FakeApis = {
    vulns: { 'pkg:npm/lodash@4.17.15': [LODASH_VULN.id] },
    osvVulns: { [LODASH_VULN.id]: LODASH_VULN },
    latest: { 'npm:lodash': '4.17.21' },
  };
  const rows = () => db.select().from(schema.projectSnapshots);

  test('writes one row per project per day and updates it on a second run the same day', async () => {
    await ingestSbom(db, sbom('4.17.15'), { project: 'app', version: '1' });
    const now = new Date('2026-11-08T03:00:00Z');
    await enrich(db, { ...enrichOptions(APIS), now });
    await enrich(db, { ...enrichOptions(APIS), now: new Date('2026-11-08T21:00:00Z') });
    expect(await rows()).toMatchObject([
      { day: '2026-11-08', components: 1, vulnerabilities: 1, high: 1, outdatedComponents: 1, outdatedMajor: 0 },
    ]);
  });

  test('a new day adds a row and the day’s numbers follow the project’s latest SBOM', async () => {
    await ingestSbom(db, sbom('4.17.15'), { project: 'app', version: '1' });
    await enrich(db, { ...enrichOptions(APIS), now: new Date('2026-11-08T03:00:00Z') });
    await ingestSbom(db, sbom('4.17.21'), { project: 'app', version: '2' });
    await enrich(db, { ...enrichOptions(APIS), now: new Date('2026-11-09T03:00:00Z') });
    expect((await rows()).map((r) => [r.day, r.vulnerabilities])).toEqual([
      ['2026-11-08', 1],
      ['2026-11-09', 0],
    ]);
  });

  test('survives SBOM history pruning', async () => {
    const { projectId } = await ingestSbom(db, sbom('4.17.15'), { project: 'app', version: '1' });
    await enrich(db, { ...enrichOptions(APIS), now: new Date('2026-11-08T03:00:00Z') });
    for (let i = 2; i <= 4; i++) {
      await ingestSbom(db, sbom('4.17.21'), { project: 'app', version: String(i) }, { historyLimit: 1 });
    }
    expect(await db.select().from(schema.sboms).where(eq(schema.sboms.projectId, projectId))).toHaveLength(1);
    expect(await rows()).toHaveLength(1);
  });

  test('a project with no SBOM gets no snapshot', async () => {
    await db.insert(schema.projects).values({ name: 'empty' });
    await enrich(db, { ...enrichOptions(APIS), now: new Date('2026-11-08T03:00:00Z') });
    expect(await rows()).toEqual([]);
  });
});
