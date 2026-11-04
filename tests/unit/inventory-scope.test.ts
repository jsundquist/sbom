import { afterEach, beforeEach, describe, expect, test } from 'vitest';
import type { Db } from '@/db';
import { ingestSbom } from '@/server/ingest';
import { getPackage, getVulnerability, groupKey, loadComponents } from '@/server/inventory';
import { enrich } from '@/worker/enrich';
import { createTestDb, enrichOptions, fixture, LODASH_VULN } from './helpers';

let db: Db;
let close: () => Promise<void>;
beforeEach(async () => {
  ({ db, close } = await createTestDb());
  await ingestSbom(db, fixture('cyclonedx.json'), {});
  await enrich(db, {
    ...enrichOptions({
      vulns: { 'pkg:npm/lodash@4.17.15': ['GHSA-p6mc-m468-83gw'] },
      osvVulns: { 'GHSA-p6mc-m468-83gw': LODASH_VULN },
    }),
    logger: { info() {}, warn() {}, error() {} },
  });
});
afterEach(() => close());

describe('loadComponents scope', () => {
  test('packageKey narrows to one package', async () => {
    const all = await loadComponents(db);
    const key = groupKey(all.find((c) => c.name === 'lodash')!);
    const scoped = await loadComponents(db, { packageKey: key });
    expect(scoped.length).toBeGreaterThan(0);
    expect(scoped.every((c) => groupKey(c) === key)).toBe(true);
    expect(scoped.length).toBeLessThan(all.length);
  });

  test('name: keys select components without a purl', async () => {
    const all = await loadComponents(db);
    const bare = all.find((c) => c.packageKey === null);
    expect(bare).toBeDefined();
    const scoped = await loadComponents(db, { packageKey: groupKey(bare!) });
    expect(scoped.map((c) => c.id)).toEqual(all.filter((c) => groupKey(c) === groupKey(bare!)).map((c) => c.id));
  });

  test('vulnerabilityId narrows to affected components', async () => {
    const scoped = await loadComponents(db, { vulnerabilityId: 'GHSA-p6mc-m468-83gw' });
    expect(scoped.map((c) => c.name)).toEqual(['lodash']);
    expect(scoped[0].vulns).toHaveLength(1);
    expect(await loadComponents(db, { vulnerabilityId: 'GHSA-none' })).toEqual([]);
  });

  test('sbomIds still selects a specific upload', async () => {
    const [first] = await loadComponents(db);
    expect((await loadComponents(db, { sbomIds: [first.sbomId] })).length).toBeGreaterThan(0);
    expect(await loadComponents(db, { sbomIds: [] })).toEqual([]);
  });

  test('detail reads still report affected packages and projects', async () => {
    const vuln = await getVulnerability(db, 'GHSA-p6mc-m468-83gw');
    expect(vuln?.affected.map((a) => a.name)).toEqual(['lodash']);
    expect(vuln?.projects).toHaveLength(1);
    expect((await getPackage(db, 'npm:lodash'))?.vulnerabilities).toHaveLength(1);
    expect(await getPackage(db, 'npm:nope')).toBeNull();
  });
});
