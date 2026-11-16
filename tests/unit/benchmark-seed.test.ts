import { afterEach, beforeEach, describe, expect, test } from 'vitest';
import { count } from 'drizzle-orm';
import type { PgTable } from 'drizzle-orm/pg-core';
import { schema, setDb, type Db } from '@/db';
import { getOverview, listProjects, listVulnerabilities } from '@/server/inventory';
import { buildUniverse, mulberry32, seedBenchmark } from '../../scripts/benchmark-seed';
import { createTestDb } from './helpers';

const OPTS = { projects: 3, components: 40, history: 3, packages: 120, seed: 7 };

describe('benchmark data generator', () => {
  test('the same seed gives the same universe, a different seed does not', () => {
    const names = (seed: number) => buildUniverse(mulberry32(seed), 50).map((p) => `${p.key}@${p.versions.join(',')}`);
    expect(names(1)).toEqual(names(1));
    expect(names(1)).not.toEqual(names(2));
  });
});

describe('seedBenchmark', () => {
  let db: Db;
  let close: () => Promise<void>;
  beforeEach(async () => {
    ({ db, close } = await createTestDb());
    setDb(db);
    await seedBenchmark(db, OPTS);
  });
  afterEach(() => close());

  const rows = async (t: PgTable) => (await db.select({ n: count() }).from(t))[0].n;

  test('writes projects, a full history of SBOMs and their components', async () => {
    expect(await rows(schema.projects)).toBe(3);
    expect(await rows(schema.sboms)).toBe(9);
    // History churns a little, so each SBOM is close to, not exactly, the requested size.
    const perSbom = (await rows(schema.components)) / 9;
    expect(perSbom).toBeGreaterThan(36);
    expect(perSbom).toBeLessThan(44);
  });

  test('the latest SBOM of each project is the one the read model reports', async () => {
    const list = await listProjects(db);
    expect(list).toHaveLength(3);
    for (const p of list) {
      expect(p.uploadCount).toBe(3);
      expect(p.stats.components).toBe(p.latest!.componentCount);
    }
  });

  test('the dataset has vulnerabilities, exploited ones and snapshots for the trend charts', async () => {
    expect((await listVulnerabilities(db)).length).toBeGreaterThan(0);
    const overview = await getOverview(db);
    expect(overview.stats.vulnerabilities).toBeGreaterThan(0);
    expect(overview.projectCount).toBe(3);
    expect(await rows(schema.projectSnapshots)).toBeGreaterThan(0);
  });
});
