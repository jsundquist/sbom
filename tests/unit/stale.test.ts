import { afterEach, beforeEach, describe, expect, test, vi } from 'vitest';
import { eq } from 'drizzle-orm';
import { schema, setDb, type Db } from '@/db';
import { resetEnv } from '@/lib/env';
import { isStale } from '@/lib/stale';
import { ingestSbom } from '@/server/ingest';
import { getOverview, getProject, listProjects } from '@/server/inventory';
import { createTestDb } from './helpers';

const NOW = new Date('2026-11-16T12:00:00Z');
const daysAgo = (n: number) => new Date(NOW.getTime() - n * 86_400_000);

describe('isStale', () => {
  test('stale only once the upload is older than the threshold', () => {
    expect(isStale(daysAgo(14), NOW, 14)).toBe(false);
    expect(isStale(new Date(daysAgo(14).getTime() - 1), NOW, 14)).toBe(true);
    expect(isStale(daysAgo(1), NOW, 14)).toBe(false);
  });
  test('accepts the ISO string the read model carries', () => {
    expect(isStale(daysAgo(30).toISOString(), NOW, 14)).toBe(true);
  });
  test('a project with no SBOM is not stale', () => {
    expect(isStale(null, NOW, 14)).toBe(false);
    expect(isStale(undefined, NOW, 14)).toBe(false);
  });
  test('a threshold of 0 disables the flag', () => {
    expect(isStale(daysAgo(900), NOW, 0)).toBe(false);
  });
});

describe('stale projects in the read model', () => {
  let db: Db;
  let close: () => Promise<void>;
  const sbom = (name: string) => ({
    bomFormat: 'CycloneDX',
    specVersion: '1.5',
    components: [{ type: 'library', name, version: '1.0.0', purl: `pkg:npm/${name}@1.0.0` }],
  });

  beforeEach(async () => {
    ({ db, close } = await createTestDb());
    setDb(db);
    vi.stubEnv('STALE_AFTER_DAYS', '14');
    resetEnv();
    await ingestSbom(db, sbom('a'), { project: 'fresh-app', version: '1' });
    await ingestSbom(db, sbom('b'), { project: 'abandoned-app', version: '1' });
    await db.insert(schema.projects).values({ name: 'no-sbom-yet' });
    await db
      .update(schema.sboms)
      .set({ uploadedAt: new Date(Date.now() - 30 * 86_400_000) })
      .where(eq(schema.sboms.version, '1'));
    // Only the second project's SBOM stays old: re-upload the first.
    await ingestSbom(db, sbom('a'), { project: 'fresh-app', version: '2' });
  });
  afterEach(async () => {
    vi.unstubAllEnvs();
    resetEnv();
    await close();
  });

  const byName = async () => Object.fromEntries((await listProjects(db)).map((p) => [p.name, p.stale]));

  test('listProjects marks only the project whose latest SBOM is old', async () => {
    expect(await byName()).toEqual({ 'fresh-app': false, 'abandoned-app': true, 'no-sbom-yet': false });
  });

  test('getProject carries the same flag, whichever SBOM is being viewed', async () => {
    const [old] = (await listProjects(db)).filter((p) => p.name === 'abandoned-app');
    expect((await getProject(db, old.id))?.stale).toBe(true);
    const [fresh] = (await listProjects(db)).filter((p) => p.name === 'fresh-app');
    const detail = await getProject(db, fresh.id, fresh.latest!.id);
    expect(detail?.stale).toBe(false);
  });

  test('the overview counts stale projects', async () => {
    expect((await getOverview(db)).staleProjects).toBe(1);
  });

  test('STALE_AFTER_DAYS=0 turns the flag off', async () => {
    vi.stubEnv('STALE_AFTER_DAYS', '0');
    resetEnv();
    expect(Object.values(await byName())).toEqual([false, false, false]);
    expect((await getOverview(db)).staleProjects).toBe(0);
  });
});
