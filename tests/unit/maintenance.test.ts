import { afterEach, beforeEach, describe, expect, test } from 'vitest';
import { setDb, type Db } from '@/db';
import { maintenanceFlags } from '@/lib/maintenance';
import { getPackage } from '@/server/inventory';
import { ingestSbom } from '@/server/ingest';
import { enrich } from '@/worker/enrich';
import { createTestDb, enrichOptions, type FakeApis } from './helpers';

const NOW = new Date('2026-11-08T00:00:00Z');

describe('maintenanceFlags', () => {
  test('a package is abandoned once its latest release is older than the threshold', () => {
    expect(maintenanceFlags({ deprecated: false, latestReleasedAt: new Date('2024-11-09T00:00:00Z') }, NOW, 2).abandoned).toBe(false);
    expect(maintenanceFlags({ deprecated: false, latestReleasedAt: new Date('2024-11-07T00:00:00Z') }, NOW, 2).abandoned).toBe(true);
  });
  test('an unknown release date is not abandoned', () => {
    expect(maintenanceFlags({ deprecated: false, latestReleasedAt: null }, NOW, 2)).toMatchObject({
      abandoned: false,
      lastReleaseAt: null,
    });
  });
  test('deprecation is independent of age and keeps the reason', () => {
    expect(maintenanceFlags({ deprecated: true, reason: 'use got', latestReleasedAt: NOW }, NOW, 2)).toMatchObject({
      deprecated: true,
      deprecatedReason: 'use got',
      abandoned: false,
    });
  });
});

describe('maintenance signals from deps.dev', () => {
  let db: Db;
  let close: () => Promise<void>;
  beforeEach(async () => {
    ({ db, close } = await createTestDb());
    setDb(db);
    await ingestSbom(
      db,
      {
        bomFormat: 'CycloneDX',
        specVersion: '1.5',
        components: [
          { type: 'library', name: 'request', version: '2.88.2', purl: 'pkg:npm/request@2.88.2' },
          { type: 'library', name: 'fresh', version: '1.0.0', purl: 'pkg:npm/fresh@1.0.0' },
          { type: 'library', name: 'dusty', version: '1.0.0', purl: 'pkg:npm/dusty@1.0.0' },
        ],
      },
      { project: 'app', version: '1' },
    );
  });
  afterEach(() => close());

  const APIS: FakeApis = {
    latest: { 'npm:request': '2.88.2', 'npm:fresh': '1.0.0', 'npm:dusty': '1.0.0' },
    latestMeta: {
      'npm:request': { publishedAt: new Date().toISOString(), deprecated: true, reason: 'request has been deprecated' },
      'npm:fresh': { publishedAt: new Date().toISOString() },
      'npm:dusty': { publishedAt: '2015-01-01T00:00:00Z' },
    },
  };

  test('stores deprecation and release date and flags only what applies', async () => {
    await enrich(db, enrichOptions(APIS));
    expect((await getPackage(db, 'npm:request'))?.maintenance).toMatchObject({
      deprecated: true,
      deprecatedReason: 'request has been deprecated',
      abandoned: false,
    });
    expect((await getPackage(db, 'npm:fresh'))?.maintenance).toMatchObject({ deprecated: false, abandoned: false });
    expect((await getPackage(db, 'npm:dusty'))?.maintenance).toMatchObject({ deprecated: false, abandoned: true });
  });
});
