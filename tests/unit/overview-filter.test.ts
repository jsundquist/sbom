import { afterEach, beforeEach, describe, expect, test } from 'vitest';
import { schema, type Db } from '@/db';
import { parseOverviewFilter } from '@/lib/params';
import { ingestSbom } from '@/server/ingest';
import { getOverview, listProjects } from '@/server/inventory';
import { getSummaryTrend } from '@/server/trends';
import { createTestDb } from './helpers';

let db: Db;
let close: () => Promise<void>;

const sbom = (...names: string[]) => ({
  bomFormat: 'CycloneDX',
  specVersion: '1.5',
  components: names.map((name) => ({ type: 'library', name, version: '1.0.0', purl: `pkg:npm/${name}@1.0.0` })),
});

beforeEach(async () => {
  ({ db, close } = await createTestDb());
  await ingestSbom(db, sbom('a', 'shared'), {
    project: 'shop-web',
    repository: 'acme/shop',
    kind: 'application',
    tags: ['team:web', 'tier-1'],
  });
  await ingestSbom(db, sbom('b', 'shared', 'c'), { project: 'shop-sdk', repository: 'acme/shop', kind: 'library', tags: ['team:web'] });
  await ingestSbom(db, sbom('d'), { project: 'billing', repository: 'acme/billing', kind: 'application', tags: ['team:pay'] });
});
afterEach(async () => {
  await close();
});

const sp = (q: string) => new URLSearchParams(q);

describe('parseOverviewFilter', () => {
  test('reads kind, tag and repository, normalising each', () => {
    expect(parseOverviewFilter(sp('kind=Library&tag=Team:Web&repository=https://github.com/Acme/Shop.git'))).toEqual({
      ok: true,
      value: { kind: 'library', tag: 'team:web', repository: 'github.com/acme/shop' },
    });
  });
  test('blank values and unrelated params mean no filter', () => {
    expect(parseOverviewFilter(sp('kind=&stale=true&q=x'))).toEqual({ ok: true, value: {} });
  });
  test('a bad kind or repository is an error, not a silent no-filter', () => {
    expect(parseOverviewFilter(sp('kind=server')).ok).toBe(false);
    expect(parseOverviewFilter(sp('repository=not a repo')).ok).toBe(false);
  });
});

describe('getOverview with a filter', () => {
  test('without one it covers every project', async () => {
    const o = await getOverview(db);
    expect(o.projectCount).toBe(3);
    expect(o.stats.components).toBe(6);
  });

  test('a tag scopes the tiles, packages and project list to matching projects', async () => {
    const o = await getOverview(db, { tag: 'team:web' });
    expect(o.projects.map((p) => p.name).sort()).toEqual(['shop-sdk', 'shop-web']);
    expect(o.projectCount).toBe(2);
    expect(o.stats.components).toBe(5);
    expect(o.packageCount).toBe(4); // a, b, c, shared
  });

  test('kind, tag and repository combine with AND', async () => {
    expect((await getOverview(db, { kind: 'application', repository: 'github.com/acme/shop' })).projects.map((p) => p.name)).toEqual([
      'shop-web',
    ]);
    expect((await getOverview(db, { kind: 'library', tag: 'tier-1' })).projectCount).toBe(0);
  });

  test('filter options always list everything, so a narrowed view can be widened', async () => {
    const o = await getOverview(db, { tag: 'team:pay' });
    expect(o.facets).toEqual({
      kinds: ['application', 'library'],
      tags: ['team:pay', 'team:web', 'tier-1'],
      repositories: ['github.com/acme/billing', 'github.com/acme/shop'],
    });
  });

  test('an empty match is empty, with the unfiltered total kept for the empty state', async () => {
    const o = await getOverview(db, { tag: 'nope' });
    expect(o.projectCount).toBe(0);
    expect(o.stats.components).toBe(0);
    expect(o.totalProjectCount).toBe(3);
  });

  test('recent uploads are scoped too', async () => {
    const o = await getOverview(db, { tag: 'team:pay' });
    expect(o.recentUploads.map((u) => u.projectName)).toEqual(['billing']);
  });
});

describe('getSummaryTrend with project ids', () => {
  test('sums only the given projects', async () => {
    const [web, , billing] = (await listProjects(db)).sort((a, b) => a.id - b.id);
    const row = (projectId: number, v: number) => ({
      projectId,
      day: '2026-11-01',
      components: 1,
      vulnerableComponents: v,
      vulnerabilities: v,
      critical: 0,
      high: v,
      medium: 0,
      low: 0,
      unknown: 0,
      outdatedComponents: 0,
      outdatedMajor: 0,
    });
    await db.insert(schema.projectSnapshots).values([row(web.id, 2), row(billing.id, 5)]);
    const now = new Date('2026-11-02');
    expect((await getSummaryTrend(db, 30, now)).map((p) => p.vulnerabilities)).toEqual([7]);
    expect((await getSummaryTrend(db, 30, now, [billing.id])).map((p) => p.vulnerabilities)).toEqual([5]);
    expect(await getSummaryTrend(db, 30, now, [])).toEqual([]);
  });
});
