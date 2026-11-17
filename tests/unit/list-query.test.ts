import { afterEach, beforeEach, describe, expect, test, vi } from 'vitest';
import { setDb, type Db } from '@/db';
import { resetEnv } from '@/lib/env';
import { parsePackageFilter, parsePage, parseProjectFilter, parseVulnerabilityFilter } from '@/lib/params';
import { GET as projectsRoute } from '@/app/api/v1/projects/route';
import { GET as packagesRoute } from '@/app/api/v1/packages/route';
import { GET as vulnsRoute } from '@/app/api/v1/vulnerabilities/route';
import { ingestSbom } from '@/server/ingest';
import { schema } from '@/db';
import { eq } from 'drizzle-orm';
import { createTestDb } from './helpers';

const sp = (q: string) => new URLSearchParams(q);

describe('parsePage', () => {
  test('defaults to unlimited from offset 0', () => {
    expect(parsePage(sp(''))).toEqual({ ok: true, value: { limit: undefined, offset: 0 } });
  });
  test('accepts limit up to 1000 and an offset', () => {
    expect(parsePage(sp('limit=1000&offset=5'))).toEqual({ ok: true, value: { limit: 1000, offset: 5 } });
  });
  test.each(['limit=0', 'limit=1001', 'limit=abc', 'limit=1.5', 'offset=-1', 'offset=x'])('rejects %s', (q) => {
    expect(parsePage(sp(q)).ok).toBe(false);
  });
});

describe('filter parsers', () => {
  test('projects', () => {
    expect(parseProjectFilter(sp('kind=Library&tag=Team:A&stale=true&q=web&repository=acme/shop'))).toEqual({
      ok: true,
      value: { kind: 'library', tag: 'team:a', stale: true, q: 'web', repository: 'github.com/acme/shop' },
    });
    expect(parseProjectFilter(sp('kind=')).ok).toBe(true);
    expect(parseProjectFilter(sp('kind=robot')).ok).toBe(false);
    expect(parseProjectFilter(sp('stale=maybe')).ok).toBe(false);
    expect(parseProjectFilter(sp('repository=%20bad%20repo')).ok).toBe(false);
  });
  test('packages', () => {
    expect(parsePackageFilter(sp('ecosystem=NPM&deprecated=false&abandoned=true'))).toEqual({
      ok: true,
      value: { ecosystem: 'npm', deprecated: false, abandoned: true },
    });
    expect(parsePackageFilter(sp('deprecated=1')).ok).toBe(false);
  });
  test('vulnerabilities', () => {
    expect(parseVulnerabilityFilter(sp('severity=high&exploited=true&project=3'))).toEqual({
      ok: true,
      value: { severity: 'HIGH', exploited: true, project: 3 },
    });
    expect(parseVulnerabilityFilter(sp('severity=scary')).ok).toBe(false);
    expect(parseVulnerabilityFilter(sp('project=0')).ok).toBe(false);
  });
});

let db: Db;
let close: () => Promise<void>;
const get = (route: (r: Request) => Promise<Response>, q = '') => route(new Request(`http://dash.test/api/v1/x${q}`));
const sbom = (...names: string[]) => ({
  bomFormat: 'CycloneDX',
  specVersion: '1.5',
  components: names.map((name) => ({
    type: 'library',
    name,
    version: '1.0.0',
    purl: `pkg:${name.startsWith('py') ? 'pypi' : 'npm'}/${name}@1.0.0`,
  })),
});

beforeEach(async () => {
  ({ db, close } = await createTestDb());
  setDb(db);
  resetEnv();
  await ingestSbom(db, sbom('alpha', 'pyshared'), { project: 'web', kind: 'application', tags: ['team:a'], repository: 'acme/web' });
  await ingestSbom(db, sbom('beta'), { project: 'lib', kind: 'library', tags: ['team:b'] });
  await ingestSbom(db, sbom('gamma'), { project: 'old', kind: 'application' });
  await db
    .update(schema.sboms)
    .set({ uploadedAt: new Date('2000-01-01') })
    .where(
      eq(
        schema.sboms.id,
        (await db.select({ id: schema.projects.latestSbomId }).from(schema.projects).where(eq(schema.projects.name, 'old')))[0].id!,
      ),
    );
  await ingestSbom(db, sbom('delta'), { project: 'fresh', kind: 'application' });
});
afterEach(async () => {
  vi.unstubAllEnvs();
  resetEnv();
  await close();
});

const names = async (res: Response) => (await res.json()).map((p: { name: string }) => p.name);

describe('GET /api/v1/projects', () => {
  test('without params returns everything as a bare array with the total', async () => {
    const res = await get(projectsRoute);
    expect(res.headers.get('X-Total-Count')).toBe('4');
    expect(await names(res)).toEqual(['fresh', 'lib', 'old', 'web']);
  });
  test('limit and offset page the list while X-Total-Count stays the match count', async () => {
    const res = await get(projectsRoute, '?limit=2&offset=1');
    expect(await names(res)).toEqual(['lib', 'old']);
    expect(res.headers.get('X-Total-Count')).toBe('4');
  });
  test('offset past the end is an empty array', async () => {
    const res = await get(projectsRoute, '?offset=10');
    expect(await res.json()).toEqual([]);
    expect(res.headers.get('X-Total-Count')).toBe('4');
  });
  test('filters by kind, tag, stale, q and repository; total counts matches', async () => {
    expect(await names(await get(projectsRoute, '?kind=library'))).toEqual(['lib']);
    expect(await names(await get(projectsRoute, '?tag=team:a'))).toEqual(['web']);
    expect(await names(await get(projectsRoute, '?stale=true'))).toEqual(['old']);
    expect(await names(await get(projectsRoute, '?q=WE'))).toEqual(['web']);
    const res = await get(projectsRoute, '?repository=acme/web&limit=1');
    expect(await names(res)).toEqual(['web']);
    expect(res.headers.get('X-Total-Count')).toBe('1');
    expect(await names(await get(projectsRoute, '?kind=application&stale=false'))).toEqual(['fresh', 'web']);
  });
  test.each(['?limit=0', '?limit=1001', '?kind=robot', '?stale=maybe', '?repository=%20bad%20repo'])('%s is 400', async (q) => {
    expect((await get(projectsRoute, q)).status).toBe(400);
  });
});

describe('GET /api/v1/packages', () => {
  test('filters by ecosystem and q, pages with a total', async () => {
    const all = await get(packagesRoute);
    expect(all.headers.get('X-Total-Count')).toBe('5');
    const py = await get(packagesRoute, '?ecosystem=pypi');
    expect((await py.json()).map((p: { name: string }) => p.name)).toEqual(['pyshared']);
    const paged = await get(packagesRoute, '?q=ta&limit=1');
    expect((await paged.json()).length).toBe(1);
    expect(paged.headers.get('X-Total-Count')).toBe('2');
  });
  test('deprecated and abandoned flags', async () => {
    expect(await (await get(packagesRoute, '?deprecated=true')).json()).toEqual([]);
    expect((await get(packagesRoute, '?abandoned=false')).headers.get('X-Total-Count')).toBe('5');
  });
  test('400 on bad values', async () => {
    expect((await get(packagesRoute, '?deprecated=1')).status).toBe(400);
    expect((await get(packagesRoute, '?limit=x')).status).toBe(400);
  });
});

describe('GET /api/v1/vulnerabilities', () => {
  test('filters by severity, exploited, project and q', async () => {
    await db.insert(schema.vulnerabilities).values([
      { id: 'GHSA-aaaa', summary: 'Prototype pollution', severity: 'HIGH', aliases: ['CVE-2024-0001'] },
      { id: 'GHSA-bbbb', summary: 'Denial of service', severity: 'LOW', aliases: [] },
    ]);
    await db.insert(schema.versionVulnerabilities).values([
      { packageKey: 'npm:alpha', version: '1.0.0', vulnerabilityId: 'GHSA-aaaa' },
      { packageKey: 'npm:beta', version: '1.0.0', vulnerabilityId: 'GHSA-bbbb' },
    ]);
    await db.insert(schema.kevEntries).values({ cveId: 'CVE-2024-0001', dateAdded: '2024-01-01' });

    const ids = async (q: string) => (await (await get(vulnsRoute, q)).json()).map((v: { id: string }) => v.id);
    expect(await ids('')).toEqual(['GHSA-aaaa', 'GHSA-bbbb']);
    expect(await ids('?severity=low')).toEqual(['GHSA-bbbb']);
    expect(await ids('?exploited=true')).toEqual(['GHSA-aaaa']);
    expect(await ids('?exploited=false')).toEqual(['GHSA-bbbb']);
    expect(await ids('?q=pollution')).toEqual(['GHSA-aaaa']);
    expect(await ids('?q=cve-2024-0001')).toEqual(['GHSA-aaaa']);
    const [web] = await db.select().from(schema.projects).where(eq(schema.projects.name, 'web'));
    expect(await ids(`?project=${web.id}`)).toEqual(['GHSA-aaaa']);
    const paged = await get(vulnsRoute, '?limit=1&offset=1');
    expect((await paged.json()).map((v: { id: string }) => v.id)).toEqual(['GHSA-bbbb']);
    expect(paged.headers.get('X-Total-Count')).toBe('2');
  });
  test('400 on bad values', async () => {
    expect((await get(vulnsRoute, '?severity=scary')).status).toBe(400);
    expect((await get(vulnsRoute, '?project=0')).status).toBe(400);
  });
});
