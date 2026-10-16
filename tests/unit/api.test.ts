import { afterEach, beforeEach, describe, expect, test, vi } from 'vitest';
import { setDb, type Db } from '@/db';
import { resetEnv } from '@/lib/env';
import { checkRateLimit, resetRateLimits } from '@/server/api';
import { POST as upload } from '@/app/api/v1/sboms/route';
import { GET as downloadSbom } from '@/app/api/v1/sboms/[id]/route';
import { DELETE as deleteProject, GET as getProject } from '@/app/api/v1/projects/[id]/route';
import { GET as getPackage } from '@/app/api/v1/packages/[key]/route';
import { GET as getVuln } from '@/app/api/v1/vulnerabilities/[id]/route';
import { GET as getSummary } from '@/app/api/v1/summary/route';
import { GET as listPackagesRoute } from '@/app/api/v1/packages/route';
import { listProjects, type ProjectDetail } from '@/server/inventory';
import { enrich } from '@/worker/enrich';
import { schema } from '@/db';
import { createTestDb, enrichOptions, fakeFetch, fixture, LODASH_VULN, type FakeApis } from './helpers';

const TOKEN = 'test-token';
const BASE = 'http://dash.test';
let db: Db;
let close: () => Promise<void>;

beforeEach(async () => {
  ({ db, close } = await createTestDb());
  setDb(db);
  process.env.UPLOAD_TOKENS = TOKEN;
  resetEnv();
  resetRateLimits();
});
afterEach(async () => {
  vi.unstubAllEnvs();
  delete process.env.UPLOAD_TOKENS;
  resetEnv();
  await close();
});

const params = <T>(p: T) => ({ params: Promise.resolve(p) });

function post(doc: unknown, query = '', headers: Record<string, string> = { authorization: `Bearer ${TOKEN}` }) {
  return upload(new Request(`${BASE}/api/v1/sboms${query}`, { method: 'POST', headers, body: JSON.stringify(doc) }));
}

async function project(id: number, sbom?: number): Promise<ProjectDetail> {
  const res = await getProject(new Request(`${BASE}/api/v1/projects/${id}${sbom ? `?sbom=${sbom}` : ''}`), params({ id: String(id) }));
  return res.json();
}

const APIS: FakeApis = {
  vulns: { 'pkg:npm/lodash@4.17.15': [LODASH_VULN.id] },
  osvVulns: { [LODASH_VULN.id]: LODASH_VULN },
  latest: {
    'npm:lodash': '4.17.21',
    'npm:express': '5.1.0',
    'npm:@babel/core': '7.24.0',
    'npm:qs': '6.14.0',
    'pypi:requests': '2.32.3',
  },
};

describe('upload API', () => {
  test('rejects bodies over MAX_UPLOAD_BYTES with 413, by header or by streamed size', async () => {
    process.env.MAX_UPLOAD_BYTES = '1000';
    resetEnv();
    try {
      const big = JSON.stringify({ pad: 'x'.repeat(2000) });
      const headers = { authorization: `Bearer ${TOKEN}` };
      const declared = await upload(
        new Request(`${BASE}/api/v1/sboms`, { method: 'POST', headers: { ...headers, 'content-length': '2000' }, body: big }),
      );
      expect(declared.status).toBe(413);
      // No content-length (chunked): the stream must be cut off at the limit.
      const stream = new ReadableStream({
        start(c) {
          c.enqueue(new TextEncoder().encode(big));
          c.close();
        },
      });
      const streamed = await upload(
        new Request(`${BASE}/api/v1/sboms`, { method: 'POST', headers, body: stream, duplex: 'half' } as RequestInit),
      );
      expect(streamed.status).toBe(413);
    } finally {
      delete process.env.MAX_UPLOAD_BYTES;
    }
  });

  test('rate limits write requests with 429 and Retry-After, then recovers', async () => {
    process.env.WRITE_RATE_LIMIT = '2';
    resetEnv();
    try {
      expect((await post({ nope: true })).status).toBe(400);
      expect((await post({ nope: true })).status).toBe(400);
      const limited = await post({ nope: true });
      expect(limited.status).toBe(429);
      expect(Number(limited.headers.get('retry-after'))).toBeGreaterThan(0);
      const later = checkRateLimit(new Request(`${BASE}/x`), Date.now() + 61_000);
      expect(later).toBeNull();
    } finally {
      delete process.env.WRITE_RATE_LIMIT;
    }
  });

  test('requires a valid token when UPLOAD_TOKENS is set', async () => {
    expect((await post(fixture('cyclonedx.json'), '', {})).status).toBe(401);
    expect((await post(fixture('cyclonedx.json'), '', { authorization: 'Bearer wrong' })).status).toBe(401);
  });

  test('accepts uploads without a token when UPLOAD_TOKENS is empty', async () => {
    delete process.env.UPLOAD_TOKENS;
    resetEnv();
    expect((await post(fixture('cyclonedx.json'), '', {})).status).toBe(201);
  });

  test('fails closed in production when no tokens are configured', async () => {
    delete process.env.UPLOAD_TOKENS;
    vi.stubEnv('NODE_ENV', 'production');
    resetEnv();
    expect((await post(fixture('cyclonedx.json'), '', {})).status).toBe(503);
    vi.stubEnv('ALLOW_OPEN_UPLOADS', 'true');
    resetEnv();
    expect((await post(fixture('cyclonedx.json'), '', {})).status).toBe(201);
    vi.unstubAllEnvs();
  });

  test('rejects bodies that are not a supported SBOM', async () => {
    const bad = await upload(
      new Request(`${BASE}/api/v1/sboms`, { method: 'POST', headers: { authorization: `Bearer ${TOKEN}` }, body: 'nope' }),
    );
    expect(bad.status).toBe(400);
    const unknown = await post({ hello: 'world' });
    expect(unknown.status).toBe(400);
    expect((await unknown.json()).error).toMatch(/Unsupported SBOM format/);
  });

  test('reads metadata from query parameters and headers', async () => {
    const res = await post(fixture('cyclonedx.json'), '?ref=refs/heads/main', {
      authorization: `Bearer ${TOKEN}`,
      'x-sbom-commit': 'abc123',
      'x-sbom-repository': 'acme/web',
    });
    expect(res.status).toBe(201);
    const body = await res.json();
    expect(body).toMatchObject({ projectName: 'web-app', componentCount: 5, url: `${BASE}/projects/${body.projectId}` });
    const p = await project(body.projectId);
    expect(p.repository).toBe('acme/web');
    expect(p.latest).toMatchObject({ version: '2.3.0', ref: 'refs/heads/main', commit: 'abc123', format: 'CycloneDX' });

    const download = await downloadSbom(new Request(`${BASE}/api/v1/sboms/${body.sbomId}`), params({ id: String(body.sbomId) }));
    expect((await download.json()).bomFormat).toBe('CycloneDX');
  });
});

describe('enrichment and inventory', () => {
  test('end-to-end: CVEs, outdated packages and cross-project views', async () => {
    const web = await (await post(fixture('cyclonedx.json'))).json();
    expect((await post(fixture('spdx.json'), '?project=api-service&version=1.0.0')).status).toBe(201);

    // Before enrichment, everything is pending.
    expect((await project(web.projectId)).stats.pending).toBe(4);

    const calls: string[] = [];
    const stats = await enrich(db, enrichOptions({ ...APIS, calls }));
    expect(stats).toMatchObject({ versionsScanned: 5, vulnsFetched: 1, packagesChecked: 5, errors: 0 });
    // Scoped npm names must be URL-encoded for deps.dev.
    expect(calls).toContain('https://depsdev.test/v3/systems/npm/packages/%40babel%2Fcore');

    const projects = await listProjects(db);
    expect(projects.map((p) => p.name)).toEqual(['api-service', 'web-app']);
    const webSummary = projects.find((p) => p.name === 'web-app')!;
    expect(webSummary.stats).toMatchObject({
      vulnerabilities: 1,
      severity: { HIGH: 1 },
      outdated: { major: 1, minor: 1, patch: 1 },
      pending: 0,
    });

    const detail = await project(web.projectId);
    const lodash = detail.components.find((c) => c.name === 'lodash')!;
    expect(lodash).toMatchObject({ latestVersion: '4.17.21', outdated: 'patch', fixVersion: '4.17.19', maxSeverity: 'HIGH' });
    expect(lodash.vulns[0]).toMatchObject({ cve: 'CVE-2020-8203', score: 7.4 });
    expect(detail.components.find((c) => c.name === 'internal-thing')!.vulnStatus).toBe('unsupported');

    const packages = await (await listPackagesRoute()).json();
    expect(packages.find((p: { key: string }) => p.key === 'npm:lodash')).toMatchObject({ projectCount: 2, vulnCount: 1 });

    const pkg = await (await getPackage(new Request(BASE), params({ key: 'npm%3Alodash' }))).json();
    expect(pkg.vulnerabilities).toHaveLength(1);
    expect(pkg.versions[0].projects).toHaveLength(2);

    const vuln = await (await getVuln(new Request(BASE), params({ id: LODASH_VULN.id }))).json();
    expect(vuln.affected[0].fixVersion).toBe('4.17.19');
    expect(vuln.projects.map((p: { name: string }) => p.name).sort()).toEqual(['api-service', 'web-app']);

    const summary = await (await getSummary()).json();
    expect(summary).toMatchObject({ projectCount: 2, vulnerablePackages: 1 });
    expect(summary.recentUploads).toHaveLength(2);

    // A second run within the TTL does nothing.
    expect(await enrich(db, enrichOptions(APIS))).toMatchObject({ versionsScanned: 0, packagesChecked: 0 });
  });

  test('retries versions whose vulnerability details could not be fetched', async () => {
    await post(fixture('cyclonedx.json'));
    const missingDetails = { ...APIS, osvVulns: {} };
    expect(await enrich(db, enrichOptions(missingDetails))).toMatchObject({ errors: 0, vulnsFetched: 0 });
    const [lodash] = (await db.select().from(schema.packageVersions)).filter((v) => v.packageKey === 'npm:lodash');
    expect(lodash.vulnsCheckedAt).toBeNull();
    expect(lodash.vulnsError).toMatch(/could not fetch/);
    await enrich(db, enrichOptions(APIS));
    const [after] = (await db.select().from(schema.packageVersions)).filter((v) => v.packageKey === 'npm:lodash');
    expect(after.vulnsCheckedAt).not.toBeNull();
  });
  test('a failing OSV.dev does not block latest-version checks', async () => {
    await post(fixture('cyclonedx.json'));
    const healthy = fakeFetch(APIS);
    const osvDown: typeof fetch = async (input, init) =>
      new URL(input.toString()).hostname === 'osv.test' ? new Response('unavailable', { status: 503 }) : healthy(input, init);
    const stats = await enrich(db, { ...enrichOptions(), fetchImpl: osvDown, logger: { info() {}, warn() {}, error() {} } });
    expect(stats.errors).toBe(1);
    expect(stats.packagesChecked).toBe(4);
    const versions = await db.select().from(schema.packageVersions);
    expect(versions.every((v) => v.vulnsCheckedAt === null)).toBe(true);
  });
});

describe('history and deletion', () => {
  test('re-uploading replaces the latest SBOM and keeps history', async () => {
    const doc = fixture('cyclonedx.json');
    await post(doc, '?version=1');
    doc.components = doc.components.slice(0, 1);
    const second = await (await post(doc, '?version=2')).json();

    const detail = await project(second.projectId);
    expect(detail.latest?.version).toBe('2');
    expect(detail.components).toHaveLength(1);
    expect(detail.history.map((h) => h.version)).toEqual(['2', '1']);
    expect((await project(second.projectId, detail.history[1].id)).components).toHaveLength(5);

    // Packages only referenced by older SBOMs drop out of the cross-project view.
    const packages = await (await listPackagesRoute()).json();
    expect(packages.map((p: { name: string }) => p.name)).toEqual(['lodash']);

    const del = await deleteProject(
      new Request(BASE, { method: 'DELETE', headers: { authorization: `Bearer ${TOKEN}` } }),
      params({ id: String(second.projectId) }),
    );
    expect(del.status).toBe(204);
    expect(await db.select().from(schema.packages)).toHaveLength(0);
  });
});
