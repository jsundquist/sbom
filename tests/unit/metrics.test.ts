import { afterEach, beforeEach, describe, expect, test, vi } from 'vitest';
import { NextRequest } from 'next/server';
import { schema, setDb, type Db } from '@/db';
import { resetEnv } from '@/lib/env';
import { proxy } from '@/proxy';
import { resetRateLimits } from '@/server/api';
import { ingestSbom } from '@/server/ingest';
import { formatMetrics, getMetrics, WORKER_FEED } from '@/server/metrics';
import { emptySeverityCounts, type ProjectSummary } from '@/server/inventory';
import { recordFeedSuccess } from '@/worker/feeds';
import { GET } from '@/app/metrics/route';
import { enrich } from '@/worker/enrich';
import { createTestDb, enrichOptions } from './helpers';

const NOW = new Date('2026-11-17T12:00:00Z');

function project(over: Partial<ProjectSummary> & { name: string }): ProjectSummary {
  return {
    id: 1,
    repository: null,
    kind: 'application',
    tags: [],
    createdAt: NOW.toISOString(),
    updatedAt: NOW.toISOString(),
    uploadCount: 1,
    latest: null,
    stale: false,
    stats: {
      components: 0,
      vulnerableComponents: 0,
      outdatedComponents: 0,
      vulnerabilities: 0,
      exploited: 0,
      severity: emptySeverityCounts(),
      outdated: { major: 0, minor: 0, patch: 0, unknown: 0 } as never,
      pending: 0,
    },
    ...over,
  } as ProjectSummary;
}

describe('formatMetrics', () => {
  test('emits gauges labelled by project and severity only', () => {
    const p = project({
      name: 'web',
      stale: true,
      latest: { uploadedAt: new Date(NOW.getTime() - 3600e3).toISOString() } as never,
    });
    p.stats.severity.CRITICAL = 2;
    p.stats.exploited = 1;
    const out = formatMetrics([p], null, NOW);
    expect(out).toContain('# TYPE sbom_vulnerabilities gauge');
    expect(out).toContain('sbom_vulnerabilities{project="web",severity="CRITICAL"} 2');
    expect(out).toContain('sbom_vulnerabilities{project="web",severity="LOW"} 0');
    expect(out).toContain('sbom_exploited_vulnerabilities{project="web"} 1');
    expect(out).toContain('sbom_age_seconds{project="web"} 3600');
    expect(out).toContain('sbom_stale{project="web"} 1');
    expect(out.endsWith('\n')).toBe(true);
  });

  test('a project without an SBOM has no age sample', () => {
    const out = formatMetrics([project({ name: 'empty' })], null, NOW);
    expect(out).not.toContain('sbom_age_seconds{');
    expect(out).toContain('sbom_stale{project="empty"} 0');
  });

  test('escapes backslash, quote and newline in label values', () => {
    const out = formatMetrics([project({ name: 'a"b\\c\nd' })], null, NOW);
    expect(out).toContain('project="a\\"b\\\\c\\nd"');
  });

  test('worker timestamp is omitted until the worker has succeeded, then in seconds', () => {
    expect(formatMetrics([], null, NOW)).not.toMatch(/^sbom_worker_last_success_timestamp_seconds /m);
    expect(formatMetrics([], new Date('2026-11-17T00:00:00Z'), NOW)).toContain('sbom_worker_last_success_timestamp_seconds 1794873600');
  });
});

describe('getMetrics and GET /metrics', () => {
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
        components: [{ type: 'library', name: 'x', version: '1.0.0', purl: 'pkg:npm/x@1.0.0' }],
      },
      { project: 'svc', version: '1' },
    );
  });
  afterEach(async () => {
    vi.unstubAllEnvs();
    resetEnv();
    resetRateLimits();
    await close();
  });

  test('reads projects and the worker feed_syncs row', async () => {
    const at = new Date('2026-11-17T11:00:00Z');
    await recordFeedSuccess(db, WORKER_FEED, at);
    const out = await getMetrics(db, NOW);
    expect(out).toContain('sbom_stale{project="svc"} 0');
    expect(out).toContain(`sbom_worker_last_success_timestamp_seconds ${at.getTime() / 1000}`);
    expect(schema.feedSyncs).toBeDefined();
  });

  test('route answers text exposition format', async () => {
    const res = await GET(new Request('http://dash.test/metrics'));
    expect(res.status).toBe(200);
    expect(res.headers.get('content-type')).toContain('text/plain; version=0.0.4');
    expect(res.headers.get('cache-control')).toBe('no-store');
    expect(await res.text()).toContain('sbom_vulnerabilities{project="svc"');
  });

  describe('access', () => {
    const configure = () => {
      vi.stubEnv('NEXTAUTH_SECRET', 'test-secret-test-secret-test-secret');
      vi.stubEnv('NEXTAUTH_URL', 'http://dash.test');
      vi.stubEnv('GITHUB_CLIENT_ID', 'cid');
      vi.stubEnv('GITHUB_CLIENT_SECRET', 'csecret');
      vi.stubEnv('OWNER_GITHUB_ID', '4242');
      vi.stubEnv('READ_TOKENS', 'scrape-token');
      resetEnv();
    };
    const call = (headers: Record<string, string> = {}, path = '/metrics') => new Request(`http://dash.test${path}`, { headers });

    test('a read token scrapes; no or wrong token is 401', async () => {
      configure();
      expect((await GET(call({ authorization: 'Bearer scrape-token' }))).status).toBe(200);
      expect((await GET(call())).status).toBe(401);
      expect((await GET(call({ authorization: 'Bearer nope' }))).status).toBe(401);
    });

    test('proxy lets a read token through and answers 401 JSON otherwise (no redirect)', async () => {
      configure();
      const nreq = (headers: Record<string, string> = {}) => new NextRequest('http://dash.test/metrics', { headers });
      expect((await proxy(nreq({ authorization: 'Bearer scrape-token' }))).headers.get('x-middleware-next')).toBe('1');
      const anon = await proxy(nreq());
      expect(anon.status).toBe(401);
      expect(anon.headers.get('location')).toBeNull();
    });

    test('a read token does not open other non-v1 paths', async () => {
      configure();
      const res = await proxy(new NextRequest('http://dash.test/metrics/x', { headers: { authorization: 'Bearer scrape-token' } }));
      expect(res.status).not.toBe(200);
    });
  });
});

describe('worker heartbeat', () => {
  test('enrich stamps feed_syncs on a clean run', async () => {
    const t = await createTestDb();
    await enrich(t.db, { ...enrichOptions({}), logger: { info() {}, warn() {}, error() {} } });
    const rows = await t.db.select().from(schema.feedSyncs);
    expect(rows.find((r) => r.name === WORKER_FEED)?.syncedAt).toBeInstanceOf(Date);
    await t.close();
  });
});
