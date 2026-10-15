import fs from 'node:fs';
import path from 'node:path';
import { PGlite } from '@electric-sql/pglite';
import { drizzle } from 'drizzle-orm/pglite';
import { migrate } from 'drizzle-orm/pglite/migrator';
import type { Db } from '@/db';
import * as schema from '@/db/schema';
import type { FetchFn } from '@/worker/http';
import type { OsvVuln } from '@/worker/osv';

const root = path.resolve(import.meta.dirname, '..', '..');

export const fixture = (name: string) => JSON.parse(fs.readFileSync(path.join(root, 'tests', 'fixtures', name), 'utf8'));

/** Fresh in-memory Postgres with all migrations applied. */
export async function createTestDb(): Promise<{ db: Db; close: () => Promise<void> }> {
  const client = new PGlite();
  const db = drizzle(client, { schema });
  await migrate(db, { migrationsFolder: path.join(root, 'drizzle') });
  return { db: db as unknown as Db, close: () => client.close() };
}

export interface FakeApis {
  /** "<base purl>@<version>" -> vulnerability ids */
  vulns?: Record<string, string[]>;
  osvVulns?: Record<string, OsvVuln>;
  /** "<deps.dev system>:<name>" -> latest version */
  latest?: Record<string, string>;
  /** CISA KEV catalog served at https://kev.test/kev.json; `null` makes the feed fail with HTTP 503. */
  kev?: KevFeedEntry[] | null;
  /** FIRST EPSS API served at https://epss.test/epss; CVEs not listed are omitted like the real API; `null` fails with HTTP 503. */
  epss?: Record<string, { epss: number; percentile: number }> | null;
  calls?: string[];
}

export interface KevFeedEntry {
  cveID: string;
  vendorProject?: string;
  product?: string;
  vulnerabilityName?: string;
  dateAdded: string;
  dueDate?: string;
  knownRansomwareCampaignUse?: string;
}

/** Fake OSV.dev + deps.dev backend. */
export function fakeFetch({ vulns = {}, osvVulns = {}, latest = {}, kev, epss, calls = [] }: FakeApis = {}): FetchFn {
  const json = (body: unknown, status = 200) => new Response(JSON.stringify(body), { status });
  return (async (input: string | URL | Request, init?: RequestInit) => {
    const url = new URL(input.toString());
    calls.push(url.toString());
    if (url.hostname === 'kev.test') {
      return kev ? json({ catalogVersion: 'test', count: kev.length, vulnerabilities: kev }) : json({}, 503);
    }
    if (url.hostname === 'epss.test') {
      if (!epss) {return json({}, 503);}
      const wanted = (url.searchParams.get('cve') ?? '').split(',').filter(Boolean);
      const data = wanted
        .filter((cve) => epss[cve])
        .map((cve) => ({ cve, epss: epss[cve].epss.toFixed(9), percentile: epss[cve].percentile.toFixed(9), date: '2026-10-14' }));
      return json({ status: 'OK', total: data.length, offset: 0, limit: 100, data });
    }
    if (url.pathname === '/v1/querybatch') {
      const { queries } = JSON.parse(String(init?.body)) as { queries: { package: { purl: string }; version: string }[] };
      return json({
        results: queries.map((q) => ({ vulns: (vulns[`${q.package.purl}@${q.version}`] ?? []).map((id) => ({ id })) })),
      });
    }
    if (url.pathname.startsWith('/v1/vulns/')) {
      const id = decodeURIComponent(url.pathname.slice('/v1/vulns/'.length));
      return osvVulns[id] ? json(osvVulns[id]) : json({ message: 'not found' }, 404);
    }
    const m = url.pathname.match(/^\/v3\/systems\/([^/]+)\/packages\/(.+)$/);
    if (m) {
      const v = latest[`${m[1]}:${decodeURIComponent(m[2])}`];
      if (!v) {return json({}, 404);}
      return json({ versions: [{ versionKey: { version: '0.0.1' }, isDefault: false }, { versionKey: { version: v }, isDefault: true }] });
    }
    return json({}, 404);
  }) as FetchFn;
}

export const LODASH_VULN: OsvVuln = {
  id: 'GHSA-p6mc-m468-83gw',
  aliases: ['CVE-2020-8203'],
  summary: 'Prototype Pollution in lodash',
  severity: [{ type: 'CVSS_V3', score: 'CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:H/A:H' }],
  affected: [
    {
      package: { ecosystem: 'npm', name: 'lodash', purl: 'pkg:npm/lodash' },
      ranges: [{ type: 'SEMVER', events: [{ introduced: '0' }, { fixed: '4.17.19' }] }],
    },
  ],
};

export const enrichOptions = (apis: FakeApis = {}) => ({
  fetchImpl: fakeFetch(apis),
  osvApiUrl: 'https://osv.test',
  depsDevApiUrl: 'https://depsdev.test',
  vulnTtlHours: 12,
  latestTtlHours: 24,
});

export const kevOptions = { kevUrl: 'https://kev.test/kev.json', kevTtlHours: 24 };

/** Requests in `calls` that were sent to `hostname` (compares the parsed host, not a URL prefix). */
export const callsTo = (calls: string[], hostname: string) => calls.filter((c) => new URL(c).hostname === hostname);

export const epssOptions = { epssUrl: 'https://epss.test/epss', epssTtlHours: 24 };
