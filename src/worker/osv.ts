// Vulnerability lookups against the OSV.dev API (https://google.github.io/osv.dev/api/).
import { z } from 'zod';
import { basePurl, displayName, type PackageRef } from '@/lib/purl';
import { compareVersions } from '@/lib/version';
import { cvss3Score, normalizeSeverity, ratingFromScore, type Severity } from '@/lib/severity';
import { fetchJson, HttpError, type FetchFn } from './http';

/** purl types OSV can map to one of its ecosystems. */
export const OSV_TYPES = new Set([
  'npm', 'pypi', 'maven', 'golang', 'cargo', 'gem', 'nuget', 'composer', 'hex', 'pub',
  'deb', 'apk', 'rpm', 'swift', 'cran', 'hackage', 'conan', 'bitnami', 'github',
]);

const severityEntry = z.looseObject({ type: z.string(), score: z.string() });
export const osvVulnSchema = z.looseObject({
  id: z.string(),
  aliases: z.array(z.string()).nullish(),
  summary: z.string().nullish(),
  details: z.string().nullish(),
  published: z.string().nullish(),
  modified: z.string().nullish(),
  severity: z.array(severityEntry).nullish(),
  database_specific: z.looseObject({ severity: z.unknown().optional() }).nullish(),
  references: z.array(z.looseObject({ type: z.string(), url: z.string() })).nullish(),
  affected: z
    .array(
      z.looseObject({
        package: z.looseObject({ ecosystem: z.string().nullish(), name: z.string().nullish(), purl: z.string().nullish() }).nullish(),
        severity: z.array(severityEntry).nullish(),
        ranges: z
          .array(z.looseObject({ type: z.string(), events: z.array(z.record(z.string(), z.string())).nullish() }))
          .nullish(),
        ecosystem_specific: z.looseObject({ severity: z.unknown().optional() }).nullish(),
        database_specific: z.looseObject({ severity: z.unknown().optional() }).nullish(),
      }),
    )
    .nullish(),
});
export type OsvVuln = z.infer<typeof osvVulnSchema>;

const queryResult = z.looseObject({
  vulns: z.array(z.looseObject({ id: z.string() })).nullish(),
  next_page_token: z.string().nullish(),
});
const batchResponse = z.looseObject({ results: z.array(queryResult) });

export interface VersionQuery {
  pkg: PackageRef;
  version: string;
}
export type QueryResult = { vulnIds: string[] } | { error: string };

const toQuery = ({ pkg, version }: VersionQuery) => ({ package: { purl: basePurl(pkg) }, version });

/** Looks up vulnerability ids for many package versions; results align with `items`. */
export async function queryBatch(fetchImpl: FetchFn, baseUrl: string, items: VersionQuery[]): Promise<QueryResult[]> {
  if (!items.length) {return [];}
  try {
    const data = await fetchJson(fetchImpl, `${baseUrl}/v1/querybatch`, batchResponse, {
      method: 'POST',
      body: { queries: items.map(toQuery) },
    });
    return Promise.all(
      items.map(async (item, i) => {
        const r = data?.results[i];
        const ids = (r?.vulns ?? []).map((v) => v.id);
        if (r?.next_page_token) {ids.push(...(await queryAllPages(fetchImpl, baseUrl, item, r.next_page_token)));}
        return { vulnIds: [...new Set(ids)] };
      }),
    );
  } catch (err) {
    // One malformed query fails the whole batch; fall back to per-item queries.
    if (err instanceof HttpError && err.status === 400 && items.length > 1) {
      return Promise.all(
        items.map(async (item) => {
          try {
            return { vulnIds: await queryAllPages(fetchImpl, baseUrl, item) };
          } catch (e) {
            return { error: (e as Error).message };
          }
        }),
      );
    }
    throw err;
  }
}

async function queryAllPages(fetchImpl: FetchFn, baseUrl: string, item: VersionQuery, pageToken?: string) {
  const ids: string[] = [];
  let token = pageToken;
  do {
    const data = await fetchJson(fetchImpl, `${baseUrl}/v1/query`, queryResult, {
      method: 'POST',
      body: { ...toQuery(item), ...(token ? { page_token: token } : {}) },
    });
    ids.push(...(data?.vulns ?? []).map((v) => v.id));
    token = data?.next_page_token ?? undefined;
  } while (token);
  return ids;
}

export function fetchVuln(fetchImpl: FetchFn, baseUrl: string, id: string) {
  return fetchJson(fetchImpl, `${baseUrl}/v1/vulns/${encodeURIComponent(id)}`, osvVulnSchema);
}

/** Severity from CVSS v3 vectors, falling back to the advisory database's own label. */
export function osvSeverity(vuln: OsvVuln): { severity: Severity; score: number | null; vector: string | null } {
  const entries = [...(vuln.severity ?? []), ...(vuln.affected ?? []).flatMap((a) => a.severity ?? [])];
  for (const e of entries) {
    if (e.type === 'CVSS_V3') {
      const score = cvss3Score(e.score);
      if (score !== null) {return { severity: ratingFromScore(score), score, vector: e.score };}
    }
  }
  const label =
    vuln.database_specific?.severity ??
    (vuln.affected ?? []).map((a) => a.ecosystem_specific?.severity ?? a.database_specific?.severity).find(Boolean);
  return { severity: normalizeSeverity(label), score: null, vector: entries.find((e) => e.type === 'CVSS_V4')?.score ?? null };
}

export function vulnRecord(vuln: OsvVuln) {
  const { severity, score, vector } = osvSeverity(vuln);
  const date = (s: string | null | undefined) => (s ? new Date(s) : null);
  return {
    id: vuln.id,
    aliases: vuln.aliases ?? [],
    summary: vuln.summary || (vuln.details ?? '').split('\n')[0].slice(0, 300) || null,
    details: (vuln.details ?? '').slice(0, 8000) || null,
    severity,
    score,
    vector,
    published: date(vuln.published),
    modified: date(vuln.modified),
    references: (vuln.references ?? []).slice(0, 15).map((r) => ({ type: r.type, url: r.url })),
  };
}

const normalizeName = (type: string, name: string) =>
  type === 'pypi' ? name.toLowerCase().replace(/[-_.]+/g, '-') : name.toLowerCase();

/** Versions that fix `vuln` for the given package, from the matching "affected" entries. */
export function fixedVersions(vuln: OsvVuln, pkg: PackageRef): string[] {
  const want = normalizeName(pkg.type, displayName(pkg));
  const purl = basePurl(pkg).toLowerCase();
  const affected = vuln.affected ?? [];
  const matching = affected.filter((a) => {
    const p = a.package;
    if (p?.purl && p.purl.split('@')[0].toLowerCase() === purl) {return true;}
    return !!p?.name && normalizeName(pkg.type, p.name) === want;
  });
  const fixed = new Set<string>();
  for (const a of matching.length ? matching : affected) {
    for (const range of a.ranges ?? []) {
      if (range.type === 'GIT') {continue;}
      for (const e of range.events ?? []) {if (e.fixed) {fixed.add(e.fixed);}}
    }
  }
  return [...fixed].sort(compareVersions);
}
