// Vulnerability lookups against the OSV.dev API (https://google.github.io/osv.dev/api/).
import { basePurl, displayName } from '../lib/purl.js';
import { compareVersions } from '../lib/version.js';
import { osvSeverity } from '../lib/severity.js';
import { fetchJson } from './http.js';

// purl types OSV can resolve to an ecosystem.
export const OSV_TYPES = new Set([
  'npm', 'pypi', 'maven', 'golang', 'cargo', 'gem', 'nuget', 'composer', 'hex', 'pub',
  'deb', 'apk', 'rpm', 'swift', 'cran', 'hackage', 'conan', 'bitnami', 'github',
]);

export function osvQuery(pkg, version) {
  return { package: { purl: basePurl(pkg) }, version };
}

/**
 * Queries OSV for many package versions. `items` = [{ pkg, version }].
 * Returns an array aligned with items: { vulnIds: string[] } | { error }.
 */
export async function queryBatch(fetchImpl, baseUrl, items) {
  if (!items.length) return [];
  try {
    const data = await fetchJson(fetchImpl, `${baseUrl}/v1/querybatch`, {
      method: 'POST',
      body: { queries: items.map((i) => osvQuery(i.pkg, i.version)) },
    });
    const results = data?.results || [];
    return Promise.all(
      items.map(async (item, idx) => {
        const r = results[idx] || {};
        const ids = (r.vulns || []).map((v) => v.id);
        if (r.next_page_token) ids.push(...(await queryAllPages(fetchImpl, baseUrl, item, r.next_page_token)));
        return { vulnIds: [...new Set(ids)] };
      }),
    );
  } catch (err) {
    // One malformed query fails the whole batch; fall back to per-item queries.
    if (err.status === 400 && items.length > 1) {
      return Promise.all(
        items.map(async (item) => {
          try {
            return { vulnIds: await queryAllPages(fetchImpl, baseUrl, item) };
          } catch (e) {
            return { error: e.message };
          }
        }),
      );
    }
    throw err;
  }
}

async function queryAllPages(fetchImpl, baseUrl, item, pageToken) {
  const ids = [];
  let token = pageToken;
  do {
    const body = { ...osvQuery(item.pkg, item.version), ...(token ? { page_token: token } : {}) };
    const data = await fetchJson(fetchImpl, `${baseUrl}/v1/query`, { method: 'POST', body });
    ids.push(...(data?.vulns || []).map((v) => v.id));
    token = data?.next_page_token;
  } while (token);
  return ids;
}

export async function fetchVuln(fetchImpl, baseUrl, id) {
  return fetchJson(fetchImpl, `${baseUrl}/v1/vulns/${encodeURIComponent(id)}`);
}

export function vulnRecord(vuln) {
  const { severity, score, vector } = osvSeverity(vuln);
  return {
    id: vuln.id,
    aliases: vuln.aliases || [],
    summary: vuln.summary || (vuln.details || '').split('\n')[0].slice(0, 300) || null,
    details: (vuln.details || '').slice(0, 8000) || null,
    severity,
    score,
    vector,
    published: vuln.published || null,
    modified: vuln.modified || null,
    refs: (vuln.references || []).slice(0, 15).map((r) => ({ type: r.type, url: r.url })),
  };
}

function normalizeOsvName(ecosystem, name) {
  return ecosystem === 'pypi' ? name.toLowerCase().replace(/[-_.]+/g, '-') : name.toLowerCase();
}

// Versions that fix `vuln` for the given package (from the matching "affected" entries).
export function fixedVersions(vuln, pkg) {
  const want = normalizeOsvName(pkg.type, displayName(pkg));
  const purl = basePurl(pkg).toLowerCase();
  const affected = vuln.affected || [];
  const matching = affected.filter((a) => {
    const p = a.package || {};
    if (p.purl && p.purl.split('@')[0].toLowerCase() === purl) return true;
    return p.name && normalizeOsvName(pkg.type, p.name) === want;
  });
  const fixed = new Set();
  for (const a of matching.length ? matching : affected) {
    for (const range of a.ranges || []) {
      if (range.type === 'GIT') continue;
      for (const e of range.events || []) if (e.fixed) fixed.add(e.fixed);
    }
  }
  return [...fixed].sort(compareVersions);
}
