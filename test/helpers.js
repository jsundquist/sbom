import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const dir = path.dirname(fileURLToPath(import.meta.url));
export const fixture = (name) => JSON.parse(fs.readFileSync(path.join(dir, 'fixtures', name), 'utf8'));

// Fake OSV + deps.dev backend.
export function fakeFetch({ vulns = {}, osvVulns = {}, latest = {}, calls = [] } = {}) {
  const json = (body, status = 200) => new Response(JSON.stringify(body), { status, headers: { 'content-type': 'application/json' } });
  return async (url, init = {}) => {
    calls.push({ url, body: init.body ? JSON.parse(init.body) : undefined });
    const u = new URL(url);
    if (u.pathname === '/v1/querybatch') {
      const { queries } = JSON.parse(init.body);
      return json({ results: queries.map((q) => ({ vulns: (vulns[`${q.package.purl}@${q.version}`] || []).map((id) => ({ id, modified: '2024-01-01T00:00:00Z' })) })) });
    }
    if (u.pathname.startsWith('/v1/vulns/')) {
      const id = decodeURIComponent(u.pathname.slice('/v1/vulns/'.length));
      return osvVulns[id] ? json(osvVulns[id]) : json({ message: 'not found' }, 404);
    }
    const m = u.pathname.match(/^\/v3\/systems\/([^/]+)\/packages\/(.+)$/);
    if (m) {
      const name = decodeURIComponent(m[2]);
      const v = latest[`${m[1]}:${name}`];
      if (!v) return json({}, 404);
      return json({ versions: [{ versionKey: { version: '0.0.1' }, isDefault: false }, { versionKey: { version: v }, isDefault: true }] });
    }
    return json({}, 404);
  };
}

export const LODASH_VULN = {
  id: 'GHSA-p6mc-m468-83gw',
  aliases: ['CVE-2020-8203'],
  summary: 'Prototype Pollution in lodash',
  severity: [{ type: 'CVSS_V3', score: 'CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:H/A:H' }],
  affected: [{ package: { ecosystem: 'npm', name: 'lodash', purl: 'pkg:npm/lodash' }, ranges: [{ type: 'SEMVER', events: [{ introduced: '0' }, { fixed: '4.17.19' }] }] }],
};
