// Demo SBOMs plus canned OSV.dev / deps.dev responses for offline seeding and e2e tests.
// Advisory details are abbreviated copies of real advisories.
import type { OsvVuln } from '@/worker/osv';

const cdx = (name: string, version: string, purls: string[], licenses: Record<string, string> = {}) => ({
  bomFormat: 'CycloneDX',
  specVersion: '1.6',
  metadata: { component: { type: 'application', name, version } },
  components: purls.map((purl) => {
    const [, rest] = purl.split(/^pkg:[^/]+\//);
    const at = rest.lastIndexOf('@');
    return {
      type: 'library',
      name: decodeURIComponent(rest.slice(0, at)),
      version: rest.slice(at + 1),
      purl,
      ...(licenses[purl] ? { licenses: [{ license: { id: licenses[purl] } }] } : {}),
    };
  }),
});

export const DEMO_SBOMS = [
  {
    meta: { project: 'web-storefront', version: '3.4.1', ref: 'refs/heads/main', commit: '9f2c1e7', repository: 'acme/web-storefront' },
    document: cdx('web-storefront', '3.4.1', [
      'pkg:npm/lodash@4.17.15',
      'pkg:npm/axios@1.5.1',
      'pkg:npm/react@18.2.0',
      'pkg:npm/react-dom@18.2.0',
      'pkg:npm/express@4.18.2',
      'pkg:npm/%40babel/core@7.24.0',
      'pkg:npm/zod@3.23.8',
    ], { 'pkg:npm/lodash@4.17.15': 'MIT', 'pkg:npm/react@18.2.0': 'MIT' }),
  },
  {
    meta: { project: 'payments-api', version: '1.12.0', ref: 'refs/tags/v1.12.0', commit: '41ab09d', repository: 'acme/payments-api' },
    document: cdx('payments-api', '1.12.0', [
      'pkg:pypi/requests@2.31.0',
      'pkg:pypi/jinja2@3.1.2',
      'pkg:pypi/fastapi@0.115.0',
      'pkg:pypi/pydantic@2.9.2',
      'pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1',
      'pkg:npm/lodash@4.17.21',
    ]),
  },
  {
    meta: { project: 'inventory-service', version: '0.9.3', ref: 'refs/heads/main', commit: 'c03e5aa', repository: 'acme/inventory-service' },
    document: cdx('inventory-service', '0.9.3', [
      'pkg:golang/golang.org/x/net@v0.17.0',
      'pkg:golang/github.com/gin-gonic/gin@v1.9.1',
      'pkg:golang/github.com/google/uuid@v1.6.0',
      'pkg:npm/lodash@4.17.15',
    ]),
  },
];

const advisory = (
  id: string,
  aliases: string[],
  summary: string,
  ecosystem: string,
  name: string,
  fixed: string,
  severity: { vector?: string; label?: string },
  published: string,
): OsvVuln => ({
  id,
  aliases,
  summary,
  details: `${summary}. Upgrade ${name} to ${fixed} or later.`,
  published,
  modified: published,
  ...(severity.vector ? { severity: [{ type: 'CVSS_V3', score: severity.vector }] } : {}),
  ...(severity.label ? { database_specific: { severity: severity.label } } : {}),
  references: [{ type: 'ADVISORY', url: `https://osv.dev/vulnerability/${id}` }],
  affected: [{ package: { ecosystem, name }, ranges: [{ type: 'ECOSYSTEM', events: [{ introduced: '0' }, { fixed }] }] }],
});

export const DEMO_OSV: Record<string, OsvVuln> = {
  'GHSA-p6mc-m468-83gw': advisory('GHSA-p6mc-m468-83gw', ['CVE-2020-8203'], 'Prototype Pollution in lodash', 'npm', 'lodash', '4.17.19',
    { vector: 'CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:H/A:H' }, '2020-07-15T19:15:00Z'),
  'GHSA-35jh-r3h4-6jhm': advisory('GHSA-35jh-r3h4-6jhm', ['CVE-2021-23337'], 'Command Injection in lodash', 'npm', 'lodash', '4.17.21',
    { vector: 'CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H' }, '2021-05-06T16:05:51Z'),
  'GHSA-wf5p-g6vw-rhxx': advisory('GHSA-wf5p-g6vw-rhxx', ['CVE-2023-45857'], 'Axios Cross-Site Request Forgery Vulnerability', 'npm', 'axios', '1.6.0',
    { vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:N/A:N', label: 'MODERATE' }, '2023-11-08T21:30:37Z'),
  'GHSA-9wx4-h78v-vm56': advisory('GHSA-9wx4-h78v-vm56', ['CVE-2024-35195'], 'Requests `Session` object does not verify requests after making first request with verify=False', 'PyPI', 'requests', '2.32.0',
    { vector: 'CVSS:3.1/AV:L/AC:H/PR:H/UI:R/S:U/C:H/I:H/A:N' }, '2024-05-20T20:15:00Z'),
  'GHSA-h5c8-rqwp-cp95': advisory('GHSA-h5c8-rqwp-cp95', ['CVE-2024-22195'], 'Jinja vulnerable to HTML attribute injection when passing user input as keys to xmlattr filter', 'PyPI', 'jinja2', '3.1.3',
    { vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:N' }, '2024-01-11T03:30:00Z'),
  'GHSA-jfh8-c2jp-5v3q': advisory('GHSA-jfh8-c2jp-5v3q', ['CVE-2021-44228'], 'Remote code injection in Log4j', 'Maven', 'org.apache.logging.log4j:log4j-core', '2.15.0',
    { vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H' }, '2021-12-10T00:40:56Z'),
  'GO-2024-2687': advisory('GO-2024-2687', ['CVE-2023-45288', 'GHSA-4v7x-pqxf-cx7m'], 'HTTP/2 CONTINUATION flood in net/http', 'Go', 'golang.org/x/net', '0.23.0',
    { label: 'HIGH' }, '2024-04-03T21:02:43Z'),
};

/** "<base purl>@<version>" -> OSV ids */
export const DEMO_AFFECTED: Record<string, string[]> = {
  'pkg:npm/lodash@4.17.15': ['GHSA-p6mc-m468-83gw', 'GHSA-35jh-r3h4-6jhm'],
  'pkg:npm/axios@1.5.1': ['GHSA-wf5p-g6vw-rhxx'],
  'pkg:pypi/requests@2.31.0': ['GHSA-9wx4-h78v-vm56'],
  'pkg:pypi/jinja2@3.1.2': ['GHSA-h5c8-rqwp-cp95'],
  'pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1': ['GHSA-jfh8-c2jp-5v3q'],
  'pkg:golang/golang.org/x/net@v0.17.0': ['GO-2024-2687'],
};

/** "<deps.dev system>:<name>" -> latest version */
export const DEMO_LATEST: Record<string, string> = {
  'npm:lodash': '4.17.21',
  'npm:axios': '1.7.9',
  'npm:react': '19.0.0',
  'npm:react-dom': '19.0.0',
  'npm:express': '5.1.0',
  'npm:@babel/core': '7.26.0',
  'npm:zod': '3.23.8',
  'pypi:requests': '2.32.3',
  'pypi:jinja2': '3.1.5',
  'pypi:fastapi': '0.115.6',
  'pypi:pydantic': '2.10.4',
  'maven:org.apache.logging.log4j:log4j-core': '2.24.3',
  'go:golang.org/x/net': 'v0.33.0',
  'go:github.com/gin-gonic/gin': 'v1.10.0',
  'go:github.com/google/uuid': 'v1.6.0',
};

/** Fake fetch serving the canned data above in the OSV.dev / deps.dev wire formats. */
/** Real KEV entry for Log4Shell, so the demo shows an exploited vulnerability. */
const DEMO_KEV = [
  {
    cveID: 'CVE-2021-44228',
    vendorProject: 'Apache',
    product: 'Log4j2',
    vulnerabilityName: 'Apache Log4j2 Remote Code Execution Vulnerability',
    dateAdded: '2021-12-10',
    dueDate: '2021-12-24',
    knownRansomwareCampaignUse: 'Known',
  },
];

/** EPSS values copied from the FIRST API (2026-10-14). CVEs not listed come back unscored. */
const DEMO_EPSS: Record<string, { epss: string; percentile: string }> = {
  'CVE-2021-44228': { epss: '0.999990000', percentile: '1.000000000' },
  'CVE-2020-8203': { epss: '0.052130000', percentile: '0.923730000' },
};

export const demoFetch: typeof fetch = async (input, init) => {
  const json = (body: unknown, status = 200) => new Response(JSON.stringify(body), { status });
  const url = new URL(input.toString());
  if (url.hostname === 'epss.demo') {
    const wanted = (url.searchParams.get('cve') ?? '').split(',');
    return json({ status: 'OK', data: wanted.filter((c) => DEMO_EPSS[c]).map((cve) => ({ cve, ...DEMO_EPSS[cve], date: '2026-10-14' })) });
  }
  if (url.hostname === 'kev.demo') {return json({ catalogVersion: 'demo', count: DEMO_KEV.length, vulnerabilities: DEMO_KEV });}
  if (url.pathname === '/v1/querybatch') {
    const { queries } = JSON.parse(String(init?.body)) as { queries: { package: { purl: string }; version: string }[] };
    return json({ results: queries.map((q) => ({ vulns: (DEMO_AFFECTED[`${q.package.purl}@${q.version}`] ?? []).map((id) => ({ id })) })) });
  }
  if (url.pathname.startsWith('/v1/vulns/')) {
    const v = DEMO_OSV[decodeURIComponent(url.pathname.slice('/v1/vulns/'.length))];
    return v ? json(v) : json({}, 404);
  }
  const m = url.pathname.match(/^\/v3\/systems\/([^/]+)\/packages\/(.+)$/);
  const latest = m && DEMO_LATEST[`${m[1]}:${decodeURIComponent(m[2])}`];
  return latest ? json({ versions: [{ versionKey: { version: latest }, isDefault: true }] }) : json({}, 404);
};
