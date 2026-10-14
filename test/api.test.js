import { test } from 'node:test';
import assert from 'node:assert/strict';
import { openDatabase } from '../src/db.js';
import { createApp } from '../src/app.js';
import { loadConfig } from '../src/config.js';
import { Enricher } from '../src/enrich/index.js';
import { parseSbom } from '../src/sbom/parse.js';
import { fixture, fakeFetch, LODASH_VULN } from './helpers.js';

const TOKEN = 'test-token';

async function setup(fetchOpts = {}) {
  const db = openDatabase(':memory:');
  const config = { ...loadConfig({}), uploadTokens: [TOKEN] };
  const calls = [];
  const enricher = new Enricher(db, config, { fetchImpl: fakeFetch({ ...fetchOpts, calls }), logger: {} });
  const app = createApp({ db, config, enricher });
  const server = await new Promise((resolve) => {
    const s = app.listen(0, () => resolve(s));
  });
  const base = `http://127.0.0.1:${server.address().port}`;
  const api = async (path, opts = {}) => {
    const res = await fetch(base + path, opts);
    const text = await res.text();
    return { status: res.status, body: text ? JSON.parse(text) : null };
  };
  const upload = (doc, query = '', headers = {}) =>
    api(`/api/v1/sboms${query}`, { method: 'POST', headers: { authorization: `Bearer ${TOKEN}`, ...headers }, body: JSON.stringify(doc) });
  return { db, enricher, api, upload, calls, close: () => server.close() };
}

test('parseSbom normalizes CycloneDX and SPDX', () => {
  const cdx = parseSbom(fixture('cyclonedx.json'));
  assert.equal(cdx.format, 'CycloneDX');
  assert.deepEqual(cdx.subject, { name: 'web-app', version: '2.3.0' });
  assert.deepEqual(cdx.components.map((c) => c.name).sort(), ['@babel/core', 'express', 'internal-thing', 'lodash', 'qs']);
  const spdx = parseSbom({ sbom: fixture('spdx.json') });
  assert.equal(spdx.format, 'SPDX');
  assert.equal(spdx.subject.name, 'com.github.acme/api-service');
  assert.deepEqual(spdx.components.map((c) => c.packageKey), ['pypi:requests', 'npm:lodash']);
  assert.equal(spdx.components[1].licenses, null);
});

test('upload requires a valid token and a parsable SBOM', async (t) => {
  const ctx = await setup();
  t.after(ctx.close);
  const noAuth = await ctx.api('/api/v1/sboms', { method: 'POST', body: '{}' });
  assert.equal(noAuth.status, 401);
  const bad = await ctx.api('/api/v1/sboms', { method: 'POST', headers: { authorization: `Bearer ${TOKEN}` }, body: 'nope' });
  assert.equal(bad.status, 400);
  const unknown = await ctx.upload({ hello: 'world' });
  assert.equal(unknown.status, 400);
});

test('end-to-end: upload, enrich, and query projects, packages and vulnerabilities', async (t) => {
  const ctx = await setup({
    vulns: { 'pkg:npm/lodash@4.17.15': ['GHSA-p6mc-m468-83gw'] },
    osvVulns: { 'GHSA-p6mc-m468-83gw': LODASH_VULN },
    latest: { 'npm:lodash': '4.17.21', 'npm:express': '5.1.0', 'npm:@babel/core': '7.24.0', 'npm:qs': '6.14.0', 'pypi:requests': '2.32.3' },
  });
  t.after(ctx.close);

  const a = await ctx.upload(fixture('cyclonedx.json'), '?ref=refs/heads/main', { 'x-sbom-commit': 'abc123', 'x-sbom-repository': 'acme/web' });
  assert.equal(a.status, 201);
  assert.equal(a.body.projectName, 'web-app');
  assert.equal(a.body.componentCount, 5);
  const b = await ctx.upload(fixture('spdx.json'), '?project=api-service&version=1.0.0');
  assert.equal(b.status, 201);

  await ctx.enricher.trigger();
  // Scoped npm names must be URL-encoded for deps.dev.
  assert.ok(ctx.calls.some((c) => c.url.endsWith('/v3/systems/npm/packages/%40babel%2Fcore')));

  const projects = (await ctx.api('/api/v1/projects')).body;
  assert.deepEqual(projects.map((p) => p.name), ['api-service', 'web-app']);
  const web = projects.find((p) => p.name === 'web-app');
  assert.equal(web.repository, 'acme/web');
  assert.equal(web.latest.version, '2.3.0');
  assert.equal(web.latest.commit, 'abc123');
  assert.equal(web.stats.vulnerabilities, 1);
  assert.equal(web.stats.severity.HIGH, 1);
  assert.deepEqual(web.stats.outdated, { major: 1, minor: 1, patch: 1 });

  const detail = (await ctx.api(`/api/v1/projects/${web.id}`)).body;
  const lodash = detail.components.find((c) => c.name === 'lodash');
  assert.equal(lodash.latestVersion, '4.17.21');
  assert.equal(lodash.outdated, 'patch');
  assert.equal(lodash.fixVersion, '4.17.19');
  assert.equal(lodash.vulns[0].cve, 'CVE-2020-8203');
  assert.equal(lodash.vulns[0].score, 7.4);
  const internal = detail.components.find((c) => c.name === 'internal-thing');
  assert.equal(internal.vulnStatus, 'unsupported');

  const packages = (await ctx.api('/api/v1/packages')).body;
  const lodashPkg = packages.find((p) => p.key === 'npm:lodash');
  assert.equal(lodashPkg.projectCount, 2);
  assert.equal(lodashPkg.vulnCount, 1);
  const pkgDetail = (await ctx.api('/api/v1/packages/npm%3Alodash')).body;
  assert.equal(pkgDetail.vulnerabilities.length, 1);

  const vulns = (await ctx.api('/api/v1/vulnerabilities')).body;
  assert.equal(vulns.length, 1);
  assert.deepEqual(vulns[0].projects.map((p) => p.name).sort(), ['api-service', 'web-app']);
  const vuln = (await ctx.api('/api/v1/vulnerabilities/GHSA-p6mc-m468-83gw')).body;
  assert.equal(vuln.affected[0].fixVersion, '4.17.19');

  const summary = (await ctx.api('/api/v1/summary')).body;
  assert.equal(summary.projects, 2);
  assert.equal(summary.vulnerablePackages, 1);
  assert.equal(summary.recentUploads.length, 2);

});

test('re-uploading replaces the latest SBOM and keeps history', async (t) => {
  const ctx = await setup();
  t.after(ctx.close);
  const doc = fixture('cyclonedx.json');
  await ctx.upload(doc, '?version=1');
  doc.components = doc.components.slice(0, 1);
  const second = await ctx.upload(doc, '?version=2');
  const detail = (await ctx.api(`/api/v1/projects/${second.body.projectId}`)).body;
  assert.equal(detail.latest.version, '2');
  assert.equal(detail.components.length, 1);
  assert.deepEqual(detail.history.map((h) => h.version), ['2', '1']);
  const old = (await ctx.api(`/api/v1/projects/${second.body.projectId}?sbom=${detail.history[1].id}`)).body;
  assert.equal(old.components.length, 5);
  // Packages only referenced by old SBOMs disappear from the cross-project view.
  const packages = (await ctx.api('/api/v1/packages')).body;
  assert.deepEqual(packages.map((p) => p.name), ['lodash']);
  const del = await ctx.api(`/api/v1/projects/${second.body.projectId}`, { method: 'DELETE', headers: { authorization: `Bearer ${TOKEN}` } });
  assert.equal(del.status, 204);
  assert.equal(ctx.db.prepare('SELECT COUNT(*) AS n FROM packages').get().n, 0);
});
