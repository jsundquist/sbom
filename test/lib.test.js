import { test } from 'node:test';
import assert from 'node:assert/strict';
import { parsePurl, packageKey, basePurl, displayName } from '../src/lib/purl.js';
import { compareVersions, updateType, isPrerelease } from '../src/lib/version.js';
import { cvss3Score, osvSeverity } from '../src/lib/severity.js';
import { pickLatest } from '../src/enrich/depsdev.js';
import { fixedVersions } from '../src/enrich/osv.js';
import { LODASH_VULN } from './helpers.js';

test('parsePurl handles namespaces, versions and qualifiers', () => {
  const p = parsePurl('pkg:npm/%40babel/core@7.24.0?foo=bar#sub');
  assert.deepEqual([p.type, p.namespace, p.name, p.version], ['npm', '@babel', 'core', '7.24.0']);
  assert.equal(displayName(p), '@babel/core');
  assert.equal(packageKey(p), 'npm:@babel/core');
  assert.equal(basePurl(p), 'pkg:npm/%40babel/core');
  const m = parsePurl('pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1');
  assert.equal(displayName(m), 'org.apache.logging.log4j:log4j-core');
  const g = parsePurl('pkg:golang/github.com/gin-gonic/gin@v1.9.0');
  assert.equal(displayName(g), 'github.com/gin-gonic/gin');
  assert.equal(packageKey(parsePurl('pkg:pypi/Django_Rest.Framework@1')), 'pypi:django-rest-framework');
  assert.equal(parsePurl('not-a-purl'), null);
});

test('compareVersions orders common version schemes', () => {
  assert.ok(compareVersions('1.10.0', '1.9.9') > 0);
  assert.ok(compareVersions('v1.2.3', '1.2.3') === 0);
  assert.ok(compareVersions('2.0.0-rc.1', '2.0.0') < 0);
  assert.ok(compareVersions('2.0.0-alpha', '2.0.0-beta') < 0);
  assert.ok(compareVersions('33.0.0-jre', '31.1-jre') > 0);
  assert.ok(compareVersions('1.0', '1.0.0') === 0);
  assert.ok(compareVersions('2.0.0b1', '2.0.0') < 0);
  assert.ok(isPrerelease('3.0.0rc2'));
  assert.ok(!isPrerelease('31.1-jre'));
});

test('updateType classifies how far behind a version is', () => {
  assert.equal(updateType('4.17.15', '4.17.21'), 'patch');
  assert.equal(updateType('4.17.15', '4.18.0'), 'minor');
  assert.equal(updateType('4.17.15', '5.0.0'), 'major');
  assert.equal(updateType('5.0.0', '5.0.0'), null);
  assert.equal(updateType('6.0.0-beta', '5.0.0'), null);
});

test('cvss3Score matches the reference calculator', () => {
  assert.equal(cvss3Score('CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H'), 10);
  assert.equal(cvss3Score('CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H'), 9.8);
  assert.equal(cvss3Score('CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:H/A:H'), 7.4);
  assert.equal(cvss3Score('CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N'), 5.5);
  assert.equal(cvss3Score('CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N'), 0);
  assert.equal(cvss3Score('garbage'), null);
});

test('osvSeverity falls back to database severity labels', () => {
  assert.deepEqual(osvSeverity(LODASH_VULN).severity, 'HIGH');
  assert.equal(osvSeverity({ database_specific: { severity: 'MODERATE' } }).severity, 'MEDIUM');
  assert.equal(osvSeverity({}).severity, 'UNKNOWN');
});

test('pickLatest prefers the stable default version', () => {
  const v = (version, isDefault = false) => ({ versionKey: { version }, isDefault });
  assert.equal(pickLatest([v('1.0.0'), v('2.0.0', true), v('3.0.0-beta')]), '2.0.0');
  assert.equal(pickLatest([v('1.0.0'), v('1.5.0'), v('2.0.0rc1', true)]), '1.5.0');
  assert.equal(pickLatest([]), null);
});

test('fixedVersions extracts fixes for the matching package', () => {
  assert.deepEqual(fixedVersions(LODASH_VULN, parsePurl('pkg:npm/lodash@4.17.15')), ['4.17.19']);
});
