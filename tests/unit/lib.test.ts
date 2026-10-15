import { describe, expect, test } from 'vitest';
import { basePurl, displayName, packageKey, parsePurl } from '@/lib/purl';
import { compareVersions, isPrerelease, updateType } from '@/lib/version';
import { cvss3Score } from '@/lib/severity';
import { pickLatest } from '@/worker/depsdev';
import { fixedVersions, osvSeverity, osvVulnSchema } from '@/worker/osv';
import { parseSbom, SbomParseError } from '@/sbom/parse';
import { fixture, LODASH_VULN } from './helpers';

describe('purl', () => {
  test('parses namespaces, versions and qualifiers', () => {
    const p = parsePurl('pkg:npm/%40babel/core@7.24.0?foo=bar#sub')!;
    expect([p.type, p.namespace, p.name, p.version]).toEqual(['npm', '@babel', 'core', '7.24.0']);
    expect(displayName(p)).toBe('@babel/core');
    expect(packageKey(p)).toBe('npm:@babel/core');
    expect(basePurl(p)).toBe('pkg:npm/%40babel/core');
  });

  test('formats ecosystem-native names', () => {
    expect(displayName(parsePurl('pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1')!)).toBe('org.apache.logging.log4j:log4j-core');
    expect(displayName(parsePurl('pkg:golang/github.com/gin-gonic/gin@v1.9.0')!)).toBe('github.com/gin-gonic/gin');
    expect(packageKey(parsePurl('pkg:pypi/Django_Rest.Framework@1')!)).toBe('pypi:django-rest-framework');
    expect(parsePurl('not-a-purl')).toBeNull();
  });
});

describe('versions', () => {
  test.each([
    ['1.10.0', '1.9.9', 1],
    ['v1.2.3', '1.2.3', 0],
    ['2.0.0-rc.1', '2.0.0', -1],
    ['2.0.0-alpha', '2.0.0-beta', -1],
    ['33.0.0-jre', '31.1-jre', 1],
    ['1.0', '1.0.0', 0],
    ['2.0.0b1', '2.0.0', -1],
  ])('compare(%s, %s) = %i', (a, b, expected) => {
    expect(compareVersions(a, b)).toBe(expected);
  });

  test('prerelease detection', () => {
    expect(isPrerelease('3.0.0rc2')).toBe(true);
    expect(isPrerelease('31.1-jre')).toBe(false);
  });

  test('updateType classifies how far behind a version is', () => {
    expect(updateType('4.17.15', '4.17.21')).toBe('patch');
    expect(updateType('4.17.15', '4.18.0')).toBe('minor');
    expect(updateType('4.17.15', '5.0.0')).toBe('major');
    expect(updateType('5.0.0', '5.0.0')).toBeNull();
    expect(updateType('6.0.0-beta', '5.0.0')).toBeNull();
  });
});

describe('severity', () => {
  test.each([
    ['CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H', 10],
    ['CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H', 9.8],
    ['CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:H/A:H', 7.4],
    ['CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N', 5.5],
    ['CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N', 0],
    ['garbage', null],
  ])('cvss3Score(%s) = %s', (vector, score) => {
    expect(cvss3Score(vector)).toBe(score);
  });

  test('osvSeverity falls back to database labels', () => {
    expect(osvSeverity(LODASH_VULN).severity).toBe('HIGH');
    expect(osvSeverity({ id: 'x', database_specific: { severity: 'MODERATE' } }).severity).toBe('MEDIUM');
    expect(osvSeverity({ id: 'x' }).severity).toBe('UNKNOWN');
  });
});

describe('enrichment helpers', () => {
  const v = (version: string, isDefault = false) => ({ versionKey: { version }, isDefault });
  test('pickLatest prefers the stable default version', () => {
    expect(pickLatest([v('1.0.0'), v('2.0.0', true), v('3.0.0-beta')])).toBe('2.0.0');
    expect(pickLatest([v('1.0.0'), v('1.5.0'), v('2.0.0rc1', true)])).toBe('1.5.0');
    expect(pickLatest([])).toBeNull();
  });

  test('fixedVersions extracts fixes for the matching package', () => {
    expect(fixedVersions(LODASH_VULN, parsePurl('pkg:npm/lodash@4.17.15')!)).toEqual(['4.17.19']);
  });
});

describe('osvVulnSchema', () => {
  test('accepts real-world records whose database_specific / ecosystem_specific omit severity', () => {
    const record = {
      id: 'GHSA-xxxx-xxxx-xxxx',
      database_specific: { cwe_ids: ['CWE-79'] },
      affected: [
        {
          package: { ecosystem: 'npm', name: 'lodash' },
          ecosystem_specific: { affected_functions: ['x'] },
          database_specific: { source: 'https://example.test' },
          ranges: [{ type: 'SEMVER', events: [{ introduced: '0' }, { fixed: '4.17.21' }] }],
        },
      ],
    };
    expect(osvVulnSchema.safeParse(record).success).toBe(true);
  });
});

describe('parseSbom', () => {
  test('normalizes CycloneDX', () => {
    const sbom = parseSbom(fixture('cyclonedx.json'));
    expect(sbom.format).toBe('CycloneDX');
    expect(sbom.subject).toEqual({ name: 'web-app', version: '2.3.0' });
    expect(sbom.components.map((c) => c.name).sort()).toEqual(['@babel/core', 'express', 'internal-thing', 'lodash', 'qs']);
  });

  test('normalizes SPDX, including the GitHub dependency graph wrapper', () => {
    const sbom = parseSbom({ sbom: fixture('spdx.json') });
    expect(sbom.format).toBe('SPDX');
    expect(sbom.subject?.name).toBe('com.github.acme/api-service');
    expect(sbom.components.map((c) => c.packageKey)).toEqual(['pypi:requests', 'npm:lodash']);
    expect(sbom.components[1].licenses).toBeNull();
  });

  test('rejects unknown and malformed documents', () => {
    expect(() => parseSbom({ hello: 'world' })).toThrow(SbomParseError);
    expect(() => parseSbom({ bomFormat: 'CycloneDX', components: 'nope' })).toThrow(/components/);
  });
});
