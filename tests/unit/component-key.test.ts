import { describe, expect, test } from 'vitest';
import { componentKey, parseSbom } from '@/sbom/parse';

const unversioned = { packageKey: 'npm:leftpad', name: 'leftpad', version: null };
const versionedNull = { packageKey: 'npm:leftpad', name: 'leftpad', version: 'null' };

describe('componentKey', () => {
  test('a missing version and the version "null" are different components', () => {
    expect(componentKey(unversioned)).not.toBe(componentKey(versionedNull));
  });

  test('versioned keys keep the package@version form that edges and trees use', () => {
    expect(componentKey({ packageKey: 'npm:vite', name: 'vite', version: '8.3.4' })).toBe('npm:vite@8.3.4');
  });

  test('falls back to the name when there is no package key', () => {
    expect(componentKey({ packageKey: null, name: 'internal-lib', version: '1.0.0' })).toBe('internal-lib@1.0.0');
  });
});

describe('parseSbom with a version literally named "null"', () => {
  test('keeps both the unversioned and the "null"-versioned component instead of dropping one as a duplicate', () => {
    const parsed = parseSbom({
      bomFormat: 'CycloneDX',
      specVersion: '1.5',
      components: [
        { type: 'library', name: 'leftpad', purl: 'pkg:npm/leftpad' },
        { type: 'library', name: 'leftpad', version: 'null', purl: 'pkg:npm/leftpad@null' },
      ],
    });
    expect(parsed.components.map((c) => c.version)).toEqual([null, 'null']);
  });
});
