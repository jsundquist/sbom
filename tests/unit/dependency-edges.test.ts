import { describe, expect, test } from 'vitest';
import { parseSbom } from '@/sbom/parse';
import { fixture } from './helpers';

const edgeSet = (edges: { from: string; to: string }[]) => new Set(edges.map((e) => `${e.from} -> ${e.to}`));

describe('dependency edges: GitHub SPDX export', () => {
  const parsed = parseSbom(fixture('github-spdx-graph.json'));

  test('keeps DEPENDS_ON edges between components, including two versions of one package', () => {
    expect(edgeSet(parsed.edges)).toEqual(
      new Set([
        'npm:vitest@5.0.4 -> npm:vite@8.3.4',
        'npm:vitest@5.0.4 -> npm:@vitest/mocker@5.0.4',
        'npm:@vitest/mocker@5.0.4 -> npm:vite@8.3.4',
        'npm:vite@8.3.4 -> npm:postcss@8.5.29',
        'npm:next@16.4.1 -> npm:postcss@8.5.23',
        'npm:@mui/material-nextjs@9.5.0 -> npm:next@16.4.1',
      ]),
    );
  });

  test('marks what the described root package depends on as direct dependencies', () => {
    expect(new Set(parsed.direct)).toEqual(new Set(['npm:vitest@5.0.4', 'npm:next@16.4.1', 'npm:@mui/material-nextjs@9.5.0']));
  });
});

describe('dependency edges: SPDX DEPENDENCY_OF', () => {
  const pkg = (id: string, name: string, version: string) => ({
    SPDXID: id,
    name,
    versionInfo: version,
    externalRefs: [{ referenceType: 'purl', referenceLocator: `pkg:npm/${name}@${version}` }],
  });
  const doc = {
    spdxVersion: 'SPDX-2.3',
    SPDXID: 'SPDXRef-DOCUMENT',
    name: 'app',
    documentDescribes: ['SPDXRef-root'],
    packages: [pkg('SPDXRef-root', 'app', '1.0.0'), pkg('SPDXRef-a', 'a', '1.0.0'), pkg('SPDXRef-b', 'b', '2.0.0')],
    relationships: [
      // "b is a dependency of a" means a depends on b.
      { spdxElementId: 'SPDXRef-b', relationshipType: 'DEPENDENCY_OF', relatedSpdxElement: 'SPDXRef-a' },
      { spdxElementId: 'SPDXRef-a', relationshipType: 'DEPENDENCY_OF', relatedSpdxElement: 'SPDXRef-root' },
    ],
  };

  test('reads the relationship in reverse and treats the described package as the root', () => {
    const parsed = parseSbom(doc);
    expect(edgeSet(parsed.edges)).toEqual(new Set(['npm:a@1.0.0 -> npm:b@2.0.0']));
    expect(parsed.direct).toEqual(['npm:a@1.0.0']);
  });
});

describe('dependency edges: CycloneDX', () => {
  test('maps bom-refs from a Syft export to components; direct dependencies are unknown without a root entry', () => {
    const parsed = parseSbom(fixture('syft-cyclonedx-graph.json'));
    expect(edgeSet(parsed.edges)).toEqual(
      new Set([
        'npm:@mui/material-nextjs@9.5.0 -> npm:next@16.4.1',
        'npm:next@16.4.1 -> npm:postcss@8.5.23',
        'npm:next@16.4.1 -> npm:postcss@8.5.29',
        'npm:vite@8.3.4 -> npm:postcss@8.5.23',
        'npm:vite@8.3.4 -> npm:postcss@8.5.29',
        'npm:vitest@5.0.4 -> npm:vite@8.3.4',
      ]),
    );
    expect(parsed.direct).toBeNull();
  });

  test('a dependencies entry for the root component lists the direct dependencies, including nested components', () => {
    const comp = (ref: string, name: string, version: string) => ({
      type: 'library',
      'bom-ref': ref,
      name,
      version,
      purl: `pkg:npm/${name}@${version}`,
    });
    const parsed = parseSbom({
      bomFormat: 'CycloneDX',
      specVersion: '1.5',
      metadata: { component: { type: 'application', name: 'app', 'bom-ref': 'root' } },
      components: [{ ...comp('a', 'a', '1.0.0'), components: [comp('b', 'b', '2.0.0')] }],
      dependencies: [
        { ref: 'root', dependsOn: ['a'] },
        { ref: 'a', dependsOn: ['b', 'missing'] },
      ],
    });
    expect(parsed.direct).toEqual(['npm:a@1.0.0']);
    expect(edgeSet(parsed.edges)).toEqual(new Set(['npm:a@1.0.0 -> npm:b@2.0.0']));
  });
});
