import { afterEach, beforeEach, describe, expect, test } from 'vitest';
import { schema, setDb, type Db } from '@/db';
import { osvEcosystem } from '@/lib/ecosystems';
import { ingestSbom } from '@/server/ingest';
import { enrich } from '@/worker/enrich';
import { createTestDb, enrichOptions, type FakeApis } from './helpers';

describe('osvEcosystem', () => {
  test.each([
    ['apk', 'alpine-3.20.1', 'Alpine:v3.20'],
    ['apk', 'alpine-3.24.0_alpha20260101', 'Alpine:v3.24'],
    ['apk', 'alpine-3.19', 'Alpine:v3.19'],
  ])('%s with distro %s maps to %s', (type, distro, expected) => {
    expect(osvEcosystem(type, distro)).toBe(expected);
  });

  test.each([
    ['apk', null],
    ['apk', 'wolfi-20230201'],
    ['npm', 'alpine-3.20.1'],
  ])('%s with distro %s has no OS ecosystem', (type, distro) => {
    expect(osvEcosystem(type, distro)).toBeNull();
  });
});

const IMAGE_SBOM = {
  bomFormat: 'CycloneDX',
  specVersion: '1.5',
  metadata: { component: { type: 'container', name: 'ghcr.io/jsundquist/sbom', version: 'abc-1' } },
  components: [
    {
      type: 'library',
      name: 'musl',
      version: '1.2.5-r0',
      purl: 'pkg:apk/alpine/musl@1.2.5-r0?arch=x86_64&distro=alpine-3.20.1',
    },
  ],
};

describe('OS package vulnerability lookup', () => {
  let db: Db;
  let close: () => Promise<void>;
  beforeEach(async () => {
    ({ db, close } = await createTestDb());
    setDb(db);
  });
  afterEach(() => close());

  async function countVulns(apis: FakeApis): Promise<number> {
    await ingestSbom(db, IMAGE_SBOM, { project: 'k8s-gitops/sbom', version: 'abc-1' });
    await enrich(db, enrichOptions(apis));
    return (await db.select().from(schema.versionVulnerabilities)).length;
  }

  test('queries OSV by Alpine release, which a bare purl lookup cannot match', async () => {
    const n = await countVulns({
      vulns: { 'Alpine:v3.20:musl@1.2.5-r0': ['ALPINE-CVE-2025-26519'] },
      osvVulns: { 'ALPINE-CVE-2025-26519': { id: 'ALPINE-CVE-2025-26519', aliases: ['CVE-2025-26519'] } },
    });
    expect(n).toBe(1);
  });
});
