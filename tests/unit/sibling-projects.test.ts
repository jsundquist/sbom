import { afterEach, beforeEach, describe, expect, test } from 'vitest';
import { eq } from 'drizzle-orm';
import { schema, type Db } from '@/db';
import { ingestSbom } from '@/server/ingest';
import { getSiblingProjects, listProjects } from '@/server/inventory';
import { createTestDb } from './helpers';

let db: Db;
let close: () => Promise<void>;

const sbom = (name: string) => ({
  bomFormat: 'CycloneDX',
  specVersion: '1.5',
  components: [{ type: 'library', name, version: '1.0.0', purl: `pkg:npm/${name}@1.0.0` }],
});

const idOf = async (name: string) => (await listProjects(db)).find((p) => p.name === name)!.id;
const siblingNames = async (name: string) => (await getSiblingProjects(db, await idOf(name))).map((p) => p.name);

beforeEach(async () => {
  ({ db, close } = await createTestDb());
  await ingestSbom(db, sbom('a'), { project: 'shop-web', repository: 'https://github.com/Acme/Shop.git', kind: 'application' });
  await ingestSbom(db, sbom('b'), { project: 'shop-api', repository: 'git@github.com:acme/shop.git', kind: 'application' });
  await ingestSbom(db, sbom('c'), { project: 'shop-sdk', repository: 'acme/shop', kind: 'library' });
  await ingestSbom(db, sbom('d'), { project: 'other', repository: 'acme/other' });
  await ingestSbom(db, sbom('e'), { project: 'no-repo' });
});
afterEach(async () => {
  await close();
});

describe('getSiblingProjects', () => {
  test('lists the other Projects with the same normalised repository, by name', async () => {
    expect(await siblingNames('shop-web')).toEqual(['shop-api', 'shop-sdk']);
    expect(await siblingNames('shop-sdk')).toEqual(['shop-api', 'shop-web']);
  });

  test('never includes the Project itself', async () => {
    expect(await siblingNames('shop-api')).not.toContain('shop-api');
  });

  test('a Project alone in its repository, or with none, has no siblings', async () => {
    expect(await siblingNames('other')).toEqual([]);
    expect(await siblingNames('no-repo')).toEqual([]);
  });

  test('carries the kind and the severity counts the page shows', async () => {
    const [sdk] = (await getSiblingProjects(db, await idOf('shop-api'))).filter((p) => p.name === 'shop-sdk');
    expect(sdk.kind).toBe('library');
    expect(sdk.stats.severity).toEqual({ CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0, UNKNOWN: 0 });
  });

  test('matches a row stored before normalisation until it is re-uploaded', async () => {
    await db.update(schema.projects).set({ repository: 'Acme/Shop' }).where(eq(schema.projects.name, 'shop-sdk'));
    expect(await siblingNames('shop-web')).toEqual(['shop-api', 'shop-sdk']);
  });

  test('an unknown Project id has no siblings', async () => {
    expect(await getSiblingProjects(db, 999_999)).toEqual([]);
  });
});
