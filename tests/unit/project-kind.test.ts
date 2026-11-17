import { afterEach, beforeEach, describe, expect, test, vi } from 'vitest';
import { setDb, type Db } from '@/db';
import { resetEnv } from '@/lib/env';
import { resetRateLimits } from '@/server/api';
import { POST as upload } from '@/app/api/v1/sboms/route';
import { GET as listProjectsRoute } from '@/app/api/v1/projects/route';
import { GET as getProject } from '@/app/api/v1/projects/[id]/route';
import { ingestSbom } from '@/server/ingest';
import { listProjects } from '@/server/inventory';
import { schema } from '@/db';
import { createTestDb, fixture } from './helpers';

const TOKEN = 'test-token';
const BASE = 'http://dash.test';
let db: Db;
let close: () => Promise<void>;

beforeEach(async () => {
  ({ db, close } = await createTestDb());
  setDb(db);
  process.env.UPLOAD_TOKENS = TOKEN;
  vi.stubEnv('OWNER_GITHUB_ID', '');
  vi.stubEnv('ALLOW_OPEN_READS', 'true');
  resetEnv();
  resetRateLimits();
});
afterEach(async () => {
  vi.unstubAllEnvs();
  delete process.env.UPLOAD_TOKENS;
  resetEnv();
  await close();
});

const post = (query = '', headers: Record<string, string> = {}) =>
  upload(
    new Request(`${BASE}/api/v1/sboms${query}`, {
      method: 'POST',
      headers: { authorization: `Bearer ${TOKEN}`, ...headers },
      body: JSON.stringify(fixture('cyclonedx.json')),
    }),
  );

const kindOf = async (name: string) => (await listProjects(db)).find((p) => p.name === name)?.kind;

describe('project kind', () => {
  test('defaults to application when the upload does not say', async () => {
    expect((await post()).status).toBe(201);
    expect(await kindOf('web-app')).toBe('application');
  });

  test('is read from the query parameter or the X-Sbom-Kind header', async () => {
    expect((await post('?kind=library')).status).toBe(201);
    expect(await kindOf('web-app')).toBe('library');
    expect((await post('', { 'x-sbom-kind': 'image' })).status).toBe(201);
    expect(await kindOf('web-app')).toBe('image');
  });

  test('is replaced on every upload, including back to the default', async () => {
    await post('?kind=host');
    expect(await kindOf('web-app')).toBe('host');
    await post();
    expect(await kindOf('web-app')).toBe('application');
  });

  test('rejects a kind that is not one of the four', async () => {
    const res = await post('?kind=service');
    expect(res.status).toBe(400);
    expect((await res.json()).error).toMatch(/kind/i);
    expect(await listProjects(db)).toHaveLength(0);
  });

  test('ingestSbom applies the kind it is given', async () => {
    await ingestSbom(db, fixture('cyclonedx.json'), { kind: 'library' });
    expect(await kindOf('web-app')).toBe('library');
  });

  test('a row stored before the column existed reads as application', async () => {
    await db.insert(schema.projects).values({ name: 'legacy' });
    expect(await kindOf('legacy')).toBe('application');
  });

  test('the projects API returns it', async () => {
    const created = await (await post('?kind=image')).json();
    const list = await (await listProjectsRoute(new Request(`${BASE}/api/v1/projects`))).json();
    expect(list[0]).toMatchObject({ name: 'web-app', kind: 'image' });
    const one = await (
      await getProject(new Request(`${BASE}/api/v1/projects/${created.projectId}`), {
        params: Promise.resolve({ id: String(created.projectId) }),
      })
    ).json();
    expect(one.kind).toBe('image');
  });
});
