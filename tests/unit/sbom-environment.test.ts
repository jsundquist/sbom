import { afterEach, beforeEach, describe, expect, test, vi } from 'vitest';
import { setDb, type Db } from '@/db';
import { resetEnv } from '@/lib/env';
import { resetRateLimits } from '@/server/api';
import { POST as upload } from '@/app/api/v1/sboms/route';
import { GET as download } from '@/app/api/v1/sboms/[id]/route';
import { getProject, listProjects } from '@/server/inventory';
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

const latestEnvironment = async () => (await listProjects(db))[0]?.latest?.environment;

describe('environment on upload', () => {
  test('is null when not sent', async () => {
    expect((await post()).status).toBe(201);
    expect(await latestEnvironment()).toBeNull();
  });

  test('is read from the query parameter or the X-Sbom-Environment header, lower-cased', async () => {
    expect((await post('?environment=Staging')).status).toBe(201);
    expect(await latestEnvironment()).toBe('staging');
    expect((await post('', { 'x-sbom-environment': 'prod-eu_1' })).status).toBe(201);
    expect(await latestEnvironment()).toBe('prod-eu_1');
  });

  test('belongs to one upload, so history keeps each upload its own value', async () => {
    await post('?environment=staging');
    await post('?environment=production');
    await post();
    const project = (await listProjects(db))[0];
    const detail = await getProject(db, project.id);
    expect(detail?.history.map((h) => h.environment)).toEqual([null, 'production', 'staging']);
  });

  test('an empty value counts as not sent', async () => {
    expect((await post('?environment=')).status).toBe(201);
    expect(await latestEnvironment()).toBeNull();
  });

  test.each([
    ['too long', 'a'.repeat(41)],
    ['a space', 'pre prod'],
    ['a dot', 'v1.2'],
    ['a colon', 'env:prod'],
  ])('rejects a value with %s as a 400 that stores nothing', async (_label, value) => {
    const res = await post(`?environment=${encodeURIComponent(value)}`);
    expect(res.status).toBe(400);
    expect((await res.json()).error).toMatch(/environment/i);
    expect(await listProjects(db)).toHaveLength(0);
  });

  test('accepts 40 characters', async () => {
    expect((await post(`?environment=${'a'.repeat(40)}`)).status).toBe(201);
  });

  test('the SBOM download carries it in an X-Sbom-Environment header', async () => {
    const res = await post('?environment=staging');
    const { sbomId } = await res.json();
    const dl = await download(new Request(`${BASE}/api/v1/sboms/${sbomId}`), { params: Promise.resolve({ id: String(sbomId) }) });
    expect(dl.headers.get('x-sbom-environment')).toBe('staging');
    const none = await post();
    const { sbomId: id2 } = await none.json();
    const dl2 = await download(new Request(`${BASE}/api/v1/sboms/${id2}`), { params: Promise.resolve({ id: String(id2) }) });
    expect(dl2.headers.has('x-sbom-environment')).toBe(false);
  });
});
