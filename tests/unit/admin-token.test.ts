import { afterEach, beforeEach, describe, expect, test, vi } from 'vitest';
import { schema, setDb, type Db } from '@/db';
import { resetEnv } from '@/lib/env';
import { resetRateLimits } from '@/server/api';
import { POST as upload } from '@/app/api/v1/sboms/route';
import { DELETE as deleteProject } from '@/app/api/v1/projects/[id]/route';
import { createTestDb, fixture } from './helpers';

const UPLOAD = 'upload-token';
const ADMIN = 'admin-token';
const BASE = 'http://dash.test';
let db: Db;
let close: () => Promise<void>;

function configure(env: Record<string, string>) {
  for (const [k, v] of Object.entries(env)) {
    vi.stubEnv(k, v);
  }
  resetEnv();
  resetRateLimits();
}

beforeEach(async () => {
  ({ db, close } = await createTestDb());
  setDb(db);
  configure({ UPLOAD_TOKENS: UPLOAD, ADMIN_TOKENS: ADMIN });
});
afterEach(async () => {
  vi.unstubAllEnvs();
  resetEnv();
  await close();
});

async function seedProject() {
  const res = await upload(
    new Request(`${BASE}/api/v1/sboms`, {
      method: 'POST',
      headers: { authorization: `Bearer ${UPLOAD}` },
      body: JSON.stringify(fixture('cyclonedx.json')),
    }),
  );
  return (await res.json()).projectId as number;
}

const del = (id: number, token?: string) =>
  deleteProject(new Request(BASE, { method: 'DELETE', headers: token ? { authorization: `Bearer ${token}` } : {} }), {
    params: Promise.resolve({ id: String(id) }),
  });

const projectCount = async () => (await db.select().from(schema.projects)).length;

describe('DELETE /api/v1/projects/[id] needs an admin token', () => {
  test('an upload token no longer deletes', async () => {
    const id = await seedProject();
    expect((await del(id, UPLOAD)).status).toBe(401);
    expect(await projectCount()).toBe(1);
  });

  test('an admin token deletes', async () => {
    const id = await seedProject();
    expect((await del(id, ADMIN)).status).toBe(204);
    expect(await projectCount()).toBe(0);
  });

  test('a missing or wrong token is refused', async () => {
    const id = await seedProject();
    expect((await del(id)).status).toBe(401);
    expect((await del(id, 'nope')).status).toBe(401);
    expect(await projectCount()).toBe(1);
  });

  test('an admin token does not upload', async () => {
    const res = await upload(
      new Request(`${BASE}/api/v1/sboms`, {
        method: 'POST',
        headers: { authorization: `Bearer ${ADMIN}` },
        body: JSON.stringify(fixture('cyclonedx.json')),
      }),
    );
    expect(res.status).toBe(401);
  });

  test('deletes spend the same rate-limit budget as uploads', async () => {
    const id = await seedProject();
    configure({ WRITE_RATE_LIMIT: '1' });
    expect((await del(id, 'nope')).status).toBe(401);
    expect((await del(id, ADMIN)).status).toBe(429);
  });
});

describe('with no ADMIN_TOKENS configured', () => {
  test('deletes are open outside production, like uploads', async () => {
    configure({ ADMIN_TOKENS: '' });
    const id = await seedProject();
    expect((await del(id)).status).toBe(204);
  });

  test('production fails closed with 503 even when UPLOAD_TOKENS is set', async () => {
    const id = await seedProject();
    configure({ NODE_ENV: 'production', ADMIN_TOKENS: '' });
    expect((await del(id, UPLOAD)).status).toBe(503);
    expect(await projectCount()).toBe(1);
  });

  test('ALLOW_OPEN_UPLOADS=true opens deletes in production, as it opens uploads', async () => {
    const id = await seedProject();
    configure({ NODE_ENV: 'production', ADMIN_TOKENS: '', ALLOW_OPEN_UPLOADS: 'true' });
    expect((await del(id)).status).toBe(204);
  });
});
