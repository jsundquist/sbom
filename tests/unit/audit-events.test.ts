import { afterEach, beforeEach, describe, expect, test } from 'vitest';
import { desc } from 'drizzle-orm';
import type { Db } from '@/db';
import { events } from '@/db/schema';
import { tokenFingerprint } from '@/lib/fingerprint';
import { deleteProject, ingestSbom } from '@/server/ingest';
import { listEvents } from '@/server/events';
import { createTestDb, fixture } from './helpers';

let db: Db;
let close: () => Promise<void>;
beforeEach(async () => {
  ({ db, close } = await createTestDb());
});
afterEach(async () => {
  await close();
});

const all = () => db.select().from(events).orderBy(desc(events.id));

describe('tokenFingerprint', () => {
  test('is a short stable hash that does not contain the token', () => {
    const fp = tokenFingerprint('super-secret-token');
    expect(fp).toMatch(/^[0-9a-f]{12}$/);
    expect(fp).toBe(tokenFingerprint('super-secret-token'));
    expect(fp).not.toBe(tokenFingerprint('other'));
    expect(tokenFingerprint('')).toBeNull();
    expect(tokenFingerprint(null)).toBeNull();
  });
});

describe('audit events', () => {
  test('an upload writes an upload event with the project and fingerprint', async () => {
    const r = await ingestSbom(db, fixture('cyclonedx.json'), { project: 'web' }, { actor: 'abc123abc123' });
    const [e] = await all();
    expect(e).toMatchObject({ kind: 'upload', projectId: r.projectId, projectName: 'web', tokenFingerprint: 'abc123abc123' });
    expect(e.detail).toMatchObject({ sbomId: r.sbomId, componentCount: r.componentCount });
  });

  test('pruning history writes a prune event in the same transaction', async () => {
    for (let i = 0; i < 3; i++) {
      await ingestSbom(db, fixture('cyclonedx.json'), { project: 'web' }, { historyLimit: 2 });
    }
    const kinds = (await all()).map((e) => e.kind);
    expect(kinds.filter((k) => k === 'upload')).toHaveLength(3);
    expect(kinds.filter((k) => k === 'prune')).toHaveLength(1);
    const prune = (await all()).find((e) => e.kind === 'prune')!;
    expect(prune.detail).toMatchObject({ removed: 1, historyLimit: 2 });
  });

  test('a failed upload leaves no event', async () => {
    await expect(ingestSbom(db, { not: 'an sbom' }, { project: 'x' })).rejects.toThrow();
    expect(await all()).toHaveLength(0);
  });

  test('deleting a Project leaves an event naming it', async () => {
    const { projectId } = await ingestSbom(db, fixture('cyclonedx.json'), { project: 'web' });
    expect(await deleteProject(db, projectId, { actor: 'fp0000000000' })).toBe(true);
    const [e] = await all();
    expect(e).toMatchObject({ kind: 'delete', projectId: null, projectName: 'web', tokenFingerprint: 'fp0000000000' });
  });

  test('deleting a missing Project writes nothing', async () => {
    expect(await deleteProject(db, 999)).toBe(false);
    expect(await all()).toHaveLength(0);
  });

  test('listEvents returns newest first with a total, limit and offset', async () => {
    for (let i = 0; i < 3; i++) {
      await ingestSbom(db, fixture('cyclonedx.json'), { project: `p${i}` });
    }
    const page = await listEvents(db, { limit: 2, offset: 0 });
    expect(page.total).toBe(3);
    expect(page.items.map((e) => e.projectName)).toEqual(['p2', 'p1']);
    const rest = await listEvents(db, { limit: 2, offset: 2 });
    expect(rest.items.map((e) => e.projectName)).toEqual(['p0']);
    expect(page.items[0]).toHaveProperty('at');
    expect(page.items[0]).not.toHaveProperty('id', undefined);
  });
});

describe('audit events over the API', () => {
  test('upload and delete record the token fingerprint, never the token; GET /events lists them', async () => {
    const { vi } = await import('vitest');
    const { setDb } = await import('@/db');
    const { resetEnv } = await import('@/lib/env');
    const { resetRateLimits } = await import('@/server/api');
    const { POST } = await import('@/app/api/v1/sboms/route');
    const { DELETE } = await import('@/app/api/v1/projects/[id]/route');
    const { GET } = await import('@/app/api/v1/events/route');
    setDb(db);
    vi.stubEnv('UPLOAD_TOKENS', 'up-secret');
    vi.stubEnv('ADMIN_TOKENS', 'admin-secret');
    resetEnv();
    resetRateLimits();
    try {
      const up = await POST(
        new Request('http://x.test/api/v1/sboms?project=web', {
          method: 'POST',
          headers: { authorization: 'Bearer up-secret' },
          body: JSON.stringify(fixture('cyclonedx.json')),
        }),
      );
      const { projectId } = await up.json();
      const del = await DELETE(new Request('http://x.test', { method: 'DELETE', headers: { authorization: 'Bearer admin-secret' } }), {
        params: Promise.resolve({ id: String(projectId) }),
      });
      expect(del.status).toBe(204);

      const res = await GET(new Request('http://x.test/api/v1/events?limit=1'));
      expect(res.headers.get('X-Total-Count')).toBe('2');
      const body = await res.json();
      expect(body).toHaveLength(1);
      expect(body[0]).toMatchObject({ kind: 'delete', projectName: 'web', projectId: null });
      const text = JSON.stringify(await (await GET(new Request('http://x.test/api/v1/events'))).json());
      expect(text).not.toContain('secret');
      expect(body[0].tokenFingerprint).toBe(tokenFingerprint('admin-secret'));
      expect((await GET(new Request('http://x.test/api/v1/events?limit=5000'))).status).toBe(400);
      expect((await GET(new Request('http://x.test/api/v1/events?offset=-1'))).status).toBe(400);
    } finally {
      vi.unstubAllEnvs();
      resetEnv();
    }
  });
});
