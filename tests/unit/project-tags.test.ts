import { afterEach, beforeEach, describe, expect, test, vi } from 'vitest';
import { setDb, type Db } from '@/db';
import { resetEnv } from '@/lib/env';
import { MAX_TAGS, parseTags } from '@/lib/tags';
import { resetRateLimits } from '@/server/api';
import { POST as upload } from '@/app/api/v1/sboms/route';
import { GET as listProjectsRoute } from '@/app/api/v1/projects/route';
import { GET as getProject } from '@/app/api/v1/projects/[id]/route';
import { ingestSbom } from '@/server/ingest';
import { listProjects } from '@/server/inventory';
import { schema } from '@/db';
import { createTestDb, fixture } from './helpers';

describe('parseTags', () => {
  test('splits on commas, trims, lower-cases and drops empties', () => {
    expect(parseTags(' Team:Payments , tier-1,,')).toEqual({ ok: true, tags: ['team:payments', 'tier-1'] });
  });
  test('de-duplicates after lower-casing, keeping first-seen order', () => {
    expect(parseTags('b,A,a,B,c')).toEqual({ ok: true, tags: ['b', 'a', 'c'] });
  });
  test('nothing sent means no tags', () => {
    expect(parseTags(undefined)).toEqual({ ok: true, tags: [] });
    expect(parseTags('')).toEqual({ ok: true, tags: [] });
    expect(parseTags(' , ')).toEqual({ ok: true, tags: [] });
  });
  test('accepts the allowed characters at the length limits', () => {
    const forty = 'a'.repeat(40);
    expect(parseTags(`a,${forty},x:y_z-1`)).toEqual({ ok: true, tags: ['a', forty, 'x:y_z-1'] });
  });
  test.each([
    ['too long', 'a'.repeat(41)],
    ['a space inside', 'internet facing'],
    ['a dot', 'v1.2'],
    ['a slash', 'team/payments'],
    ['non-ASCII', 'équipe'],
  ])('rejects a tag with %s, naming it', (_label, tag) => {
    const r = parseTags(`ok,${tag}`);
    expect(r.ok).toBe(false);
    expect(!r.ok && r.error).toContain('tag');
  });
  test('rejects more than the maximum number of distinct tags', () => {
    const many = Array.from({ length: MAX_TAGS + 1 }, (_, i) => `t${i}`).join(',');
    expect(parseTags(many).ok).toBe(false);
    expect(parseTags(Array.from({ length: MAX_TAGS }, (_, i) => `t${i}`).join(',')).ok).toBe(true);
  });
  test('duplicates do not count against the maximum', () => {
    const dup = Array.from({ length: MAX_TAGS + 5 }, () => 'same').join(',');
    expect(parseTags(dup)).toEqual({ ok: true, tags: ['same'] });
  });
});

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

const tagsOf = async (name: string) => (await listProjects(db)).find((p) => p.name === name)?.tags;

describe('project tags on upload', () => {
  test('a project with no tags reads as an empty list', async () => {
    expect((await post()).status).toBe(201);
    expect(await tagsOf('web-app')).toEqual([]);
  });

  test('are read from the query parameter or the X-Sbom-Tags header', async () => {
    expect((await post('?tags=Team:Web,tier-1')).status).toBe(201);
    expect(await tagsOf('web-app')).toEqual(['team:web', 'tier-1']);
    expect((await post('', { 'x-sbom-tags': 'internet-facing' })).status).toBe(201);
    expect(await tagsOf('web-app')).toEqual(['internet-facing']);
  });

  test('are replaced on every upload, including back to none', async () => {
    await post('?tags=a,b');
    await post('?tags=c');
    expect(await tagsOf('web-app')).toEqual(['c']);
    await post();
    expect(await tagsOf('web-app')).toEqual([]);
  });

  test('a bad tag is a 400 that names the problem and stores nothing', async () => {
    const res = await post('?tags=ok,not%20ok');
    expect(res.status).toBe(400);
    expect((await res.json()).error).toMatch(/tag/i);
    expect(await listProjects(db)).toHaveLength(0);
  });

  test('too many tags is a 400', async () => {
    const many = Array.from({ length: MAX_TAGS + 1 }, (_, i) => `t${i}`).join(',');
    expect((await post(`?tags=${many}`)).status).toBe(400);
  });

  test('ingestSbom stores the tags it is given', async () => {
    await ingestSbom(db, fixture('cyclonedx.json'), { tags: ['x', 'y'] });
    expect(await tagsOf('web-app')).toEqual(['x', 'y']);
  });

  test('a row stored before the column existed reads as no tags', async () => {
    await db.insert(schema.projects).values({ name: 'legacy' });
    expect(await tagsOf('legacy')).toEqual([]);
  });

  test('the projects API returns them', async () => {
    const created = await (await post('?tags=team:web')).json();
    const list = await (await listProjectsRoute(new Request(`${BASE}/api/v1/projects`))).json();
    expect(list[0]).toMatchObject({ name: 'web-app', tags: ['team:web'] });
    const one = await (
      await getProject(new Request(`${BASE}/api/v1/projects/${created.projectId}`), {
        params: Promise.resolve({ id: String(created.projectId) }),
      })
    ).json();
    expect(one.tags).toEqual(['team:web']);
  });
});
