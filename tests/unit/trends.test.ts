import { afterEach, beforeEach, describe, expect, test } from 'vitest';
import { schema, setDb, type Db } from '@/db';
import { GET as projectTrends } from '@/app/api/v1/projects/[id]/trends/route';
import { GET as summaryTrends } from '@/app/api/v1/summary/trends/route';
import { getProjectTrend, getSummaryTrend } from '@/server/trends';
import { createTestDb } from './helpers';

const BASE = 'http://dash.test';
const ctx = (id: string) => ({ params: Promise.resolve({ id }) });
const counts = (vulnerabilities: number, components = 10) => ({
  components,
  vulnerableComponents: vulnerabilities,
  vulnerabilities,
  critical: 0,
  high: vulnerabilities,
  medium: 0,
  low: 0,
  unknown: 0,
  outdatedComponents: 1,
  outdatedMajor: 0,
});

let db: Db;
let close: () => Promise<void>;
let a: number;
let b: number;

beforeEach(async () => {
  ({ db, close } = await createTestDb());
  setDb(db);
  [{ id: a }, { id: b }] = await db
    .insert(schema.projects)
    .values([{ name: 'a' }, { name: 'b' }])
    .returning({ id: schema.projects.id });
  const row = (projectId: number, day: string, v: number) => ({ projectId, day, ...counts(v) });
  await db.insert(schema.projectSnapshots).values([row(a, '2026-11-01', 1), row(a, '2026-11-03', 3), row(b, '2026-11-02', 5)]);
});
afterEach(() => close());

describe('getProjectTrend', () => {
  test('returns the project’s points oldest first, limited to the window', async () => {
    expect((await getProjectTrend(db, a, 365, new Date('2026-11-08')))?.map((p) => [p.day, p.vulnerabilities])).toEqual([
      ['2026-11-01', 1],
      ['2026-11-03', 3],
    ]);
    expect((await getProjectTrend(db, a, 7, new Date('2026-11-08')))?.map((p) => p.day)).toEqual(['2026-11-03']);
  });
  test('is null for an unknown project and empty for one with no snapshots yet', async () => {
    const [{ id }] = await db.insert(schema.projects).values({ name: 'new' }).returning({ id: schema.projects.id });
    expect(await getProjectTrend(db, 9999, 90)).toBeNull();
    expect(await getProjectTrend(db, id, 90)).toEqual([]);
  });
});

describe('getSummaryTrend', () => {
  test('sums each project’s latest snapshot at or before the day, so a quiet day does not drop a project', async () => {
    const points = await getSummaryTrend(db, 365, new Date('2026-11-08'));
    expect(points.map((p) => [p.day, p.vulnerabilities, p.components])).toEqual([
      ['2026-11-01', 1, 10],
      ['2026-11-02', 6, 20],
      ['2026-11-03', 8, 20],
    ]);
  });
});

describe('trend routes', () => {
  test('GET /projects/:id/trends', async () => {
    const res = await projectTrends(new Request(`${BASE}/api/v1/projects/${a}/trends?days=9999`), ctx(String(a)));
    expect(res.status).toBe(200);
    expect(((await res.json()) as { points: unknown[] }).points).toHaveLength(2);
    expect((await projectTrends(new Request(BASE), ctx('9999'))).status).toBe(404);
    expect((await projectTrends(new Request(BASE), ctx('abc'))).status).toBe(404);
  });
  test('GET /summary/trends', async () => {
    const res = await summaryTrends(new Request(`${BASE}/api/v1/summary/trends`));
    expect(res.status).toBe(200);
    expect(((await res.json()) as { points: unknown[] }).points).toHaveLength(3);
  });
});
