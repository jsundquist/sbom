// Trend reads over project_snapshots. Pages and API routes share these.
import { asc, eq, gte, and } from 'drizzle-orm';
import type { Db } from '@/db';
import { projects, projectSnapshots } from '@/db/schema';
import type { SnapshotCounts } from '@/lib/snapshot';

export interface TrendPoint extends SnapshotCounts {
  /** UTC date, YYYY-MM-DD. */
  day: string;
}

const COUNT_KEYS = [
  'components',
  'vulnerableComponents',
  'vulnerabilities',
  'critical',
  'high',
  'medium',
  'low',
  'unknown',
  'outdatedComponents',
  'outdatedMajor',
] as const satisfies readonly (keyof SnapshotCounts)[];

/** First day of a window of `days` days that ends today. */
const since = (days: number, now: Date) => new Date(now.getTime() - (days - 1) * 86_400_000).toISOString().slice(0, 10);

const toPoint = (r: SnapshotCounts & { day: string }): TrendPoint =>
  ({ day: r.day, ...Object.fromEntries(COUNT_KEYS.map((k) => [k, r[k]])) }) as TrendPoint;

/** One project's daily points, oldest first; null when the project does not exist. */
export async function getProjectTrend(db: Db, projectId: number, days: number, now = new Date()): Promise<TrendPoint[] | null> {
  const [project] = await db.select({ id: projects.id }).from(projects).where(eq(projects.id, projectId));
  if (!project) {
    return null;
  }
  const rows = await db
    .select()
    .from(projectSnapshots)
    .where(and(eq(projectSnapshots.projectId, projectId), gte(projectSnapshots.day, since(days, now))))
    .orderBy(asc(projectSnapshots.day));
  return rows.map(toPoint);
}

/**
 * All applications together. Each day sums every project's latest snapshot at or before that day, so a project that
 * was not snapshotted on a day (worker down) keeps its last known numbers instead of dropping out of the total.
 */
export async function getSummaryTrend(db: Db, days: number, now = new Date()): Promise<TrendPoint[]> {
  const rows = await db
    .select()
    .from(projectSnapshots)
    .where(gte(projectSnapshots.day, since(days, now)))
    .orderBy(asc(projectSnapshots.day));
  const latest = new Map<number, (typeof rows)[number]>();
  const points: TrendPoint[] = [];
  for (let i = 0; i < rows.length; i++) {
    latest.set(rows[i].projectId, rows[i]);
    // Emit once all of a day's rows are applied.
    if (i + 1 < rows.length && rows[i + 1].day === rows[i].day) {
      continue;
    }
    const total = Object.fromEntries(COUNT_KEYS.map((k) => [k, 0])) as unknown as SnapshotCounts;
    for (const r of latest.values()) {
      for (const k of COUNT_KEYS) {
        total[k] += r[k];
      }
    }
    points.push({ day: rows[i].day, ...total });
  }
  return points;
}
