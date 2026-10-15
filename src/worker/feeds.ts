// Shared bookkeeping for jobs that pull external feeds: TTL freshness and retry backoff, stored in `feed_syncs`.
import { eq } from 'drizzle-orm';
import type { Db } from '@/db';
import { feedSyncs } from '@/db/schema';

/** After a failed attempt, wait this long before trying again. */
const RETRY_MINUTES = 15;

/** True when the feed was synced within the TTL, or a recent attempt failed. `force` bypasses both. */
export async function feedIsCurrent(db: Db, name: string, ttlHours: number, force?: boolean): Promise<boolean> {
  if (force) {
    return false;
  }
  const [state] = await db.select().from(feedSyncs).where(eq(feedSyncs.name, name));
  if (!state) {
    return false;
  }
  const now = Date.now();
  const fresh = !!state.syncedAt && state.syncedAt.getTime() > now - ttlHours * 3600e3;
  const backingOff = !!state.error && state.attemptedAt.getTime() > now - RETRY_MINUTES * 60e3;
  return fresh || backingOff;
}

export async function recordFeedSuccess(db: Pick<Db, 'insert'>, name: string, at = new Date()) {
  await db
    .insert(feedSyncs)
    .values({ name, syncedAt: at, attemptedAt: at, error: null })
    .onConflictDoUpdate({ target: feedSyncs.name, set: { syncedAt: at, attemptedAt: at, error: null } });
}

export async function recordFeedFailure(db: Db, name: string, err: unknown) {
  const message = (err as Error).message.slice(0, 500);
  const at = new Date();
  await db
    .insert(feedSyncs)
    .values({ name, attemptedAt: at, error: message })
    .onConflictDoUpdate({ target: feedSyncs.name, set: { attemptedAt: at, error: message } });
}
