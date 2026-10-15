// CISA Known Exploited Vulnerabilities (KEV) catalog: https://www.cisa.gov/known-exploited-vulnerabilities-catalog
import { eq } from 'drizzle-orm';
import { z } from 'zod';
import type { Db } from '@/db';
import { feedSyncs, kevEntries } from '@/db/schema';
import { fetchJson, type FetchFn } from './http';

export const KEV_FEED = 'kev';
/** After a failed attempt, wait this long before trying again. */
const RETRY_MINUTES = 15;

const kevFeedSchema = z.looseObject({
  vulnerabilities: z.array(
    z.looseObject({
      cveID: z.string(),
      vendorProject: z.string().nullish(),
      product: z.string().nullish(),
      vulnerabilityName: z.string().nullish(),
      dateAdded: z.string(),
      dueDate: z.string().nullish(),
      knownRansomwareCampaignUse: z.string().nullish(),
    }),
  ),
});

export interface KevSyncOptions {
  fetchImpl: FetchFn;
  url: string;
  ttlHours: number;
  force?: boolean;
}

/** Downloads the catalog when it is older than the TTL. Returns true when it was refreshed. Throws on failure. */
export async function syncKev(db: Db, { fetchImpl, url, ttlHours, force }: KevSyncOptions): Promise<boolean> {
  const now = Date.now();
  const [state] = await db.select().from(feedSyncs).where(eq(feedSyncs.name, KEV_FEED));
  if (!force && state) {
    const fresh = state.syncedAt && state.syncedAt.getTime() > now - ttlHours * 3600e3;
    const backingOff = state.error && state.attemptedAt.getTime() > now - RETRY_MINUTES * 60e3;
    if (fresh || backingOff) return false;
  }

  try {
    const feed = await fetchJson(fetchImpl, url, kevFeedSchema, { timeoutMs: 60_000 });
    if (!feed) throw new Error(`KEV feed not found at ${url}`);
    const rows = feed.vulnerabilities.map((v) => ({
      cveId: v.cveID.toUpperCase(),
      vendor: v.vendorProject ?? null,
      product: v.product ?? null,
      name: v.vulnerabilityName ?? null,
      dateAdded: v.dateAdded,
      dueDate: v.dueDate || null,
      knownRansomwareUse: v.knownRansomwareCampaignUse?.toLowerCase() === 'known',
    }));
    const at = new Date();
    await db.transaction(async (tx) => {
      await tx.delete(kevEntries);
      for (let i = 0; i < rows.length; i += 500) {
        await tx.insert(kevEntries).values(rows.slice(i, i + 500)).onConflictDoNothing();
      }
      await tx
        .insert(feedSyncs)
        .values({ name: KEV_FEED, syncedAt: at, attemptedAt: at, error: null })
        .onConflictDoUpdate({ target: feedSyncs.name, set: { syncedAt: at, attemptedAt: at, error: null } });
    });
    return true;
  } catch (err) {
    const message = (err as Error).message.slice(0, 500);
    const at = new Date();
    await db
      .insert(feedSyncs)
      .values({ name: KEV_FEED, attemptedAt: at, error: message })
      .onConflictDoUpdate({ target: feedSyncs.name, set: { attemptedAt: at, error: message } });
    throw err;
  }
}
