// FIRST EPSS scores: https://www.first.org/epss/api. Only CVEs we actually track are looked up.
import { inArray } from 'drizzle-orm';
import { z } from 'zod';
import type { Db } from '@/db';
import { epssScores, vulnerabilities } from '@/db/schema';
import { feedIsCurrent, recordFeedFailure, recordFeedSuccess } from './feeds';
import { fetchJson, type FetchFn } from './http';

export const EPSS_FEED = 'epss';
/** CVEs per request; keeps the URL well under common length limits. */
export const EPSS_BATCH_SIZE = 50;

const epssResponse = z.looseObject({
  data: z.array(
    z.looseObject({
      cve: z.string(),
      epss: z.coerce.number(),
      percentile: z.coerce.number(),
      date: z.string().nullish(),
    }),
  ),
});

export interface EpssSyncOptions {
  fetchImpl: FetchFn;
  url: string;
  ttlHours: number;
  force?: boolean;
}

/** Looks up EPSS for CVEs that have no score yet or a stale one. Returns how many CVEs were refreshed. Throws on failure. */
export async function syncEpss(db: Db, { fetchImpl, url, ttlHours, force }: EpssSyncOptions): Promise<number> {
  // Freshness is tracked per CVE (new vulnerabilities must be looked up right away), so the feed-level TTL is 0:
  // this only applies the retry backoff after a failed attempt.
  if (await feedIsCurrent(db, EPSS_FEED, 0, force)) {
    return 0;
  }

  const tracked = await db.select({ id: vulnerabilities.id, aliases: vulnerabilities.aliases }).from(vulnerabilities);
  const cves = [...new Set(tracked.flatMap((v) => [v.id, ...v.aliases]).filter((id) => id.startsWith('CVE-')))];
  if (!cves.length) {
    return 0;
  }
  const known = new Map<string, number>();
  for (let i = 0; i < cves.length; i += 1000) {
    const rows = await db.select().from(epssScores).where(inArray(epssScores.cveId, cves.slice(i, i + 1000)));
    for (const r of rows) {
      known.set(r.cveId, r.fetchedAt.getTime());
    }
  }
  const cutoff = force ? Date.now() + 1000 : Date.now() - ttlHours * 3600e3;
  const due = cves.filter((cve) => (known.get(cve) ?? 0) < cutoff);
  if (!due.length) {
    return 0;
  }

  try {
    for (let i = 0; i < due.length; i += EPSS_BATCH_SIZE) {
      const batch = due.slice(i, i + EPSS_BATCH_SIZE);
      const res = await fetchJson(fetchImpl, `${url}?cve=${batch.join(',')}`, epssResponse);
      if (!res) {
        throw new Error(`EPSS API returned 404 for ${url}`);
      }
      const scored = new Map(res.data.map((d) => [d.cve.toUpperCase(), d]));
      const at = new Date();
      const rows = batch.map((cve) => {
        const hit = scored.get(cve);
        return {
          cveId: cve,
          score: hit?.epss ?? null,
          percentile: hit?.percentile ?? null,
          modelDate: hit?.date ?? null,
          fetchedAt: at,
        };
      });
      for (const row of rows) {
        await db.insert(epssScores).values(row).onConflictDoUpdate({ target: epssScores.cveId, set: row });
      }
    }
    await recordFeedSuccess(db, EPSS_FEED);
    return due.length;
  } catch (err) {
    await recordFeedFailure(db, EPSS_FEED, err);
    throw err;
  }
}
