// Enrichment jobs: CVE lookups (OSV.dev) and latest-version lookups (deps.dev).
// The database is the queue: rows with a null or stale "checked at" timestamp are due.
import { and, asc, eq, gte, inArray, isNull, lt, or, sql } from 'drizzle-orm';
import type { Db } from '@/db';
import { components, packages, packageVersions, versionVulnerabilities, vulnerabilities } from '@/db/schema';
import { isVersionCheckable, SCANNABLE_ECOSYSTEMS } from '@/lib/coverage';
import { isDistroScoped } from '@/lib/ecosystems';
import { parsePurl } from '@/lib/purl';
import { latestVersion } from './depsdev';
import { mapLimit, type FetchFn } from './http';
import { syncEpss } from './epss';
import { syncKev } from './kev';
import { writeSnapshots } from './snapshots';
import { fetchVuln, fixedVersions, queryBatch, vulnRecord, type OsvVuln, type VersionQuery } from './osv';

export interface EnrichOptions {
  fetchImpl?: FetchFn;
  osvApiUrl: string;
  depsDevApiUrl: string;
  vulnTtlHours: number;
  latestTtlHours: number;
  /** Clock for the daily snapshot; tests pin it. */
  now?: Date;
  /** CISA KEV catalog; the job is skipped when `kevUrl` is not set. */
  kevUrl?: string;
  kevTtlHours?: number;
  /** FIRST EPSS API; the job is skipped when `epssUrl` is not set. */
  epssUrl?: string;
  epssTtlHours?: number;
  force?: boolean;
  logger?: Pick<Console, 'info' | 'warn' | 'error'>;
}

export interface EnrichStats {
  versionsScanned: number;
  vulnsFetched: number;
  packagesChecked: number;
  errors: number;
  /** Whole-feed downloads refreshed this run (e.g. the KEV catalog). */
  feedsSynced: number;
}

const BATCH_SIZE = 500;

/** OS packages are matched by release, which only the component purls carry (`distro`); the newest upload that carries one wins.
 * One version row holds one vulnerability set, so the same version in two releases is only checked against one. */
async function distrosFor(db: Db, rows: { packageKey: string; version: string; type: string }[]): Promise<Map<string, string>> {
  const keys = [...new Set(rows.filter((r) => isDistroScoped(r.type)).map((r) => r.packageKey))];
  const out = new Map<string, string>();
  if (!keys.length) {
    return out;
  }
  const found = await db
    .select({ packageKey: components.packageKey, version: components.version, purl: components.purl })
    .from(components)
    .where(inArray(components.packageKey, keys))
    .orderBy(asc(components.id));
  for (const c of found) {
    const distro = parsePurl(c.purl)?.qualifiers.distro;
    if (distro && c.version) {
      out.set(`${c.packageKey}@${c.version}`, distro);
    }
  }
  return out;
}

export async function enrich(db: Db, opts: EnrichOptions): Promise<EnrichStats> {
  const stats: EnrichStats = { versionsScanned: 0, vulnsFetched: 0, packagesChecked: 0, errors: 0, feedsSynced: 0 };
  // Independent jobs: one upstream API being down must not block the other.
  for (const [name, job] of [
    ['vulnerability scan', scanVulnerabilities],
    ['latest-version check', checkLatestVersions],
    ['KEV sync', syncKevFeed],
    ['EPSS sync', syncEpssScores],
    ['snapshots', snapshotProjects],
  ] as const) {
    try {
      await job(db, opts, stats);
    } catch (err) {
      stats.errors++;
      const cause = (err as Error & { cause?: Error }).cause;
      opts.logger?.error(`[worker] ${name} failed: ${(err as Error).message}${cause ? ` (${cause.message})` : ''}`);
    }
  }
  return stats;
}

async function syncKevFeed(db: Db, opts: EnrichOptions, stats: EnrichStats) {
  if (!opts.kevUrl) {
    return;
  }
  const synced = await syncKev(db, {
    fetchImpl: opts.fetchImpl ?? fetch,
    url: opts.kevUrl,
    ttlHours: opts.kevTtlHours ?? 24,
    force: opts.force,
  });
  if (synced) {
    stats.feedsSynced++;
  }
}

async function syncEpssScores(db: Db, opts: EnrichOptions, stats: EnrichStats) {
  if (!opts.epssUrl) {
    return;
  }
  const refreshed = await syncEpss(db, {
    fetchImpl: opts.fetchImpl ?? fetch,
    url: opts.epssUrl,
    ttlHours: opts.epssTtlHours ?? 24,
    force: opts.force,
  });
  if (refreshed) {
    stats.feedsSynced++;
  }
}

const cutoff = (hours: number, force?: boolean) => new Date(force ? Date.now() + 1000 : Date.now() - hours * 3600e3);

async function scanVulnerabilities(db: Db, opts: EnrichOptions, stats: EnrichStats) {
  const fetchImpl = opts.fetchImpl ?? fetch;
  const before = cutoff(opts.vulnTtlHours, opts.force);
  const due = await db
    .select({
      packageKey: packageVersions.packageKey,
      version: packageVersions.version,
      type: packages.ecosystem,
      namespace: packages.namespace,
      name: packages.name,
    })
    .from(packageVersions)
    .innerJoin(packages, eq(packages.key, packageVersions.packageKey))
    .where(
      and(
        inArray(packages.ecosystem, SCANNABLE_ECOSYSTEMS as string[]),
        or(isNull(packageVersions.vulnsCheckedAt), lt(packageVersions.vulnsCheckedAt, before)),
      ),
    )
    .orderBy(sql`${packageVersions.vulnsCheckedAt} asc nulls first`);

  for (let i = 0; i < due.length; i += BATCH_SIZE) {
    const rows = due.slice(i, i + BATCH_SIZE);
    const distros = await distrosFor(db, rows);
    const queries: VersionQuery[] = rows.map((r) => ({ pkg: r, version: r.version, distro: distros.get(`${r.packageKey}@${r.version}`) }));
    const results = await queryBatch(fetchImpl, opts.osvApiUrl, queries);

    // Fetch details for vulnerabilities not stored (or stale).
    const ids = [...new Set(results.flatMap((r) => ('vulnIds' in r ? r.vulnIds : [])))];
    const fresh = ids.length
      ? new Set(
          (
            await db
              .select({ id: vulnerabilities.id })
              .from(vulnerabilities)
              .where(and(inArray(vulnerabilities.id, ids), gte(vulnerabilities.fetchedAt, before)))
          ).map((r) => r.id),
        )
      : new Set<string>();
    const details = new Map<string, OsvVuln>();
    await mapLimit(
      ids.filter((id) => !fresh.has(id)),
      8,
      async (id) => {
        try {
          const v = await fetchVuln(fetchImpl, opts.osvApiUrl, id);
          if (v) {
            details.set(id, v);
          }
        } catch (err) {
          stats.errors++;
          opts.logger?.warn(`[worker] vulnerability ${id}: ${(err as Error).message}`);
        }
      },
    );
    stats.vulnsFetched += details.size;

    await db.transaction(async (tx) => {
      const now = new Date();
      for (const v of details.values()) {
        const record = { ...vulnRecord(v), fetchedAt: now };
        await tx.insert(vulnerabilities).values(record).onConflictDoUpdate({ target: vulnerabilities.id, set: record });
      }
      const stored = new Set(
        ids.length
          ? (await tx.select({ id: vulnerabilities.id }).from(vulnerabilities).where(inArray(vulnerabilities.id, ids))).map((r) => r.id)
          : [],
      );

      for (const [idx, row] of rows.entries()) {
        const res = results[idx];
        const where = and(eq(packageVersions.packageKey, row.packageKey), eq(packageVersions.version, row.version));
        if ('error' in res) {
          await tx
            .update(packageVersions)
            .set({ vulnsCheckedAt: now, vulnsError: res.error.slice(0, 500) })
            .where(where);
          continue;
        }
        const missing = res.vulnIds.filter((id) => !stored.has(id));
        if (missing.length) {
          // Leave unchecked so the next run retries the failed detail lookups.
          await tx
            .update(packageVersions)
            .set({ vulnsError: `could not fetch ${missing.join(', ')}`.slice(0, 500) })
            .where(where);
          continue;
        }
        const linkWhere = and(eq(versionVulnerabilities.packageKey, row.packageKey), eq(versionVulnerabilities.version, row.version));
        const previous = new Map(
          (await tx.select().from(versionVulnerabilities).where(linkWhere)).map((l) => [l.vulnerabilityId, l.fixedVersions]),
        );
        await tx.delete(versionVulnerabilities).where(linkWhere);
        if (res.vulnIds.length) {
          await tx.insert(versionVulnerabilities).values(
            res.vulnIds.map((id) => {
              const detail = details.get(id);
              return {
                packageKey: row.packageKey,
                version: row.version,
                vulnerabilityId: id,
                fixedVersions: detail ? fixedVersions(detail, row) : (previous.get(id) ?? []),
              };
            }),
          );
        }
        await tx.update(packageVersions).set({ vulnsCheckedAt: now, vulnsError: null }).where(where);
      }
    });
    stats.versionsScanned += rows.length;
  }
}

async function checkLatestVersions(db: Db, opts: EnrichOptions, stats: EnrichStats) {
  const fetchImpl = opts.fetchImpl ?? fetch;
  const before = cutoff(opts.latestTtlHours, opts.force);
  const due = (
    await db
      .select({ key: packages.key, type: packages.ecosystem, namespace: packages.namespace, name: packages.name })
      .from(packages)
      .where(or(isNull(packages.latestCheckedAt), lt(packages.latestCheckedAt, before)))
      .orderBy(asc(packages.key))
  ).filter((p) => isVersionCheckable(p.type));

  await mapLimit(due, 8, async (p) => {
    let latest: string | null = null;
    let error: string | null = null;
    try {
      latest = await latestVersion(fetchImpl, opts.depsDevApiUrl, p);
      if (!latest) {
        error = 'not found';
      }
    } catch (err) {
      stats.errors++;
      error = (err as Error).message.slice(0, 500);
    }
    await db
      .update(packages)
      .set({ latestVersion: sql`coalesce(${latest}, ${packages.latestVersion})`, latestCheckedAt: new Date(), latestError: error })
      .where(eq(packages.key, p.key));
    stats.packagesChecked++;
  });
}

async function snapshotProjects(db: Db, opts: EnrichOptions) {
  // Last, so today's row reflects what this run just learned. Uploads wake the worker, which covers the upload-time snapshot.
  await writeSnapshots(db, opts.now);
}
