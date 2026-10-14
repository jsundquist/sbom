// Background enrichment: CVE lookups (OSV) and latest-version lookups (deps.dev).
import { transaction } from '../db.js';
import { OSV_TYPES, queryBatch, fetchVuln, vulnRecord, fixedVersions } from './osv.js';
import { depsDevSystem, latestVersion } from './depsdev.js';
import { mapLimit } from './http.js';

const BATCH = 500;

export class Enricher {
  constructor(db, config, { fetchImpl = globalThis.fetch, logger = console } = {}) {
    this.db = db;
    this.config = config;
    this.fetch = fetchImpl;
    this.log = logger;
    this.running = null;
    this.rerun = false;
    this.lastRun = null;
  }

  /** Runs enrichment; concurrent calls coalesce into one follow-up run. */
  trigger({ force = false } = {}) {
    if (force) this.force = true;
    if (this.running) {
      this.rerun = true;
      return this.running;
    }
    this.running = (async () => {
      try {
        do {
          this.rerun = false;
          const f = this.force;
          this.force = false;
          await this.run({ force: f });
        } while (this.rerun);
      } finally {
        this.running = null;
      }
    })();
    return this.running;
  }

  async run({ force = false } = {}) {
    const started = Date.now();
    const stats = { versionsScanned: 0, vulnsFetched: 0, packagesChecked: 0, errors: 0 };
    try {
      await this.scanVulnerabilities(stats, force);
      await this.checkLatestVersions(stats, force);
    } catch (err) {
      stats.errors++;
      this.log.error?.(`[enrich] failed: ${err.message}`);
    }
    this.lastRun = { ...stats, finishedAt: new Date().toISOString(), durationMs: Date.now() - started };
    if (stats.versionsScanned || stats.packagesChecked) this.log.info?.(`[enrich] ${JSON.stringify(this.lastRun)}`);
    return this.lastRun;
  }

  cutoff(hours, force) {
    return force ? new Date(Date.now() + 1000).toISOString() : new Date(Date.now() - hours * 3600e3).toISOString();
  }

  async scanVulnerabilities(stats, force) {
    const cutoff = this.cutoff(this.config.vulnTtlHours, force);
    const types = [...OSV_TYPES].map((t) => `'${t}'`).join(',');
    const rows = this.db
      .prepare(
        `SELECT pv.package_key, pv.version, p.ecosystem, p.namespace, p.name
         FROM package_versions pv JOIN packages p ON p.key = pv.package_key
         WHERE p.ecosystem IN (${types}) AND (pv.vulns_checked_at IS NULL OR pv.vulns_checked_at < ?)
         ORDER BY pv.vulns_checked_at IS NOT NULL, pv.vulns_checked_at`,
      )
      .all(cutoff);

    for (let i = 0; i < rows.length; i += BATCH) {
      const chunk = rows.slice(i, i + BATCH);
      const items = chunk.map((r) => ({
        row: r,
        version: r.version,
        pkg: { type: r.ecosystem, namespace: r.namespace, name: r.name },
      }));
      const results = await queryBatch(this.fetch, this.config.osvApiUrl, items);

      // Fetch details for vulnerabilities we haven't stored yet.
      const ids = [...new Set(results.flatMap((r) => r.vulnIds || []))];
      const known = new Set();
      const stmt = this.db.prepare('SELECT id FROM vulnerabilities WHERE id = ? AND fetched_at >= ?');
      for (const id of ids) if (stmt.get(id, cutoff)) known.add(id);
      const details = new Map();
      await mapLimit(
        ids.filter((id) => !known.has(id)),
        8,
        async (id) => {
          try {
            const v = await fetchVuln(this.fetch, this.config.osvApiUrl, id);
            if (v) details.set(id, v);
          } catch (err) {
            stats.errors++;
            this.log.warn?.(`[enrich] vuln ${id}: ${err.message}`);
          }
        },
      );
      stats.vulnsFetched += details.size;
      this.storeVulnResults(items, results, details);
      stats.versionsScanned += chunk.length;
    }
  }

  storeVulnResults(items, results, details) {
    const now = new Date().toISOString();
    const db = this.db;
    transaction(db, () => {
      const upsertVuln = db.prepare(
        `INSERT INTO vulnerabilities (id, aliases, summary, details, severity, score, vector, published, modified, refs, fetched_at)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
         ON CONFLICT(id) DO UPDATE SET aliases=excluded.aliases, summary=excluded.summary, details=excluded.details,
           severity=excluded.severity, score=excluded.score, vector=excluded.vector, published=excluded.published,
           modified=excluded.modified, refs=excluded.refs, fetched_at=excluded.fetched_at`,
      );
      for (const v of details.values()) {
        const r = vulnRecord(v);
        upsertVuln.run(r.id, JSON.stringify(r.aliases), r.summary, r.details, r.severity, r.score, r.vector,
          r.published, r.modified, JSON.stringify(r.refs), now);
      }
      const exists = db.prepare('SELECT 1 FROM vulnerabilities WHERE id = ?');
      const existingFixes = db.prepare('SELECT fixed_versions FROM version_vulns WHERE package_key = ? AND version = ? AND vuln_id = ?');
      const clear = db.prepare('DELETE FROM version_vulns WHERE package_key = ? AND version = ?');
      const link = db.prepare('INSERT OR REPLACE INTO version_vulns (package_key, version, vuln_id, fixed_versions) VALUES (?, ?, ?, ?)');
      const mark = db.prepare('UPDATE package_versions SET vulns_checked_at = ?, vulns_error = ? WHERE package_key = ? AND version = ?');

      items.forEach((item, idx) => {
        const res = results[idx];
        const { package_key: key, version } = item.row;
        if (res.error) {
          mark.run(now, res.error.slice(0, 500), key, version);
          return;
        }
        const missing = res.vulnIds.filter((id) => !details.has(id) && !exists.get(id));
        if (missing.length) {
          // Leave unchecked so the next run retries the failed detail lookups.
          db.prepare('UPDATE package_versions SET vulns_error = ? WHERE package_key = ? AND version = ?')
            .run(`could not fetch ${missing.join(', ')}`.slice(0, 500), key, version);
          return;
        }
        const previous = new Map();
        for (const id of res.vulnIds) {
          const prev = existingFixes.get(key, version, id);
          if (prev) previous.set(id, prev.fixed_versions);
        }
        clear.run(key, version);
        for (const id of res.vulnIds) {
          if (!exists.get(id)) continue;
          const detail = details.get(id);
          const fixed = detail ? JSON.stringify(fixedVersions(detail, item.pkg)) : previous.get(id) || '[]';
          link.run(key, version, id, fixed);
        }
        mark.run(now, null, key, version);
      });
    });
  }

  async checkLatestVersions(stats, force) {
    const cutoff = this.cutoff(this.config.latestTtlHours, force);
    const rows = this.db
      .prepare('SELECT key, ecosystem, namespace, name FROM packages WHERE latest_checked_at IS NULL OR latest_checked_at < ?')
      .all(cutoff)
      .filter((r) => depsDevSystem(r.ecosystem));
    const update = this.db.prepare('UPDATE packages SET latest_version = COALESCE(?, latest_version), latest_checked_at = ?, latest_error = ? WHERE key = ?');
    await mapLimit(rows, 8, async (r) => {
      const now = new Date().toISOString();
      try {
        const latest = await latestVersion(this.fetch, this.config.depsDevApiUrl, {
          type: r.ecosystem,
          namespace: r.namespace,
          name: r.name,
        });
        update.run(latest, now, latest ? null : 'not found', r.key);
      } catch (err) {
        stats.errors++;
        update.run(null, now, err.message.slice(0, 500), r.key);
      }
      stats.packagesChecked++;
    });
  }
}
