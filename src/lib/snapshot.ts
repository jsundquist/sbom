// Point-in-time counts for one project, stored once a day so trends survive SBOM history pruning.
import type { Severity } from './severity';
import { updateType } from './version';

export interface SnapshotInput {
  version: string | null;
  latestVersion: string | null;
  vulns: { id: string; severity: Severity }[];
}

export interface SnapshotCounts {
  components: number;
  vulnerableComponents: number;
  /** Distinct vulnerabilities, so one CVE in three components counts once. */
  vulnerabilities: number;
  critical: number;
  high: number;
  medium: number;
  low: number;
  unknown: number;
  outdatedComponents: number;
  outdatedMajor: number;
}

export function snapshotCounts(list: SnapshotInput[]): SnapshotCounts {
  const counts: SnapshotCounts = {
    components: list.length,
    vulnerableComponents: 0,
    vulnerabilities: 0,
    critical: 0,
    high: 0,
    medium: 0,
    low: 0,
    unknown: 0,
    outdatedComponents: 0,
    outdatedMajor: 0,
  };
  const seen = new Set<string>();
  for (const c of list) {
    if (c.vulns.length) {
      counts.vulnerableComponents++;
    }
    for (const v of c.vulns) {
      if (!seen.has(v.id)) {
        seen.add(v.id);
        counts.vulnerabilities++;
        counts[v.severity.toLowerCase() as 'critical' | 'high' | 'medium' | 'low' | 'unknown']++;
      }
    }
    const outdated = updateType(c.version, c.latestVersion);
    if (outdated) {
      counts.outdatedComponents++;
      if (outdated === 'major') {
        counts.outdatedMajor++;
      }
    }
  }
  return counts;
}
