// Daily per-project snapshots of vulnerability and freshness counts (project_snapshots).
import { and, eq, inArray, isNotNull } from 'drizzle-orm';
import type { Db } from '@/db';
import { components, packages, projects, projectSnapshots, versionVulnerabilities, vulnerabilities } from '@/db/schema';
import { snapshotCounts, type SnapshotInput } from '@/lib/snapshot';

/** Upserts today's snapshot for every project that has an SBOM. Returns how many rows were written. */
export async function writeSnapshots(db: Db, now = new Date()): Promise<number> {
  const day = now.toISOString().slice(0, 10);
  const latest = await db.select({ id: projects.id, sbomId: projects.latestSbomId }).from(projects).where(isNotNull(projects.latestSbomId));
  if (!latest.length) {
    return 0;
  }
  const sbomIds = latest.map((p) => p.sbomId!);

  const rows = await db
    .select({
      sbomId: components.sbomId,
      packageKey: components.packageKey,
      version: components.version,
      latestVersion: packages.latestVersion,
    })
    .from(components)
    .leftJoin(packages, eq(packages.key, components.packageKey))
    .where(inArray(components.sbomId, sbomIds));

  const vulnRows = await db
    .selectDistinct({
      packageKey: versionVulnerabilities.packageKey,
      version: versionVulnerabilities.version,
      id: vulnerabilities.id,
      severity: vulnerabilities.severity,
    })
    .from(versionVulnerabilities)
    .innerJoin(vulnerabilities, eq(vulnerabilities.id, versionVulnerabilities.vulnerabilityId))
    .innerJoin(
      components,
      // Same pairing the dashboard uses: a component's vulnerabilities are those of its exact package version.
      and(eq(components.packageKey, versionVulnerabilities.packageKey), eq(components.version, versionVulnerabilities.version)),
    )
    .where(inArray(components.sbomId, sbomIds));

  const vulnsByVersion = new Map<string, { id: string; severity: SnapshotInput['vulns'][number]['severity'] }[]>();
  for (const v of vulnRows) {
    const key = `${v.packageKey}@${v.version}`;
    vulnsByVersion.set(key, [...(vulnsByVersion.get(key) ?? []), { id: v.id, severity: v.severity }]);
  }
  const bySbom = new Map<number, SnapshotInput[]>();
  for (const r of rows) {
    const list = bySbom.get(r.sbomId) ?? [];
    list.push({ version: r.version, latestVersion: r.latestVersion, vulns: vulnsByVersion.get(`${r.packageKey}@${r.version}`) ?? [] });
    bySbom.set(r.sbomId, list);
  }

  for (const p of latest) {
    const counts = snapshotCounts(bySbom.get(p.sbomId!) ?? []);
    await db
      .insert(projectSnapshots)
      .values({ projectId: p.id, day, ...counts })
      .onConflictDoUpdate({ target: [projectSnapshots.projectId, projectSnapshots.day], set: { ...counts, updatedAt: now } });
  }
  return latest.length;
}
