import { and, desc, eq, notInArray, sql } from 'drizzle-orm';
import type { Db } from '@/db';
import { componentEdges, components, packages, packageVersions, projects, sboms } from '@/db/schema';
import { SBOM_UPLOADED_CHANNEL } from '@/lib/channels';
import { parsePurl } from '@/lib/purl';
import { componentKey, parseSbom } from '@/sbom/parse';

export interface UploadMeta {
  project?: string;
  version?: string;
  ref?: string;
  commit?: string;
  repository?: string;
}

export class IngestError extends Error {}

function chunk<T>(items: T[], size: number): T[][] {
  const out: T[][] = [];
  for (let i = 0; i < items.length; i += size) {
    out.push(items.slice(i, i + size));
  }
  return out;
}

/** Stores an SBOM for a project, creating the project on first upload. */
export async function ingestSbom(db: Db, document: unknown, meta: UploadMeta, { historyLimit = 20 } = {}) {
  const parsed = parseSbom(document);
  const projectName = (meta.project || parsed.subject?.name || '').trim();
  if (!projectName) {
    throw new IngestError('Project name is required: pass "project" or include the subject component in the SBOM');
  }

  const result = await db.transaction(async (tx) => {
    const now = new Date();
    const [project] = await tx
      .insert(projects)
      .values({ name: projectName, repository: meta.repository ?? null })
      .onConflictDoUpdate({
        target: projects.name,
        set: { repository: sql`COALESCE(excluded.repository, ${projects.repository})`, updatedAt: now },
      })
      .returning({ id: projects.id });

    const [sbom] = await tx
      .insert(sboms)
      .values({
        projectId: project.id,
        version: meta.version || parsed.subject?.version || null,
        ref: meta.ref ?? null,
        commitSha: meta.commit ?? null,
        format: parsed.format,
        specVersion: parsed.specVersion,
        componentCount: parsed.components.length,
        document: document as object,
        uploadedAt: now,
      })
      .returning({ id: sboms.id });

    const idByKey = new Map<string, number>();
    for (const rows of chunk(parsed.components, 1000)) {
      const inserted = await tx
        .insert(components)
        .values(rows.map((c) => ({ ...c, sbomId: sbom.id })))
        .returning({ id: components.id });
      rows.forEach((c, i) => idByKey.set(componentKey(c), inserted[i].id));
    }
    const edgeRows = [
      ...(parsed.direct ?? []).map((to) => ({ parent: null, to })),
      ...parsed.edges.map((e) => ({ parent: e.from, to: e.to })),
    ].map((e) => ({
      sbomId: sbom.id,
      parentId: e.parent === null ? null : (idByKey.get(e.parent) ?? null),
      childId: idByKey.get(e.to)!,
    }));
    for (const rows of chunk(edgeRows, 1000)) {
      await tx.insert(componentEdges).values(rows);
    }

    const withPurl = parsed.components.filter((c) => c.packageKey);
    const pkgRows = new Map<string, typeof packages.$inferInsert>();
    for (const c of withPurl) {
      const p = parsePurl(c.purl)!;
      pkgRows.set(c.packageKey!, { key: c.packageKey!, ecosystem: p.type, namespace: p.namespace, name: p.name });
    }
    for (const rows of chunk([...pkgRows.values()], 1000)) {
      await tx.insert(packages).values(rows).onConflictDoNothing();
    }
    const versionRows = withPurl.filter((c) => c.version).map((c) => ({ packageKey: c.packageKey!, version: c.version! }));
    for (const rows of chunk(versionRows, 1000)) {
      await tx.insert(packageVersions).values(rows).onConflictDoNothing();
    }

    await tx.update(projects).set({ latestSbomId: sbom.id }).where(eq(projects.id, project.id));

    // Keep the newest `historyLimit` uploads per project.
    const keep = tx
      .select({ id: sboms.id })
      .from(sboms)
      .where(eq(sboms.projectId, project.id))
      .orderBy(desc(sboms.uploadedAt), desc(sboms.id))
      .limit(historyLimit);
    await tx.delete(sboms).where(and(eq(sboms.projectId, project.id), notInArray(sboms.id, keep)));

    // Wakes the worker; delivered on commit.
    await tx.execute(sql.raw(`NOTIFY ${SBOM_UPLOADED_CHANNEL}`));
    return { projectId: project.id, projectName, sbomId: sbom.id, componentCount: parsed.components.length };
  });

  await garbageCollect(db);
  return result;
}

/** Removes packages, versions and vulnerabilities no longer referenced by any stored SBOM. */
export async function garbageCollect(db: Db) {
  await db.execute(sql`
    DELETE FROM package_versions pv WHERE NOT EXISTS (
      SELECT 1 FROM components c WHERE c.package_key = pv.package_key AND c.version = pv.version)`);
  await db.execute(sql`DELETE FROM packages p WHERE NOT EXISTS (SELECT 1 FROM components c WHERE c.package_key = p.key)`);
  await db.execute(sql`
    DELETE FROM vulnerabilities v WHERE NOT EXISTS (
      SELECT 1 FROM version_vulnerabilities vv WHERE vv.vulnerability_id = v.id)`);
}

export async function deleteProject(db: Db, id: number) {
  const deleted = await db.delete(projects).where(eq(projects.id, id)).returning({ id: projects.id });
  if (deleted.length) {
    await garbageCollect(db);
  }
  return deleted.length > 0;
}
