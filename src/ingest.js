import zlib from 'node:zlib';
import { transaction } from './db.js';
import { parsePurl } from './lib/purl.js';
import { parseSbom } from './sbom/parse.js';

/**
 * Stores an SBOM document for a project. Returns { projectId, sbomId, componentCount }.
 * `meta` = { project, version, ref, commit, repository }; project/version fall back to the SBOM subject.
 */
export function ingestSbom(db, document, meta = {}, { historyLimit = 20, rawText } = {}) {
  const parsed = parseSbom(document);
  const projectName = (meta.project || parsed.subject?.name || '').trim();
  if (!projectName) {
    const err = new Error('Project name is required (pass "project" or include a subject component in the SBOM)');
    err.status = 400;
    throw err;
  }
  const now = new Date().toISOString();
  const raw = zlib.gzipSync(rawText ?? JSON.stringify(document));

  return transaction(db, () => {
    db.prepare(
      `INSERT INTO projects (name, repository, created_at, updated_at) VALUES (?, ?, ?, ?)
       ON CONFLICT(name) DO UPDATE SET repository = COALESCE(excluded.repository, projects.repository), updated_at = excluded.updated_at`,
    ).run(projectName, meta.repository || null, now, now);
    const project = db.prepare('SELECT id FROM projects WHERE name = ?').get(projectName);

    const sbomId = Number(
      db
        .prepare(
          `INSERT INTO sboms (project_id, version, ref, commit_sha, format, spec_version, component_count, uploaded_at, raw)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
        )
        .run(
          project.id,
          meta.version || parsed.subject?.version || null,
          meta.ref || null,
          meta.commit || null,
          parsed.format,
          parsed.specVersion,
          parsed.components.length,
          now,
          raw,
        ).lastInsertRowid,
    );

    const insertComponent = db.prepare(
      `INSERT INTO components (sbom_id, name, version, purl, ecosystem, package_key, type, licenses, supplier)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
    );
    const insertPackage = db.prepare(
      'INSERT OR IGNORE INTO packages (key, ecosystem, namespace, name) VALUES (?, ?, ?, ?)',
    );
    const insertVersion = db.prepare('INSERT OR IGNORE INTO package_versions (package_key, version) VALUES (?, ?)');

    for (const c of parsed.components) {
      insertComponent.run(sbomId, c.name, c.version, c.purl, c.ecosystem, c.packageKey, c.type, c.licenses, c.supplier);
      if (c.packageKey) {
        const p = parsePurl(c.purl);
        insertPackage.run(c.packageKey, p.type, p.namespace, p.name);
        if (c.version) insertVersion.run(c.packageKey, c.version);
      }
    }

    db.prepare('UPDATE projects SET latest_sbom_id = ? WHERE id = ?').run(sbomId, project.id);
    pruneHistory(db, project.id, historyLimit);
    return { projectId: project.id, projectName, sbomId, componentCount: parsed.components.length };
  });
}

function pruneHistory(db, projectId, limit) {
  db.prepare(
    `DELETE FROM sboms WHERE project_id = ? AND id NOT IN (
       SELECT id FROM sboms WHERE project_id = ? ORDER BY uploaded_at DESC, id DESC LIMIT ?)`,
  ).run(projectId, projectId, limit);
}

// Removes packages and versions no longer referenced by any stored SBOM.
export function garbageCollect(db) {
  db.exec(`
    DELETE FROM package_versions WHERE NOT EXISTS (
      SELECT 1 FROM components c WHERE c.package_key = package_versions.package_key AND c.version = package_versions.version);
    DELETE FROM packages WHERE NOT EXISTS (SELECT 1 FROM components c WHERE c.package_key = packages.key);
    DELETE FROM vulnerabilities WHERE NOT EXISTS (SELECT 1 FROM version_vulns vv WHERE vv.vuln_id = vulnerabilities.id);
  `);
}
