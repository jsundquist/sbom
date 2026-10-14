// Read model: joins components with vulnerability and latest-version data.
import { OSV_TYPES } from './enrich/osv.js';
import { depsDevSystem } from './enrich/depsdev.js';
import { compareVersions, updateType } from './lib/version.js';
import { SEVERITY_RANK, maxSeverity } from './lib/severity.js';

const SEVERITIES = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'UNKNOWN'];

export function emptySeverityCounts() {
  return Object.fromEntries(SEVERITIES.map((s) => [s, 0]));
}

function cveOf(id, aliases) {
  if (id.startsWith('CVE-')) return id;
  return aliases.find((a) => a.startsWith('CVE-')) || null;
}

function vulnFromRow(r) {
  const aliases = JSON.parse(r.aliases || '[]');
  return {
    id: r.id,
    cve: cveOf(r.id, aliases),
    aliases,
    summary: r.summary,
    severity: r.severity,
    score: r.score,
    published: r.published,
  };
}

/**
 * Loads enriched components for the given SBOM ids (defaults to every project's latest SBOM).
 */
export function loadComponents(db, sbomIds) {
  const ids = sbomIds ?? db.prepare('SELECT latest_sbom_id AS id FROM projects WHERE latest_sbom_id IS NOT NULL').all().map((r) => r.id);
  if (!ids.length) return [];
  const placeholders = ids.map(() => '?').join(',');
  const rows = db
    .prepare(
      `SELECT c.id, c.sbom_id, s.project_id, pr.name AS project_name, c.name, c.version, c.purl, c.ecosystem,
              c.package_key, c.type, c.licenses, c.supplier,
              p.latest_version, p.latest_checked_at, pv.vulns_checked_at
       FROM components c
       JOIN sboms s ON s.id = c.sbom_id
       JOIN projects pr ON pr.id = s.project_id
       LEFT JOIN packages p ON p.key = c.package_key
       LEFT JOIN package_versions pv ON pv.package_key = c.package_key AND pv.version = c.version
       WHERE c.sbom_id IN (${placeholders})`,
    )
    .all(...ids);

  const vulnRows = db
    .prepare(
      `SELECT DISTINCT vv.package_key, vv.version, vv.fixed_versions, v.*
       FROM version_vulns vv
       JOIN vulnerabilities v ON v.id = vv.vuln_id
       JOIN components c ON c.package_key = vv.package_key AND c.version = vv.version
       WHERE c.sbom_id IN (${placeholders})`,
    )
    .all(...ids);
  const vulnsByVersion = new Map();
  for (const r of vulnRows) {
    const key = `${r.package_key}@${r.version}`;
    if (!vulnsByVersion.has(key)) vulnsByVersion.set(key, []);
    vulnsByVersion.get(key).push({ ...vulnFromRow(r), fixedVersions: JSON.parse(r.fixed_versions || '[]') });
  }

  return rows.map((r) => {
    const vulns = (vulnsByVersion.get(`${r.package_key}@${r.version}`) || []).sort(
      (a, b) => SEVERITY_RANK[b.severity] - SEVERITY_RANK[a.severity] || (b.score ?? 0) - (a.score ?? 0),
    );
    const scannable = r.ecosystem && OSV_TYPES.has(r.ecosystem) && r.version;
    return {
      id: r.id,
      sbomId: r.sbom_id,
      projectId: r.project_id,
      projectName: r.project_name,
      name: r.name,
      version: r.version,
      purl: r.purl,
      ecosystem: r.ecosystem,
      packageKey: r.package_key,
      type: r.type,
      licenses: r.licenses,
      supplier: r.supplier,
      latestVersion: r.latest_version,
      outdated: updateType(r.version, r.latest_version),
      vulns,
      maxSeverity: maxSeverity(vulns.map((v) => v.severity)),
      fixVersion: recommendedFix(r.version, vulns),
      vulnStatus: !scannable ? 'unsupported' : r.vulns_checked_at ? 'scanned' : 'pending',
      versionStatus: !r.ecosystem || !depsDevSystem(r.ecosystem) ? 'unsupported' : r.latest_checked_at ? 'checked' : 'pending',
    };
  });
}

// Smallest version that fixes every known vulnerability (when one can be determined).
function recommendedFix(current, vulns) {
  if (!vulns.length || !current) return null;
  let target = null;
  for (const v of vulns) {
    const candidate = v.fixedVersions.find((f) => compareVersions(f, current) > 0);
    if (!candidate) continue;
    if (!target || compareVersions(candidate, target) > 0) target = candidate;
  }
  return target;
}

export function summarize(components) {
  const severity = emptySeverityCounts();
  const vulnIds = new Set();
  const outdated = { major: 0, minor: 0, patch: 0 };
  let vulnerableComponents = 0;
  let outdatedComponents = 0;
  for (const c of components) {
    if (c.vulns.length) vulnerableComponents++;
    for (const v of c.vulns) {
      if (!vulnIds.has(v.id)) severity[v.severity]++;
      vulnIds.add(v.id);
    }
    if (c.outdated) {
      outdated[c.outdated]++;
      outdatedComponents++;
    }
  }
  return {
    components: components.length,
    vulnerableComponents,
    outdatedComponents,
    vulnerabilities: vulnIds.size,
    severity,
    outdated,
    pending: components.filter((c) => c.vulnStatus === 'pending' || c.versionStatus === 'pending').length,
  };
}

export function listProjects(db) {
  const projects = db
    .prepare(
      `SELECT p.id, p.name, p.repository, p.created_at, p.updated_at, s.id AS sbom_id, s.version, s.ref, s.commit_sha,
              s.format, s.spec_version, s.uploaded_at, s.component_count,
              (SELECT COUNT(*) FROM sboms x WHERE x.project_id = p.id) AS upload_count
       FROM projects p LEFT JOIN sboms s ON s.id = p.latest_sbom_id
       ORDER BY p.name COLLATE NOCASE`,
    )
    .all();
  const components = loadComponents(db);
  const bySbom = Map.groupBy(components, (c) => c.sbomId);
  return projects.map((p) => ({ ...projectInfo(p), stats: summarize(bySbom.get(p.sbom_id) || []) }));
}

function projectInfo(p) {
  return {
    id: p.id,
    name: p.name,
    repository: p.repository,
    createdAt: p.created_at,
    updatedAt: p.updated_at,
    uploadCount: p.upload_count,
    latest: p.sbom_id
      ? {
          id: p.sbom_id,
          version: p.version,
          ref: p.ref,
          commit: p.commit_sha,
          format: p.format,
          specVersion: p.spec_version,
          uploadedAt: p.uploaded_at,
          componentCount: p.component_count,
        }
      : null,
  };
}

export function getProject(db, idOrName) {
  const p = db
    .prepare(
      `SELECT p.id, p.name, p.repository, p.created_at, p.updated_at, s.id AS sbom_id, s.version, s.ref, s.commit_sha,
              s.format, s.spec_version, s.uploaded_at, s.component_count,
              (SELECT COUNT(*) FROM sboms x WHERE x.project_id = p.id) AS upload_count
       FROM projects p LEFT JOIN sboms s ON s.id = p.latest_sbom_id
       WHERE p.id = ? OR p.name = ?`,
    )
    .get(Number(idOrName) || -1, String(idOrName));
  if (!p) return null;
  const history = db
    .prepare(
      `SELECT id, version, ref, commit_sha AS "commit", format, spec_version AS specVersion, component_count AS componentCount,
              uploaded_at AS uploadedAt
       FROM sboms WHERE project_id = ? ORDER BY uploaded_at DESC, id DESC`,
    )
    .all(p.id);
  return { ...projectInfo(p), history };
}

// Aggregates components across projects into one row per package.
export function listPackages(components) {
  const map = new Map();
  for (const c of components) {
    const key = c.packageKey || `name:${c.name}`;
    let pkg = map.get(key);
    if (!pkg) {
      pkg = {
        key,
        name: c.name,
        ecosystem: c.ecosystem,
        latestVersion: c.latestVersion,
        versions: new Map(),
        projects: new Set(),
        vulnIds: new Set(),
        severity: null,
        outdated: null,
        licenses: new Set(),
      };
      map.set(key, pkg);
    }
    pkg.projects.add(c.projectId);
    if (c.licenses) pkg.licenses.add(c.licenses);
    const ver = c.version || '(unknown)';
    if (!pkg.versions.has(ver)) {
      pkg.versions.set(ver, { version: c.version, outdated: c.outdated, vulnCount: c.vulns.length, maxSeverity: c.maxSeverity, fixVersion: c.fixVersion, projects: [] });
    }
    pkg.versions.get(ver).projects.push({ id: c.projectId, name: c.projectName });
    for (const v of c.vulns) pkg.vulnIds.add(v.id);
    pkg.severity = maxSeverity([pkg.severity, c.maxSeverity].filter(Boolean));
    if (c.outdated && (!pkg.outdated || ['patch', 'minor', 'major'].indexOf(c.outdated) > ['patch', 'minor', 'major'].indexOf(pkg.outdated))) {
      pkg.outdated = c.outdated;
    }
  }
  return [...map.values()]
    .map((p) => ({
      key: p.key,
      name: p.name,
      ecosystem: p.ecosystem,
      latestVersion: p.latestVersion,
      versions: [...p.versions.values()].sort((a, b) => compareVersions(b.version, a.version)),
      projectCount: p.projects.size,
      vulnCount: p.vulnIds.size,
      maxSeverity: p.severity,
      outdated: p.outdated,
      licenses: [...p.licenses],
    }))
    .sort((a, b) => a.name.localeCompare(b.name));
}

// One row per vulnerability with the affected packages and projects.
export function listVulnerabilities(components) {
  const map = new Map();
  for (const c of components) {
    for (const v of c.vulns) {
      let row = map.get(v.id);
      if (!row) {
        row = { ...v, fixedVersions: undefined, affected: new Map(), projects: new Map() };
        map.set(v.id, row);
      }
      const akey = `${c.packageKey}@${c.version}`;
      if (!row.affected.has(akey)) {
        row.affected.set(akey, { packageKey: c.packageKey, name: c.name, ecosystem: c.ecosystem, version: c.version, fixedVersions: v.fixedVersions, fixVersion: c.fixVersion });
      }
      row.projects.set(c.projectId, { id: c.projectId, name: c.projectName });
    }
  }
  return [...map.values()]
    .map(({ fixedVersions, ...v }) => ({ ...v, affected: [...v.affected.values()], projects: [...v.projects.values()] }))
    .sort((a, b) => SEVERITY_RANK[b.severity] - SEVERITY_RANK[a.severity] || (b.score ?? 0) - (a.score ?? 0) || a.id.localeCompare(b.id));
}

export function getVulnerability(db, id) {
  const r = db.prepare('SELECT * FROM vulnerabilities WHERE id = ?').get(id);
  if (!r) return null;
  return { ...vulnFromRow(r), details: r.details, vector: r.vector, modified: r.modified, references: JSON.parse(r.refs || '[]') };
}
