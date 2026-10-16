// Read model: joins SBOM components with vulnerability and latest-version data.
import { and, count, desc, eq, inArray, isNotNull, sql } from 'drizzle-orm';
import type { Db } from '@/db';
import {
  componentEdges,
  components,
  epssScores,
  kevEntries,
  packages,
  packageVersions,
  projects,
  sboms,
  versionVulnerabilities,
  vulnerabilities,
} from '@/db/schema';
import { OSV_TYPES } from '@/worker/osv';
import { depsDevSystem } from '@/worker/depsdev';
import { compareVersions, UPDATE_RANK, updateType, type UpdateType } from '@/lib/version';
import { comparePriority } from '@/lib/priority';
import { maxSeverity, SEVERITIES, SEVERITY_RANK, type Severity } from '@/lib/severity';

/** CISA Known Exploited Vulnerabilities entry for a vulnerability. */
export interface KevInfo {
  dateAdded: string;
  dueDate: string | null;
  ransomware: boolean;
}

/** FIRST EPSS: probability (0..1) of exploitation activity in the next 30 days, and its percentile among all CVEs. */
export interface EpssInfo {
  score: number;
  percentile: number;
}

export interface ComponentVuln {
  id: string;
  cve: string | null;
  aliases: string[];
  summary: string | null;
  severity: Severity;
  score: number | null;
  published: string | null;
  fixedVersions: string[];
  /** Set when the vulnerability (or one of its CVE aliases) is in the CISA KEV catalog. */
  kev: KevInfo | null;
  /** Highest EPSS among the vulnerability's CVE ids; null when unscored. */
  epss: EpssInfo | null;
}

export interface InventoryComponent {
  id: number;
  sbomId: number;
  projectId: number;
  projectName: string;
  name: string;
  version: string | null;
  purl: string | null;
  ecosystem: string | null;
  packageKey: string | null;
  type: string | null;
  licenses: string | null;
  latestVersion: string | null;
  outdated: UpdateType | null;
  vulns: ComponentVuln[];
  maxSeverity: Severity | null;
  fixVersion: string | null;
  vulnStatus: 'scanned' | 'pending' | 'unsupported';
  versionStatus: 'checked' | 'pending' | 'unsupported';
}

export type SeverityCounts = Record<Severity, number>;

export interface Stats {
  components: number;
  vulnerableComponents: number;
  outdatedComponents: number;
  vulnerabilities: number;
  /** Distinct vulnerabilities known to be exploited (CISA KEV). */
  exploited: number;
  severity: SeverityCounts;
  outdated: Record<UpdateType, number>;
  pending: number;
}

const iso = (d: Date | null | undefined) => (d ? d.toISOString() : null);

export function cveOf(id: string, aliases: string[]): string | null {
  return id.startsWith('CVE-') ? id : (aliases.find((a) => a.startsWith('CVE-')) ?? null);
}

const cveIds = (id: string, aliases: string[]) => [id, ...aliases].filter((x) => x.startsWith('CVE-'));

/** KEV entries for the CVE ids of the given vulnerabilities, keyed by CVE id. */
export async function loadKev(db: Db, vulns: { id: string; aliases: string[] }[]): Promise<Map<string, KevInfo>> {
  const ids = [...new Set(vulns.flatMap((v) => cveIds(v.id, v.aliases)))];
  if (!ids.length) {
    return new Map();
  }
  const rows = await db.select().from(kevEntries).where(inArray(kevEntries.cveId, ids));
  return new Map(rows.map((r) => [r.cveId, { dateAdded: r.dateAdded, dueDate: r.dueDate, ransomware: r.knownRansomwareUse }]));
}

export function kevFor(kev: Map<string, KevInfo>, id: string, aliases: string[]): KevInfo | null {
  for (const cve of cveIds(id, aliases)) {
    const hit = kev.get(cve);
    if (hit) {
      return hit;
    }
  }
  return null;
}

/** EPSS scores for the CVE ids of the given vulnerabilities, keyed by CVE id. */
export async function loadEpss(db: Db, vulns: { id: string; aliases: string[] }[]): Promise<Map<string, EpssInfo>> {
  const ids = [...new Set(vulns.flatMap((v) => cveIds(v.id, v.aliases)))];
  if (!ids.length) {
    return new Map();
  }
  const rows = await db.select().from(epssScores).where(inArray(epssScores.cveId, ids));
  return new Map(rows.flatMap((r) => (r.score === null ? [] : [[r.cveId, { score: r.score, percentile: r.percentile ?? 0 }] as const])));
}

export function epssFor(epss: Map<string, EpssInfo>, id: string, aliases: string[]): EpssInfo | null {
  let best: EpssInfo | null = null;
  for (const cve of cveIds(id, aliases)) {
    const hit = epss.get(cve);
    if (hit && (!best || hit.score > best.score)) {
      best = hit;
    }
  }
  return best;
}

/** Package identity used for grouping; falls back to the name when there is no purl. */
export const groupKey = (c: Pick<InventoryComponent, 'packageKey' | 'name'>) => c.packageKey ?? `name:${c.name}`;

async function latestSbomIds(db: Db): Promise<number[]> {
  const rows = await db.select({ id: projects.latestSbomId }).from(projects).where(isNotNull(projects.latestSbomId));
  return rows.map((r) => r.id!);
}

/** Enriched components for the given SBOMs (defaults to every project's latest SBOM). */
export async function loadComponents(db: Db, sbomIds?: number[]): Promise<InventoryComponent[]> {
  const ids = sbomIds ?? (await latestSbomIds(db));
  if (!ids.length) {
    return [];
  }

  const rows = await db
    .select({
      id: components.id,
      sbomId: components.sbomId,
      projectId: projects.id,
      projectName: projects.name,
      name: components.name,
      version: components.version,
      purl: components.purl,
      ecosystem: components.ecosystem,
      packageKey: components.packageKey,
      type: components.type,
      licenses: components.licenses,
      latestVersion: packages.latestVersion,
      latestCheckedAt: packages.latestCheckedAt,
      vulnsCheckedAt: packageVersions.vulnsCheckedAt,
    })
    .from(components)
    .innerJoin(sboms, eq(sboms.id, components.sbomId))
    .innerJoin(projects, eq(projects.id, sboms.projectId))
    .leftJoin(packages, eq(packages.key, components.packageKey))
    .leftJoin(packageVersions, and(eq(packageVersions.packageKey, components.packageKey), eq(packageVersions.version, components.version)))
    .where(inArray(components.sbomId, ids));

  const vulnRows = await db
    .selectDistinct({
      packageKey: versionVulnerabilities.packageKey,
      version: versionVulnerabilities.version,
      fixedVersions: versionVulnerabilities.fixedVersions,
      id: vulnerabilities.id,
      aliases: vulnerabilities.aliases,
      summary: vulnerabilities.summary,
      severity: vulnerabilities.severity,
      score: vulnerabilities.score,
      published: vulnerabilities.published,
    })
    .from(versionVulnerabilities)
    .innerJoin(vulnerabilities, eq(vulnerabilities.id, versionVulnerabilities.vulnerabilityId))
    .innerJoin(
      components,
      and(eq(components.packageKey, versionVulnerabilities.packageKey), eq(components.version, versionVulnerabilities.version)),
    )
    .where(inArray(components.sbomId, ids));

  const kev = await loadKev(db, vulnRows);
  const epss = await loadEpss(db, vulnRows);
  const vulnsByVersion = new Map<string, ComponentVuln[]>();
  for (const r of vulnRows) {
    const key = `${r.packageKey}@${r.version}`;
    const list = vulnsByVersion.get(key) ?? [];
    list.push({
      id: r.id,
      cve: cveOf(r.id, r.aliases),
      aliases: r.aliases,
      summary: r.summary,
      severity: r.severity,
      score: r.score,
      published: iso(r.published),
      fixedVersions: r.fixedVersions,
      kev: kevFor(kev, r.id, r.aliases),
      epss: epssFor(epss, r.id, r.aliases),
    });
    vulnsByVersion.set(key, list);
  }

  return rows.map((r) => {
    const vulns = (vulnsByVersion.get(`${r.packageKey}@${r.version}`) ?? []).sort(
      (a, b) => SEVERITY_RANK[b.severity] - SEVERITY_RANK[a.severity] || (b.score ?? 0) - (a.score ?? 0),
    );
    const scannable = !!(r.ecosystem && OSV_TYPES.has(r.ecosystem) && r.version);
    const versionCheckable = !!(r.ecosystem && depsDevSystem(r.ecosystem));
    return {
      id: r.id,
      sbomId: r.sbomId,
      projectId: r.projectId,
      projectName: r.projectName,
      name: r.name,
      version: r.version,
      purl: r.purl,
      ecosystem: r.ecosystem,
      packageKey: r.packageKey,
      type: r.type,
      licenses: r.licenses,
      latestVersion: r.latestVersion,
      outdated: updateType(r.version, r.latestVersion),
      vulns,
      maxSeverity: maxSeverity(vulns.map((v) => v.severity)),
      fixVersion: recommendedFix(r.version, vulns),
      vulnStatus: !scannable ? 'unsupported' : r.vulnsCheckedAt ? 'scanned' : 'pending',
      versionStatus: !versionCheckable ? 'unsupported' : r.latestCheckedAt ? 'checked' : 'pending',
    };
  });
}

/** Smallest version that fixes every known vulnerability, when one can be determined. */
function recommendedFix(current: string | null, vulns: ComponentVuln[]): string | null {
  if (!current || !vulns.length) {
    return null;
  }
  let target: string | null = null;
  for (const v of vulns) {
    const candidate = v.fixedVersions.find((f) => compareVersions(f, current) > 0);
    if (candidate && (!target || compareVersions(candidate, target) > 0)) {
      target = candidate;
    }
  }
  return target;
}

export function emptySeverityCounts(): SeverityCounts {
  return Object.fromEntries(SEVERITIES.map((s) => [s, 0])) as SeverityCounts;
}

export function summarize(list: InventoryComponent[]): Stats {
  const severity = emptySeverityCounts();
  const seen = new Set<string>();
  const exploited = new Set<string>();
  const outdated: Record<UpdateType, number> = { major: 0, minor: 0, patch: 0 };
  let vulnerableComponents = 0;
  let pending = 0;
  for (const c of list) {
    if (c.vulns.length) {
      vulnerableComponents++;
    }
    for (const v of c.vulns) {
      if (!seen.has(v.id)) {
        severity[v.severity]++;
      }
      seen.add(v.id);
      if (v.kev) {
        exploited.add(v.id);
      }
    }
    if (c.outdated) {
      outdated[c.outdated]++;
    }
    if (c.vulnStatus === 'pending' || c.versionStatus === 'pending') {
      pending++;
    }
  }
  return {
    components: list.length,
    vulnerableComponents,
    outdatedComponents: outdated.major + outdated.minor + outdated.patch,
    vulnerabilities: seen.size,
    exploited: exploited.size,
    severity,
    outdated,
    pending,
  };
}

export interface SbomInfo {
  id: number;
  version: string | null;
  ref: string | null;
  commit: string | null;
  format: string;
  specVersion: string | null;
  componentCount: number;
  uploadedAt: string;
}

export interface ProjectSummary {
  id: number;
  name: string;
  repository: string | null;
  createdAt: string;
  updatedAt: string;
  uploadCount: number;
  latest: SbomInfo | null;
  stats: Stats;
}

const sbomColumns = {
  id: sboms.id,
  version: sboms.version,
  ref: sboms.ref,
  commit: sboms.commitSha,
  format: sboms.format,
  specVersion: sboms.specVersion,
  componentCount: sboms.componentCount,
  uploadedAt: sboms.uploadedAt,
};

const toSbomInfo = (s: { id: number | null; uploadedAt: Date | null } & Omit<SbomInfo, 'id' | 'uploadedAt'>): SbomInfo | null =>
  s.id ? { ...s, id: s.id, uploadedAt: iso(s.uploadedAt)! } : null;

async function projectRows(db: Db, filter?: ReturnType<typeof eq>) {
  const uploads = db
    .select({ projectId: sboms.projectId, n: count().as('n') })
    .from(sboms)
    .groupBy(sboms.projectId)
    .as('uploads');
  return db
    .select({
      id: projects.id,
      name: projects.name,
      repository: projects.repository,
      createdAt: projects.createdAt,
      updatedAt: projects.updatedAt,
      uploadCount: sql<number>`coalesce(${uploads.n}, 0)`.mapWith(Number),
      sbom: {
        id: sboms.id,
        version: sboms.version,
        ref: sboms.ref,
        commit: sboms.commitSha,
        format: sboms.format,
        specVersion: sboms.specVersion,
        componentCount: sboms.componentCount,
        uploadedAt: sboms.uploadedAt,
      },
    })
    .from(projects)
    .leftJoin(sboms, eq(sboms.id, projects.latestSbomId))
    .leftJoin(uploads, eq(uploads.projectId, projects.id))
    .where(filter)
    .orderBy(sql`lower(${projects.name})`);
}

function toProject(r: Awaited<ReturnType<typeof projectRows>>[number], stats: Stats): ProjectSummary {
  return {
    id: r.id,
    name: r.name,
    repository: r.repository,
    createdAt: iso(r.createdAt)!,
    updatedAt: iso(r.updatedAt)!,
    uploadCount: r.uploadCount,
    latest: r.sbom ? toSbomInfo(r.sbom as Parameters<typeof toSbomInfo>[0]) : null,
    stats,
  };
}

export async function listProjects(db: Db): Promise<ProjectSummary[]> {
  return listProjectsFrom(db, await loadComponents(db));
}

export interface ProjectDetail extends ProjectSummary {
  history: SbomInfo[];
  sbomId: number | null;
  components: InventoryComponent[];
}

/** A project with the components of its latest SBOM (or of `sbomId` from its history). */
export async function getProject(db: Db, id: number, sbomId?: number): Promise<ProjectDetail | null> {
  const [row] = await projectRows(db, eq(projects.id, id));
  if (!row) {
    return null;
  }
  const history = await db.select(sbomColumns).from(sboms).where(eq(sboms.projectId, id)).orderBy(desc(sboms.uploadedAt), desc(sboms.id));
  const selected = sbomId ?? row.sbom?.id ?? null;
  if (selected && !history.some((h) => h.id === selected)) {
    return null;
  }
  const list = selected ? await loadComponents(db, [selected]) : [];
  return {
    ...toProject(row, summarize(list)),
    history: history.map((h) => toSbomInfo(h)!),
    sbomId: selected,
    components: list,
  };
}

export interface DependencyGraph {
  sbomId: number;
  /** Components of the SBOM with their vulnerabilities. */
  components: InventoryComponent[];
  /** `parentId` depends on `childId` (component ids). */
  edges: { parentId: number; childId: number }[];
  /** Components the application depends on directly, or null when the SBOM does not say. */
  directIds: number[] | null;
}

/** The dependency graph of a project's latest SBOM (or `sbomId`); null when the project or SBOM does not exist. */
export async function getDependencyGraph(db: Db, projectId: number, sbomId?: number): Promise<DependencyGraph | null> {
  const [project] = await db.select({ latestSbomId: projects.latestSbomId }).from(projects).where(eq(projects.id, projectId));
  if (!project) {
    return null;
  }
  const selected = sbomId ?? project.latestSbomId;
  if (!selected) {
    return null;
  }
  const [owned] = await db
    .select({ id: sboms.id })
    .from(sboms)
    .where(and(eq(sboms.id, selected), eq(sboms.projectId, projectId)));
  if (!owned) {
    return null;
  }
  const [list, rows] = await Promise.all([
    loadComponents(db, [selected]),
    db
      .select({ parentId: componentEdges.parentId, childId: componentEdges.childId })
      .from(componentEdges)
      .where(eq(componentEdges.sbomId, selected)),
  ]);
  const direct = rows.filter((r) => r.parentId === null).map((r) => r.childId);
  return {
    sbomId: selected,
    components: list,
    edges: rows.flatMap((r) => (r.parentId === null ? [] : [{ parentId: r.parentId, childId: r.childId }])),
    directIds: direct.length ? direct : null,
  };
}

export interface PackageVersionUsage {
  version: string | null;
  outdated: UpdateType | null;
  vulnCount: number;
  maxSeverity: Severity | null;
  fixVersion: string | null;
  projects: { id: number; name: string }[];
}

export interface PackageSummary {
  key: string;
  name: string;
  ecosystem: string | null;
  purl: string | null;
  latestVersion: string | null;
  versions: PackageVersionUsage[];
  projectCount: number;
  vulnCount: number;
  maxSeverity: Severity | null;
  outdated: UpdateType | null;
  licenses: string[];
}

/** One row per package across projects. */
export function aggregatePackages(list: InventoryComponent[]): PackageSummary[] {
  const map = new Map<
    string,
    Omit<PackageSummary, 'versions' | 'projectCount' | 'vulnCount' | 'licenses'> & {
      versions: Map<string, PackageVersionUsage>;
      projects: Set<number>;
      vulnIds: Set<string>;
      licenses: Set<string>;
    }
  >();
  for (const c of list) {
    const key = groupKey(c);
    let pkg = map.get(key);
    if (!pkg) {
      pkg = {
        key,
        name: c.name,
        ecosystem: c.ecosystem,
        purl: c.purl?.split('@')[0] ?? null,
        latestVersion: c.latestVersion,
        versions: new Map(),
        projects: new Set(),
        vulnIds: new Set(),
        maxSeverity: null,
        outdated: null,
        licenses: new Set(),
      };
      map.set(key, pkg);
    }
    pkg.projects.add(c.projectId);
    if (c.licenses) {
      pkg.licenses.add(c.licenses);
    }
    const vkey = c.version ?? '';
    let usage = pkg.versions.get(vkey);
    if (!usage) {
      usage = {
        version: c.version,
        outdated: c.outdated,
        vulnCount: c.vulns.length,
        maxSeverity: c.maxSeverity,
        fixVersion: c.fixVersion,
        projects: [],
      };
      pkg.versions.set(vkey, usage);
    }
    if (!usage.projects.some((p) => p.id === c.projectId)) {
      usage.projects.push({ id: c.projectId, name: c.projectName });
    }
    for (const v of c.vulns) {
      pkg.vulnIds.add(v.id);
    }
    pkg.maxSeverity = maxSeverity([pkg.maxSeverity, c.maxSeverity]);
    if (c.outdated && (!pkg.outdated || UPDATE_RANK[c.outdated] > UPDATE_RANK[pkg.outdated])) {
      pkg.outdated = c.outdated;
    }
  }
  return [...map.values()]
    .map(({ versions, projects: p, vulnIds, licenses, ...rest }) => ({
      ...rest,
      versions: [...versions.values()].sort((a, b) => compareVersions(b.version, a.version)),
      projectCount: p.size,
      vulnCount: vulnIds.size,
      licenses: [...licenses],
    }))
    .sort((a, b) => a.name.localeCompare(b.name));
}

export interface AffectedPackage {
  packageKey: string;
  name: string;
  ecosystem: string | null;
  version: string | null;
  fixedVersions: string[];
  fixVersion: string | null;
}

export interface VulnerabilitySummary extends Omit<ComponentVuln, 'fixedVersions'> {
  /** 1-based position in the fix-first order (known exploited, then EPSS, then severity). */
  rank: number;
  affected: AffectedPackage[];
  projects: { id: number; name: string }[];
}

/** One row per vulnerability with the affected packages and projects. */
export function aggregateVulnerabilities(list: InventoryComponent[]): VulnerabilitySummary[] {
  const map = new Map<
    string,
    Omit<VulnerabilitySummary, 'affected' | 'projects' | 'rank'> & {
      affected: Map<string, AffectedPackage>;
      projects: Map<number, { id: number; name: string }>;
    }
  >();
  for (const c of list) {
    for (const { fixedVersions, ...v } of c.vulns) {
      let row = map.get(v.id);
      if (!row) {
        row = { ...v, affected: new Map(), projects: new Map() };
        map.set(v.id, row);
      }
      const key = `${groupKey(c)}@${c.version}`;
      if (!row.affected.has(key)) {
        row.affected.set(key, {
          packageKey: groupKey(c),
          name: c.name,
          ecosystem: c.ecosystem,
          version: c.version,
          fixedVersions,
          fixVersion: fixedVersions.find((f) => compareVersions(f, c.version) > 0) ?? null,
        });
      }
      row.projects.set(c.projectId, { id: c.projectId, name: c.projectName });
    }
  }
  return [...map.values()]
    .map((v) => ({ ...v, affected: [...v.affected.values()], projects: [...v.projects.values()] }))
    .sort((a, b) => comparePriority(a, b) || a.id.localeCompare(b.id))
    .map((v, i) => ({ ...v, rank: i + 1 }));
}

export async function listPackages(db: Db) {
  return aggregatePackages(await loadComponents(db));
}

export async function getPackage(db: Db, key: string) {
  const list = (await loadComponents(db)).filter((c) => groupKey(c) === key);
  if (!list.length) {
    return null;
  }
  const [pkg] = aggregatePackages(list);
  return { ...pkg, vulnerabilities: aggregateVulnerabilities(list) };
}

export async function listVulnerabilities(db: Db) {
  return aggregateVulnerabilities(await loadComponents(db));
}

export interface VulnerabilityDetail extends Omit<VulnerabilitySummary, 'rank'> {
  details: string | null;
  vector: string | null;
  modified: string | null;
  references: { type: string; url: string }[];
}

export async function getVulnerability(db: Db, id: string): Promise<VulnerabilityDetail | null> {
  const [v] = await db.select().from(vulnerabilities).where(eq(vulnerabilities.id, id));
  if (!v) {
    return null;
  }
  const kev = kevFor(await loadKev(db, [v]), v.id, v.aliases);
  const epss = epssFor(await loadEpss(db, [v]), v.id, v.aliases);
  const usage = (await listVulnerabilities(db)).find((u) => u.id === v.id);
  return {
    id: v.id,
    cve: cveOf(v.id, v.aliases),
    aliases: v.aliases,
    summary: v.summary,
    severity: v.severity,
    score: v.score,
    published: iso(v.published),
    kev,
    epss,
    details: v.details,
    vector: v.vector,
    modified: iso(v.modified),
    references: v.references,
    affected: usage?.affected ?? [],
    projects: usage?.projects ?? [],
  };
}

const FIX_FIRST_COUNT = 5;

export async function getOverview(db: Db) {
  const all = await loadComponents(db);
  const pkgs = aggregatePackages(all);
  const [projectList, recentUploads] = await Promise.all([
    listProjectsFrom(db, all),
    db
      .select({ ...sbomColumns, projectId: projects.id, projectName: projects.name })
      .from(sboms)
      .innerJoin(projects, eq(projects.id, sboms.projectId))
      .orderBy(desc(sboms.uploadedAt), desc(sboms.id))
      .limit(8),
  ]);
  return {
    projectCount: projectList.length,
    packageCount: pkgs.length,
    vulnerablePackages: pkgs.filter((p) => p.vulnCount).length,
    outdatedPackages: pkgs.filter((p) => p.outdated).length,
    stats: summarize(all),
    fixFirst: aggregateVulnerabilities(all).slice(0, FIX_FIRST_COUNT),
    projects: projectList,
    recentUploads: recentUploads.map((u) => ({ ...u, uploadedAt: iso(u.uploadedAt)! })),
  };
}

async function listProjectsFrom(db: Db, all: InventoryComponent[]) {
  const rows = await projectRows(db);
  const bySbom = Map.groupBy(all, (c) => c.sbomId);
  return rows.map((r) => toProject(r, summarize((r.sbom?.id && bySbom.get(r.sbom.id)) || [])));
}

export async function getSbomDocument(db: Db, id: number) {
  const [row] = await db
    .select({ document: sboms.document, version: sboms.version, projectName: projects.name })
    .from(sboms)
    .innerJoin(projects, eq(projects.id, sboms.projectId))
    .where(eq(sboms.id, id));
  return row ?? null;
}
