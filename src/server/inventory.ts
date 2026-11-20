// Read model: joins SBOM components with vulnerability and latest-version data.
import { and, count, desc, eq, exists, inArray, isNotNull, isNull, or, sql } from 'drizzle-orm';
import { legacyRepositoryForms, normalizeRepository } from '@/lib/repository';
import type { Db } from '@/db';
import {
  componentEdges,
  components,
  packages,
  packageVersions,
  projects,
  sboms,
  versionVulnerabilities,
  vulnerabilities,
} from '@/db/schema';
import { cveOf } from '@/lib/cve';
import { versionStatus, vulnStatus, type VersionStatus, type VulnStatus } from '@/lib/coverage';
import { compareVersions, isPrerelease, parseVersion, UPDATE_RANK, updateType, type UpdateType } from '@/lib/version';
import { comparePriority } from '@/lib/priority';
import { scorecardStatus, weakestChecks, type ScorecardCheck, type ScorecardStatus } from '@/lib/scorecard';
import { env } from '@/lib/env';
import { maintenanceFlags, type Maintenance } from '@/lib/maintenance';
import type { ProjectKind } from '@/lib/kinds';
import { isStale } from '@/lib/stale';
import type { OverviewFilter, PackageFilter, PageParams, ProjectFilter, VulnerabilityFilter } from '@/lib/params';
import {
  filterOverviewProjects,
  filterPackages,
  filterProjects,
  filterVulnerabilities,
  overviewFacets,
  paginate,
  type Page,
} from './list-filters';
import { loadExploitSignals, type ExploitSignals } from './exploit-signals';
import { maxSeverity, SEVERITIES, SEVERITY_RANK, type Severity } from '@/lib/severity';

export interface ComponentVuln extends ExploitSignals {
  id: string;
  cve: string | null;
  aliases: string[];
  summary: string | null;
  severity: Severity;
  score: number | null;
  published: string | null;
  fixedVersions: string[];
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
  maintenance: Maintenance;
  vulns: ComponentVuln[];
  maxSeverity: Severity | null;
  fixVersion: string | null;
  vulnStatus: VulnStatus;
  versionStatus: VersionStatus;
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

/** Package identity used for grouping; falls back to the name when there is no purl. */
const NAME_KEY_PREFIX = 'name:';
export const groupKey = (c: Pick<InventoryComponent, 'packageKey' | 'name'>) => c.packageKey ?? `${NAME_KEY_PREFIX}${c.name}`;

async function latestSbomIds(db: Db): Promise<number[]> {
  const rows = await db.select({ id: projects.latestSbomId }).from(projects).where(isNotNull(projects.latestSbomId));
  return rows.map((r) => r.id!);
}

/** What to load. SBOMs default to every project's latest; the other fields narrow that set in SQL. */
export interface ComponentScope {
  sbomIds?: number[];
  /** A `groupKey` value: a package key, or `name:<name>` for components without a purl. */
  packageKey?: string;
  /** Only components affected by this vulnerability (their other vulnerabilities are still loaded). */
  vulnerabilityId?: string;
}

/** Enriched components for the given scope (defaults to every project's latest SBOM). */
export async function loadComponents(db: Db, scope: ComponentScope = {}): Promise<InventoryComponent[]> {
  const ids = scope.sbomIds ?? (await latestSbomIds(db));
  if (!ids.length) {
    return [];
  }
  const { packageKey, vulnerabilityId } = scope;
  const inScope = and(
    inArray(components.sbomId, ids),
    packageKey === undefined
      ? undefined
      : packageKey.startsWith(NAME_KEY_PREFIX)
        ? and(isNull(components.packageKey), eq(components.name, packageKey.slice(NAME_KEY_PREFIX.length)))
        : eq(components.packageKey, packageKey),
    vulnerabilityId === undefined
      ? undefined
      : exists(
          db
            .select({ one: sql`1` })
            .from(versionVulnerabilities)
            .where(
              and(
                eq(versionVulnerabilities.packageKey, components.packageKey),
                eq(versionVulnerabilities.version, components.version),
                eq(versionVulnerabilities.vulnerabilityId, vulnerabilityId),
              ),
            ),
        ),
  );

  // What belongs to a package or to a package version rather than to one component (latest release, maintenance, scan state,
  // vulnerabilities) is loaded once from the small tables and joined here. Joining it to every component row repeated the same
  // values, and parsed the same timestamps, hundreds of thousands of times (F-004 benchmark, K-001).
  const rows = await db
    .select({
      id: components.id,
      sbomId: components.sbomId,
      name: components.name,
      version: components.version,
      purl: components.purl,
      ecosystem: components.ecosystem,
      packageKey: components.packageKey,
      type: components.type,
      licenses: components.licenses,
    })
    .from(components)
    .where(inScope);
  if (!rows.length) {
    return [];
  }

  const keys = [...new Set(rows.flatMap((r) => (r.packageKey ? [r.packageKey] : [])))];
  const [owners, packageRows, versionRows, vulnRows] = await Promise.all([
    db
      .select({ sbomId: sboms.id, projectId: projects.id, projectName: projects.name })
      .from(sboms)
      .innerJoin(projects, eq(projects.id, sboms.projectId))
      .where(inArray(sboms.id, ids)),
    inChunks(keys, (chunk) =>
      db
        .select({
          key: packages.key,
          latestVersion: packages.latestVersion,
          latestCheckedAt: packages.latestCheckedAt,
          latestReleasedAt: packages.latestReleasedAt,
          deprecated: packages.deprecated,
          deprecatedReason: packages.deprecatedReason,
        })
        .from(packages)
        .where(inArray(packages.key, chunk)),
    ),
    inChunks(keys, (chunk) =>
      db
        .select({
          packageKey: packageVersions.packageKey,
          version: packageVersions.version,
          vulnsCheckedAt: packageVersions.vulnsCheckedAt,
        })
        .from(packageVersions)
        .where(inArray(packageVersions.packageKey, chunk)),
    ),
    inChunks(keys, (chunk) =>
      db
        .select({
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
        .where(inArray(versionVulnerabilities.packageKey, chunk)),
    ),
  ]);

  // Only the versions that are actually in scope: the package-key lookup above also returns versions used by other SBOMs.
  const inUse = new Set(rows.map((r) => versionKey(r.packageKey, r.version)));
  const scopedVulnRows = vulnRows.filter((r) => inUse.has(versionKey(r.packageKey, r.version)));
  const signals = await loadExploitSignals(db, scopedVulnRows);
  const vulnsByVersion = new Map<string, ComponentVuln[]>();
  for (const r of scopedVulnRows) {
    const key = versionKey(r.packageKey, r.version);
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
      ...signals(r.id, r.aliases),
    });
    vulnsByVersion.set(key, list);
  }

  const now = new Date();
  const abandonedAfterYears = env().ABANDONED_AFTER_YEARS;
  const ownerOf = new Map(owners.map((o) => [o.sbomId, o]));
  const checkedAt = new Map(versionRows.map((v) => [versionKey(v.packageKey, v.version), v.vulnsCheckedAt]));
  const noPackage = {
    latestVersion: null,
    latestCheckedAt: null,
    maintenance: maintenanceFlags({ deprecated: false, reason: null, latestReleasedAt: null }, now, abandonedAfterYears),
  };
  const packageFacts = new Map(
    packageRows.map((p) => [
      p.key,
      {
        latestVersion: p.latestVersion,
        latestCheckedAt: p.latestCheckedAt,
        maintenance: maintenanceFlags(
          { deprecated: p.deprecated, reason: p.deprecatedReason, latestReleasedAt: p.latestReleasedAt },
          now,
          abandonedAfterYears,
        ),
      },
    ]),
  );

  // Everything below depends only on the package and its version, and a few thousand versions cover hundreds of thousands of
  // components, so it is worked out once per version and shared.
  const byVersion = new Map<string, VersionFacts>();
  const factsOf = (r: (typeof rows)[number]): VersionFacts => {
    const key = versionKey(r.packageKey, r.version);
    let facts = byVersion.get(key);
    if (!facts) {
      const pkg = (r.packageKey && packageFacts.get(r.packageKey)) || noPackage;
      const vulns = (vulnsByVersion.get(key) ?? []).sort(
        (a, b) => SEVERITY_RANK[b.severity] - SEVERITY_RANK[a.severity] || (b.score ?? 0) - (a.score ?? 0),
      );
      facts = {
        latestVersion: pkg.latestVersion,
        outdated: updateType(r.version, pkg.latestVersion),
        maintenance: pkg.maintenance,
        vulns,
        maxSeverity: maxSeverity(vulns.map((v) => v.severity)),
        fixVersion: recommendedFix(r.version, vulns),
        vulnStatus: vulnStatus(r.ecosystem, r.version, checkedAt.get(key) ?? null),
        versionStatus: versionStatus(r.ecosystem, pkg.latestCheckedAt),
      };
      byVersion.set(key, facts);
    }
    return facts;
  };

  return rows.map((r) => {
    const owner = ownerOf.get(r.sbomId)!;
    return { ...r, projectId: owner.projectId, projectName: owner.projectName, ...factsOf(r) };
  });
}

type VersionFacts = Pick<
  InventoryComponent,
  'latestVersion' | 'outdated' | 'maintenance' | 'vulns' | 'maxSeverity' | 'fixVersion' | 'vulnStatus' | 'versionStatus'
>;

/** Identifies one version of one package; components without a purl share the key with a null package. */
const versionKey = (packageKey: string | null, version: string | null) => `${packageKey}\u0000${version}`;

/** Runs `query` over `items` in blocks, so an IN list never nears the driver's 65,535 parameter limit. */
async function inChunks<T, R>(items: T[], query: (chunk: T[]) => Promise<R[]>, size = 5000): Promise<R[]> {
  const out: R[] = [];
  for (let i = 0; i < items.length; i += size) {
    out.push(...(await query(items.slice(i, i + size))));
  }
  return out;
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
  environment: string | null;
  format: string;
  specVersion: string | null;
  componentCount: number;
  uploadedAt: string;
}

export interface ProjectSummary {
  id: number;
  name: string;
  repository: string | null;
  kind: ProjectKind;
  tags: string[];
  createdAt: string;
  updatedAt: string;
  uploadCount: number;
  latest: SbomInfo | null;
  /** The latest SBOM is older than STALE_AFTER_DAYS; false for a project with no SBOM. */
  stale: boolean;
  stats: Stats;
}

const sbomColumns = {
  id: sboms.id,
  version: sboms.version,
  ref: sboms.ref,
  commit: sboms.commitSha,
  environment: sboms.environment,
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
      kind: projects.kind,
      tags: projects.tags,
      createdAt: projects.createdAt,
      updatedAt: projects.updatedAt,
      uploadCount: sql<number>`coalesce(${uploads.n}, 0)`.mapWith(Number),
      sbom: {
        id: sboms.id,
        version: sboms.version,
        ref: sboms.ref,
        commit: sboms.commitSha,
        environment: sboms.environment,
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
  const latest = r.sbom ? toSbomInfo(r.sbom as Parameters<typeof toSbomInfo>[0]) : null;
  return {
    id: r.id,
    name: r.name,
    repository: r.repository,
    kind: r.kind,
    tags: r.tags,
    createdAt: iso(r.createdAt)!,
    updatedAt: iso(r.updatedAt)!,
    uploadCount: r.uploadCount,
    latest,
    stale: isStale(latest?.uploadedAt, new Date(), env().STALE_AFTER_DAYS),
    stats,
  };
}

/** `repository` is already normalised (normalizeRepository); rows not yet re-uploaded may hold an older spelling, so those match too. */
export async function listProjects(db: Db, { repository }: { repository?: string } = {}): Promise<ProjectSummary[]> {
  if (!repository) {
    return listProjectsFrom(db, await loadComponents(db));
  }
  const forms = legacyRepositoryForms(repository);
  const rows = await projectRows(
    db,
    or(
      inArray(projects.repository, forms),
      inArray(
        sql`lower(${projects.repository})`,
        forms.map((f) => f.toLowerCase()),
      ),
    ),
  );
  const sbomIds = rows.flatMap((r) => (r.sbom?.id ? [r.sbom.id] : []));
  const all = sbomIds.length ? await loadComponents(db, { sbomIds }) : [];
  const bySbom = Map.groupBy(all, (c) => c.sbomId);
  return rows.map((r) => toProject(r, summarize((r.sbom?.id && bySbom.get(r.sbom.id)) || [])));
}

/** The other Projects built from the same repository (monorepo services), by name. Nothing for a Project with no usable repository. */
export async function getSiblingProjects(db: Db, projectId: number): Promise<ProjectSummary[]> {
  const [row] = await db.select({ repository: projects.repository }).from(projects).where(eq(projects.id, projectId));
  const repository = row?.repository ? normalizeRepository(row.repository) : null;
  if (!repository) {
    return [];
  }
  // Scoped to this repository's SBOMs, so it stays cheap at 100 Projects (ADR 0005).
  return (await listProjects(db, { repository })).filter((p) => p.id !== projectId);
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
  const list = selected ? await loadComponents(db, { sbomIds: [selected] }) : [];
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
    loadComponents(db, { sbomIds: [selected] }),
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
  maintenance: Maintenance;
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
        maintenance: c.maintenance,
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

export interface UpgradeTarget {
  version: string;
  /** Vulnerability ids this version clears. */
  clears: string[];
}

/** Risk retired by an upgrade, summed over the CVEs it clears; compared in this order (KEV, EPSS, severity, CVSS). */
export interface UpgradeRisk {
  kev: number;
  epss: number;
  severity: number;
  score: number;
}

export interface PackageRef {
  name: string;
  version: string | null;
}

export interface PackageUpgrade {
  /** 1-based position in the ranking by risk retired. */
  rank: number;
  packageKey: string;
  name: string;
  ecosystem: string | null;
  version: string | null;
  projects: { id: number; name: string }[];
  /** Every vulnerability id on this package version. */
  vulnerabilities: string[];
  /** Lowest fixed version in the current major that clears the most CVEs; null when no fix stays in the major. */
  sameMajor: UpgradeTarget | null;
  /** Lowest version that clears every CVE (may be a major bump); null when some CVE has no fixed version. */
  clearsAll: UpgradeTarget | null;
  /** Vulnerability ids the ranked target (`sameMajor`, else `clearsAll`) leaves behind. */
  remaining: string[];
  risk: UpgradeRisk;
  /** True when listed as a direct dependency, false when only reached through parents, null when the graph is silent. */
  direct: boolean | null;
  /** Packages that depend on this one. Upgrading this package is not claimed to drop a parent's need for it. */
  parents: PackageRef[];
  /** Shortest chain from a direct dependency down to this package; null when direct or unknown. */
  path: PackageRef[] | null;
}

export interface UnfixedPackage {
  packageKey: string;
  name: string;
  ecosystem: string | null;
  version: string | null;
  projects: { id: number; name: string }[];
  vulnerabilities: string[];
}

export interface UpgradePlan {
  upgrades: PackageUpgrade[];
  /** Package versions with vulnerabilities and no fixed version above them. */
  unfixed: UnfixedPackage[];
}

type GraphEdges = Pick<DependencyGraph, 'edges' | 'directIds'>;

const major = (v: string) => parseVersion(v).release[0] ?? 0;

/**
 * Ranked package upgrades by the risk they retire (the priority order of `comparePriority`, summed over cleared CVEs).
 * A version clears a CVE when it is at or above one of the CVE's fixed versions. `graphs` (from `getDependencyGraph`)
 * is optional and only adds parent and path context for transitives.
 */
export function aggregateUpgrades(list: InventoryComponent[], graphs: GraphEdges[] = []): UpgradePlan {
  const byId = new Map(list.map((c) => [c.id, c]));
  const parentsOf = new Map<number, number[]>();
  const direct = new Set<number>();
  for (const g of graphs) {
    for (const e of g.edges) {
      parentsOf.set(e.childId, [...(parentsOf.get(e.childId) ?? []), e.parentId]);
    }
    for (const id of g.directIds ?? []) {
      direct.add(id);
    }
  }
  const ref = (id: number): PackageRef => ({ name: byId.get(id)!.name, version: byId.get(id)!.version });

  // Breadth-first up the parents, so the first direct dependency reached gives the shortest chain.
  const pathTo = (start: number): PackageRef[] | null => {
    const seen = new Set([start]);
    let frontier: number[][] = [[start]];
    while (frontier.length) {
      const next: number[][] = [];
      for (const chain of frontier) {
        for (const p of parentsOf.get(chain[0]) ?? []) {
          if (seen.has(p) || !byId.has(p)) {
            continue;
          }
          seen.add(p);
          if (direct.has(p)) {
            return [p, ...chain].map(ref);
          }
          next.push([p, ...chain]);
        }
      }
      frontier = next;
    }
    return null;
  };

  const groups = new Map<string, InventoryComponent[]>();
  for (const c of list) {
    if (!c.vulns.length) {
      continue;
    }
    const key = `${groupKey(c)}@${c.version}`;
    groups.set(key, [...(groups.get(key) ?? []), c]);
  }

  const upgrades: Omit<PackageUpgrade, 'rank'>[] = [];
  const unfixed: UnfixedPackage[] = [];
  for (const members of groups.values()) {
    const first = members[0];
    const vulns = new Map<string, ComponentVuln>();
    for (const c of members) {
      for (const v of c.vulns) {
        vulns.set(v.id, v);
      }
    }
    const projects = new Map(members.map((c) => [c.projectId, { id: c.projectId, name: c.projectName }]));
    const base = {
      packageKey: groupKey(first),
      name: first.name,
      ecosystem: first.ecosystem,
      version: first.version,
      projects: [...projects.values()],
      vulnerabilities: [...vulns.keys()],
    };
    // Prereleases are never offered as a fix; a fix at or below the current version is not an upgrade.
    const fixes = (v: ComponentVuln) => v.fixedVersions.filter((f) => compareVersions(f, first.version) > 0 && !isPrerelease(f));
    const candidates = [...new Set([...vulns.values()].flatMap(fixes))].sort(compareVersions);
    if (!candidates.length) {
      unfixed.push(base);
      continue;
    }
    const clearedBy = (version: string): UpgradeTarget => ({
      version,
      clears: [...vulns.values()].filter((v) => fixes(v).some((f) => compareVersions(f, version) <= 0)).map((v) => v.id),
    });
    const inMajor = candidates.filter((f) => major(f) === major(first.version ?? '')).map(clearedBy);
    // Candidates ascend, so the first with the largest clear count is the lowest such version.
    const sameMajor = inMajor.reduce<UpgradeTarget | null>((best, t) => (!best || t.clears.length > best.clears.length ? t : best), null);
    const all = candidates.map(clearedBy).find((t) => t.clears.length === vulns.size) ?? null;
    const ranked = sameMajor ?? all ?? candidates.map(clearedBy).at(-1)!;
    const cleared = new Set(ranked.clears);
    const risk: UpgradeRisk = { kev: 0, epss: 0, severity: 0, score: 0 };
    for (const v of vulns.values()) {
      if (cleared.has(v.id)) {
        risk.kev += v.kev ? 1 : 0;
        risk.epss += v.epss?.score ?? 0;
        risk.severity += SEVERITY_RANK[v.severity];
        risk.score += v.score ?? 0;
      }
    }
    const ids = members.map((c) => c.id);
    const isDirect = ids.some((id) => direct.has(id));
    const parentIds = [...new Set(ids.flatMap((id) => parentsOf.get(id) ?? []))].filter((p) => byId.has(p));
    const parents = new Map(parentIds.map((p) => [`${ref(p).name}@${ref(p).version}`, ref(p)]));
    upgrades.push({
      ...base,
      sameMajor,
      clearsAll: all,
      remaining: base.vulnerabilities.filter((id) => !cleared.has(id)),
      risk,
      direct: isDirect ? true : parents.size ? false : null,
      parents: [...parents.values()],
      path: isDirect ? null : (ids.map(pathTo).find((p) => p) ?? null),
    });
  }
  upgrades.sort(
    (a, b) =>
      b.risk.kev - a.risk.kev ||
      b.risk.epss - a.risk.epss ||
      b.risk.severity - a.risk.severity ||
      b.risk.score - a.risk.score ||
      a.name.localeCompare(b.name) ||
      compareVersions(a.version, b.version),
  );
  unfixed.sort((a, b) => a.name.localeCompare(b.name) || compareVersions(a.version, b.version));
  return { upgrades: upgrades.map((u, i) => ({ ...u, rank: i + 1 })), unfixed };
}

export async function listPackages(db: Db) {
  return aggregatePackages(await loadComponents(db));
}

/** Filtered and paged lists for `GET /api/v1/*` (L-002); the unfiltered functions above stay for the pages. */
export async function listProjectsPage(db: Db, filter: ProjectFilter, page: PageParams): Promise<Page<ProjectSummary>> {
  return paginate(filterProjects(await listProjects(db, { repository: filter.repository }), filter), page);
}

export async function listPackagesPage(db: Db, filter: PackageFilter, page: PageParams): Promise<Page<PackageSummary>> {
  return paginate(filterPackages(await listPackages(db), filter), page);
}

export async function listVulnerabilitiesPage(db: Db, filter: VulnerabilityFilter, page: PageParams): Promise<Page<VulnerabilitySummary>> {
  return paginate(filterVulnerabilities(await listVulnerabilities(db), filter), page);
}

export interface PackageScorecard {
  status: ScorecardStatus;
  score: number | null;
  sourceRepo: string | null;
  /** Lowest scored checks, worst first. */
  weakest: ScorecardCheck[];
  checkedAt: string | null;
}

async function loadScorecard(db: Db, key: string, ecosystem: string | null): Promise<PackageScorecard> {
  const [p] = await db
    .select({
      sourceRepo: packages.sourceRepo,
      score: packages.scorecardScore,
      checks: packages.scorecardChecks,
      checkedAt: packages.scorecardCheckedAt,
    })
    .from(packages)
    .where(eq(packages.key, key));
  return {
    status: scorecardStatus(ecosystem, p?.checkedAt ?? null, p?.score ?? null),
    score: p?.score ?? null,
    sourceRepo: p?.sourceRepo ?? null,
    weakest: weakestChecks(p?.checks ?? []),
    checkedAt: iso(p?.checkedAt ?? null),
  };
}

export async function getPackage(db: Db, key: string) {
  const list = await loadComponents(db, { packageKey: key });
  if (!list.length) {
    return null;
  }
  const [pkg] = aggregatePackages(list);
  return { ...pkg, scorecard: await loadScorecard(db, key, pkg.ecosystem), vulnerabilities: aggregateVulnerabilities(list) };
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
  const { kev, epss } = (await loadExploitSignals(db, [v]))(v.id, v.aliases);
  const usage = aggregateVulnerabilities(await loadComponents(db, { vulnerabilityId: v.id })).find((u) => u.id === v.id);
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

export async function getOverview(db: Db, filter: OverviewFilter = {}) {
  const everything = await loadComponents(db);
  const everyProject = await listProjectsFrom(db, everything);
  const projectList = filterOverviewProjects(everyProject, filter);
  const filtered = projectList.length !== everyProject.length;
  const sbomIds = new Set(projectList.flatMap((p) => (p.latest ? [p.latest.id] : [])));
  const all = filtered ? everything.filter((c) => sbomIds.has(c.sbomId)) : everything;
  const pkgs = aggregatePackages(all);
  const recentUploads = projectList.length
    ? await db
        .select({ ...sbomColumns, projectId: projects.id, projectName: projects.name })
        .from(sboms)
        .innerJoin(projects, eq(projects.id, sboms.projectId))
        .where(
          inArray(
            projects.id,
            projectList.map((p) => p.id),
          ),
        )
        .orderBy(desc(sboms.uploadedAt), desc(sboms.id))
        .limit(8)
    : [];
  return {
    /** Projects matching the filter; `totalProjectCount` ignores it, so an empty match is not mistaken for an empty dashboard. */
    projectCount: projectList.length,
    totalProjectCount: everyProject.length,
    /** Every value a filter could pick, from all Projects, so a narrowed view can be widened. */
    facets: overviewFacets(everyProject),
    staleProjects: projectList.filter((p) => p.stale).length,
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
    .select({ document: sboms.document, version: sboms.version, environment: sboms.environment, projectName: projects.name })
    .from(sboms)
    .innerJoin(projects, eq(projects.id, sboms.projectId))
    .where(eq(sboms.id, id));
  return row ?? null;
}
