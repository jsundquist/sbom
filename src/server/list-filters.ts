// In-memory filters and paging for the list endpoints (L-002). At the ADR 0005 scale the lists are small, so this runs after
// the aggregation and keeps one code path; `repository` is the exception (it narrows the SQL in `listProjects`).
import type { OverviewFilter, PackageFilter, PageParams, ProjectFilter, VulnerabilityFilter } from '@/lib/params';
import { normalizeRepository } from '@/lib/repository';
import type { PackageSummary, ProjectSummary, VulnerabilitySummary } from './inventory';

const has = (haystack: (string | null | undefined)[], q: string | undefined) =>
  !q || haystack.some((h) => h?.toLowerCase().includes(q.toLowerCase()));

export const filterProjects = (list: ProjectSummary[], f: ProjectFilter) =>
  list.filter(
    (p) =>
      (!f.kind || p.kind === f.kind) &&
      (!f.tag || p.tags.includes(f.tag)) &&
      (f.stale === undefined || p.stale === f.stale) &&
      has([p.name, p.repository], f.q),
  );

/** The overview's filter, repository included (rows may still hold an older spelling, so compare normalised). */
export const filterOverviewProjects = (list: ProjectSummary[], f: OverviewFilter) =>
  list.filter(
    (p) =>
      (!f.kind || p.kind === f.kind) &&
      (!f.tag || p.tags.includes(f.tag)) &&
      (!f.repository || (p.repository !== null && normalizeRepository(p.repository) === f.repository)),
  );

/** What each overview filter can offer, from all Projects: sorted, de-duplicated. */
export function overviewFacets(list: ProjectSummary[]) {
  const sorted = (xs: string[]) => [...new Set(xs)].sort();
  return {
    kinds: sorted(list.map((p) => p.kind)),
    tags: sorted(list.flatMap((p) => p.tags)),
    repositories: sorted(list.flatMap((p) => (p.repository ? [normalizeRepository(p.repository) ?? p.repository] : []))),
  };
}

export const filterPackages = (list: PackageSummary[], f: PackageFilter) =>
  list.filter(
    (p) =>
      (!f.ecosystem || p.ecosystem?.toLowerCase() === f.ecosystem) &&
      (f.deprecated === undefined || p.maintenance.deprecated === f.deprecated) &&
      (f.abandoned === undefined || p.maintenance.abandoned === f.abandoned) &&
      has([p.name, p.key], f.q),
  );

export const filterVulnerabilities = (list: VulnerabilitySummary[], f: VulnerabilityFilter) =>
  list.filter(
    (v) =>
      (!f.severity || v.severity === f.severity) &&
      (f.exploited === undefined || !!v.kev === f.exploited) &&
      (!f.project || v.projects.some((p) => p.id === f.project)) &&
      has([v.id, v.summary, ...v.aliases], f.q),
  );

export interface Page<T> {
  items: T[];
  /** Matches before paging, for X-Total-Count. */
  total: number;
}

export function paginate<T>(list: T[], { limit, offset }: PageParams): Page<T> {
  return { items: list.slice(offset, limit === undefined ? undefined : offset + limit), total: list.length };
}
