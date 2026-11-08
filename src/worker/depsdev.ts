// Latest-version lookups against the deps.dev API (https://docs.deps.dev/api/v3/).
import { z } from 'zod';
import { depsDevSystem } from '@/lib/ecosystems';
import { displayName, type PackageRef } from '@/lib/purl';
import type { ScorecardCheck } from '@/lib/scorecard';
import { isPrerelease, maxVersion } from '@/lib/version';
import { fetchJson, type FetchFn } from './http';

const versionSchema = z.looseObject({
  versionKey: z.looseObject({ version: z.string() }),
  isDefault: z.boolean().nullish(),
});
const packageSchema = z.looseObject({ versions: z.array(versionSchema).nullish() });
type DepsDevVersion = z.infer<typeof versionSchema>;

/** Latest stable version of a package, or null when unknown. */
export async function latestVersion(fetchImpl: FetchFn, baseUrl: string, pkg: PackageRef): Promise<string | null> {
  const system = depsDevSystem(pkg.type);
  if (!system) {
    return null;
  }
  const url = `${baseUrl}/v3/systems/${system}/packages/${encodeURIComponent(displayName(pkg))}`;
  const data = await fetchJson(fetchImpl, url, packageSchema);
  return pickLatest(data?.versions ?? []);
}

export function pickLatest(versions: DepsDevVersion[]): string | null {
  const def = versions.find((v) => v.isDefault)?.versionKey.version;
  // The registry's default (e.g. npm's "latest" dist-tag) is authoritative when it's a stable release.
  if (def && !isPrerelease(def)) {
    return def;
  }
  const stable = versions.map((v) => v.versionKey.version).filter((v) => !isPrerelease(v));
  return maxVersion(stable) ?? def ?? null;
}

const relatedSchema = z.looseObject({
  relatedProjects: z
    .array(z.looseObject({ relationType: z.string().nullish(), projectKey: z.looseObject({ id: z.string() }).nullish() }))
    .nullish(),
});

/** deps.dev project id (e.g. "github.com/org/repo") of the package version's source repository, or null. */
export async function sourceRepo(fetchImpl: FetchFn, baseUrl: string, pkg: PackageRef, version: string): Promise<string | null> {
  const system = depsDevSystem(pkg.type);
  if (!system) {
    return null;
  }
  const url = `${baseUrl}/v3/systems/${system}/packages/${encodeURIComponent(displayName(pkg))}/versions/${encodeURIComponent(version)}`;
  const data = await fetchJson(fetchImpl, url, relatedSchema);
  return data?.relatedProjects?.find((p) => p.relationType === 'SOURCE_REPO')?.projectKey?.id ?? null;
}

const projectSchema = z.looseObject({
  scorecard: z
    .looseObject({
      overallScore: z.number().nullish(),
      checks: z.array(z.looseObject({ name: z.string(), score: z.number(), reason: z.string().nullish() })).nullish(),
    })
    .nullish(),
});

export interface ProjectScorecard {
  score: number;
  checks: ScorecardCheck[];
}

/** OpenSSF Scorecard deps.dev holds for a source repo, or null when it has none. */
export async function projectScorecard(fetchImpl: FetchFn, baseUrl: string, repo: string): Promise<ProjectScorecard | null> {
  const data = await fetchJson(fetchImpl, `${baseUrl}/v3/projects/${encodeURIComponent(repo)}`, projectSchema);
  const card = data?.scorecard;
  if (card?.overallScore == null) {
    return null;
  }
  return { score: card.overallScore, checks: (card.checks ?? []).map((c) => ({ name: c.name, score: c.score, reason: c.reason ?? null })) };
}
