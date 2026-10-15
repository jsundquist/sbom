// Latest-version lookups against the deps.dev API (https://docs.deps.dev/api/v3/).
import { z } from 'zod';
import { displayName, type PackageRef } from '@/lib/purl';
import { isPrerelease, maxVersion } from '@/lib/version';
import { fetchJson, type FetchFn } from './http';

const SYSTEMS: Record<string, string> = {
  npm: 'npm',
  pypi: 'pypi',
  maven: 'maven',
  golang: 'go',
  cargo: 'cargo',
  gem: 'rubygems',
  nuget: 'nuget',
};

export const depsDevSystem = (purlType: string): string | null => SYSTEMS[purlType] ?? null;

const versionSchema = z.looseObject({
  versionKey: z.looseObject({ version: z.string() }),
  isDefault: z.boolean().nullish(),
});
const packageSchema = z.looseObject({ versions: z.array(versionSchema).nullish() });
type DepsDevVersion = z.infer<typeof versionSchema>;

/** Latest stable version of a package, or null when unknown. */
export async function latestVersion(fetchImpl: FetchFn, baseUrl: string, pkg: PackageRef): Promise<string | null> {
  const system = depsDevSystem(pkg.type);
  if (!system) return null;
  const url = `${baseUrl}/v3/systems/${system}/packages/${encodeURIComponent(displayName(pkg))}`;
  const data = await fetchJson(fetchImpl, url, packageSchema);
  return pickLatest(data?.versions ?? []);
}

export function pickLatest(versions: DepsDevVersion[]): string | null {
  const def = versions.find((v) => v.isDefault)?.versionKey.version;
  // The registry's default (e.g. npm's "latest" dist-tag) is authoritative when it's a stable release.
  if (def && !isPrerelease(def)) return def;
  const stable = versions.map((v) => v.versionKey.version).filter((v) => !isPrerelease(v));
  return maxVersion(stable) ?? def ?? null;
}
