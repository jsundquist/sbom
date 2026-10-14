// Latest-version lookups against the deps.dev API (https://docs.deps.dev/api/v3/).
import { displayName } from '../lib/purl.js';
import { isPrerelease, maxVersion } from '../lib/version.js';
import { fetchJson } from './http.js';

const SYSTEMS = { npm: 'npm', pypi: 'pypi', maven: 'maven', golang: 'go', cargo: 'cargo', gem: 'rubygems', nuget: 'nuget' };

export function depsDevSystem(type) {
  return SYSTEMS[type] || null;
}

/** Returns the latest stable version of a package, or null if unknown. */
export async function latestVersion(fetchImpl, baseUrl, pkg) {
  const system = depsDevSystem(pkg.type);
  if (!system) return null;
  const name = displayName(pkg);
  const data = await fetchJson(
    fetchImpl,
    `${baseUrl}/v3/systems/${system}/packages/${encodeURIComponent(name)}`,
  );
  return pickLatest(data?.versions || []);
}

export function pickLatest(versions) {
  const def = versions.find((v) => v.isDefault)?.versionKey?.version;
  // The registry's default (e.g. npm's "latest" dist-tag) is authoritative when it's a stable release.
  if (def && !isPrerelease(def)) return def;
  const stable = versions.map((v) => v.versionKey?.version).filter((v) => v && !isPrerelease(v));
  return maxVersion(stable) || def || null;
}
