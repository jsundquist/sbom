// Ecosystem mappings shared by the worker (enrichment) and server (what is scannable).

/** purl types OSV can map to one of its ecosystems. */
export const OSV_TYPES = new Set([
  'npm',
  'pypi',
  'maven',
  'golang',
  'cargo',
  'gem',
  'nuget',
  'composer',
  'hex',
  'pub',
  'deb',
  'apk',
  'rpm',
  'swift',
  'cran',
  'hackage',
  'conan',
  'bitnami',
  'github',
]);

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

/** purl types OSV matches by distro release rather than by purl; the one place that rule lives. */
export const isDistroScoped = (purlType: string): boolean => purlType === 'apk';

/**
 * OSV ecosystem name for OS packages, which OSV matches by release ("Alpine:v3.20") and never by a bare purl.
 * `distro` is the purl qualifier, e.g. "alpine-3.20.1". Only Alpine is mapped: Debian, Ubuntu and RPM advisories are filed
 * under source package names that the SBOM's binary package names do not give. Alpine has the same gap for
 * subpackages (musl-utils is advised under its origin package musl), which still return nothing.
 */
export function osvEcosystem(purlType: string, distro: string | null | undefined): string | null {
  const alpine = isDistroScoped(purlType) ? /^alpine-(\d+\.\d+)/.exec(distro ?? '') : null;
  return alpine ? `Alpine:v${alpine[1]}` : null;
}
