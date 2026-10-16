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
