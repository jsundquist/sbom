// Which packages enrichment covers, shared by the worker (what is due) and the server (what to show).
import { depsDevSystem, OSV_TYPES } from './ecosystems';

export type VulnStatus = 'scanned' | 'pending' | 'unsupported';
export type VersionStatus = 'checked' | 'pending' | 'unsupported';

/** purl types the vulnerability scan queries; the worker selects due versions from these. */
export const SCANNABLE_ECOSYSTEMS: readonly string[] = [...OSV_TYPES];

/** Whether a component can be scanned for vulnerabilities. A version is required: OSV is queried per version. */
export const isScannable = (ecosystem: string | null, version: string | null): boolean =>
  !!ecosystem && OSV_TYPES.has(ecosystem) && !!version;

/** Whether a package's latest version can be looked up. */
export const isVersionCheckable = (ecosystem: string | null): boolean => !!ecosystem && depsDevSystem(ecosystem) !== null;

export function vulnStatus(ecosystem: string | null, version: string | null, vulnsCheckedAt: Date | null): VulnStatus {
  if (!isScannable(ecosystem, version)) {
    return 'unsupported';
  }
  return vulnsCheckedAt ? 'scanned' : 'pending';
}

export function versionStatus(ecosystem: string | null, latestCheckedAt: Date | null): VersionStatus {
  if (!isVersionCheckable(ecosystem)) {
    return 'unsupported';
  }
  return latestCheckedAt ? 'checked' : 'pending';
}
