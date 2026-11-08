// Whether a package is still maintained, from what deps.dev reports about its latest release.

export interface MaintenanceInput {
  deprecated: boolean;
  reason?: string | null;
  /** Publish date of the latest version, null when deps.dev does not know it. */
  latestReleasedAt: Date | null;
}

export interface Maintenance {
  deprecated: boolean;
  deprecatedReason: string | null;
  /** No release for longer than the threshold. Never set when the release date is unknown. */
  abandoned: boolean;
  lastReleaseAt: string | null;
}

export function maintenanceFlags(
  { deprecated, reason, latestReleasedAt }: MaintenanceInput,
  now: Date,
  abandonedAfterYears: number,
): Maintenance {
  const cutoff = new Date(now);
  cutoff.setUTCFullYear(cutoff.getUTCFullYear() - abandonedAfterYears);
  return {
    deprecated,
    deprecatedReason: deprecated ? (reason ?? null) : null,
    abandoned: !!latestReleasedAt && latestReleasedAt < cutoff,
    lastReleaseAt: latestReleasedAt ? latestReleasedAt.toISOString() : null,
  };
}
