// Whether a project's latest SBOM is too old to trust: an abandoned pipeline must not look healthy.

/** Older than `afterDays`, counted from `now`. A project with no SBOM is not stale, and `afterDays` 0 disables the flag. */
export function isStale(uploadedAt: Date | string | null | undefined, now: Date, afterDays: number): boolean {
  if (!uploadedAt || afterDays <= 0) {
    return false;
  }
  return now.getTime() - new Date(uploadedAt).getTime() > afterDays * 86_400_000;
}
