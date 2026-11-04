// CVE identity: advisories (GHSA-..., PYSEC-...) carry their CVE ids as aliases.

/** Every CVE id a vulnerability is known by: its own id and its aliases. */
export function cveIdsOf(id: string, aliases: readonly string[]): string[] {
  return [id, ...aliases].filter((x) => x.startsWith('CVE-'));
}

/** The vulnerability's primary CVE id, preferring its own id over an alias. */
export function cveOf(id: string, aliases: readonly string[]): string | null {
  return id.startsWith('CVE-') ? id : (aliases.find((a) => a.startsWith('CVE-')) ?? null);
}
