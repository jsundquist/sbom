import { SEVERITY_RANK, type Severity } from './severity';

export interface PriorityInput {
  /** Non-null when the vulnerability is in the CISA KEV catalog. */
  kev: unknown | null;
  epss: { score: number } | null;
  severity: Severity;
  score: number | null;
}

/**
 * Orders vulnerabilities by what to fix first: known exploited (KEV), then EPSS (probability of exploitation),
 * then severity and CVSS score. Negative when `a` should come before `b`. An unscored CVE counts as EPSS 0.
 */
export function comparePriority(a: PriorityInput, b: PriorityInput): number {
  return (
    Number(!!b.kev) - Number(!!a.kev) ||
    (b.epss?.score ?? 0) - (a.epss?.score ?? 0) ||
    SEVERITY_RANK[b.severity] - SEVERITY_RANK[a.severity] ||
    (b.score ?? 0) - (a.score ?? 0)
  );
}
