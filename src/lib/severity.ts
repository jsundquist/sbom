// CVSS v3.x base score calculation and severity helpers.
import type { Severity } from '@/db/schema';

export type { Severity };
export const SEVERITIES: Severity[] = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'UNKNOWN'];
export const SEVERITY_RANK: Record<Severity, number> = { CRITICAL: 4, HIGH: 3, MEDIUM: 2, LOW: 1, UNKNOWN: 0 };

const AV: Record<string, number> = { N: 0.85, A: 0.62, L: 0.55, P: 0.2 };
const AC: Record<string, number> = { L: 0.77, H: 0.44 };
const UI: Record<string, number> = { N: 0.85, R: 0.62 };
const CIA: Record<string, number> = { H: 0.56, L: 0.22, N: 0 };

function roundUp(x: number): number {
  const i = Math.round(x * 100000);
  return i % 10000 === 0 ? i / 100000 : (Math.floor(i / 10000) + 1) / 10;
}

export function cvss3Score(vector: unknown): number | null {
  if (typeof vector !== 'string' || !/^CVSS:3\.[01]\//.test(vector)) {return null;}
  const m = Object.fromEntries(
    vector
      .split('/')
      .slice(1)
      .map((p) => p.split(':')),
  ) as Record<string, string>;
  const changed = m.S === 'C';
  const pr = ({ N: 0.85, L: changed ? 0.68 : 0.62, H: changed ? 0.5 : 0.27 } as Record<string, number>)[m.PR];
  const values = [pr, AV[m.AV], AC[m.AC], UI[m.UI], CIA[m.C], CIA[m.I], CIA[m.A]];
  if (values.some((v) => v === undefined) || !['U', 'C'].includes(m.S)) {return null;}
  const [, av, ac, ui, c, i, a] = values;
  const iss = 1 - (1 - c) * (1 - i) * (1 - a);
  const impact = changed ? 7.52 * (iss - 0.029) - 3.25 * Math.pow(iss - 0.02, 15) : 6.42 * iss;
  if (impact <= 0) {return 0;}
  const exploitability = 8.22 * av * ac * pr * ui;
  return roundUp(Math.min((changed ? 1.08 : 1) * (impact + exploitability), 10));
}

export function ratingFromScore(score: number | null | undefined): Severity {
  if (score === null || score === undefined) {return 'UNKNOWN';}
  if (score >= 9) {return 'CRITICAL';}
  if (score >= 7) {return 'HIGH';}
  if (score >= 4) {return 'MEDIUM';}
  if (score > 0) {return 'LOW';}
  return 'UNKNOWN';
}

export function normalizeSeverity(label: unknown): Severity {
  const s = String(label ?? '').toUpperCase();
  if (s === 'MODERATE') {return 'MEDIUM';}
  return (SEVERITIES as string[]).includes(s) ? (s as Severity) : 'UNKNOWN';
}

export function maxSeverity(severities: (Severity | null | undefined)[]): Severity | null {
  let best: Severity | null = null;
  for (const s of severities) {if (s && (best === null || SEVERITY_RANK[s] > SEVERITY_RANK[best])) {best = s;}}
  return best;
}
