// CVSS v3.x base score calculation and severity helpers.

export const SEVERITY_RANK = { CRITICAL: 4, HIGH: 3, MEDIUM: 2, LOW: 1, UNKNOWN: 0 };

const W = {
  AV: { N: 0.85, A: 0.62, L: 0.55, P: 0.2 },
  AC: { L: 0.77, H: 0.44 },
  UI: { N: 0.85, R: 0.62 },
  CIA: { H: 0.56, L: 0.22, N: 0 },
};

function roundUp(x) {
  const i = Math.round(x * 100000);
  return i % 10000 === 0 ? i / 100000 : (Math.floor(i / 10000) + 1) / 10;
}

export function cvss3Score(vector) {
  if (typeof vector !== 'string' || !/^CVSS:3\.[01]\//.test(vector)) return null;
  const m = Object.fromEntries(
    vector
      .split('/')
      .slice(1)
      .map((p) => p.split(':')),
  );
  const changed = m.S === 'C';
  const pr = { N: 0.85, L: changed ? 0.68 : 0.62, H: changed ? 0.5 : 0.27 }[m.PR];
  const av = W.AV[m.AV];
  const ac = W.AC[m.AC];
  const ui = W.UI[m.UI];
  const [c, i, a] = [W.CIA[m.C], W.CIA[m.I], W.CIA[m.A]];
  if ([pr, av, ac, ui, c, i, a].some((v) => v === undefined) || !['U', 'C'].includes(m.S)) return null;
  const iss = 1 - (1 - c) * (1 - i) * (1 - a);
  const impact = changed ? 7.52 * (iss - 0.029) - 3.25 * Math.pow(iss - 0.02, 15) : 6.42 * iss;
  if (impact <= 0) return 0;
  const exploitability = 8.22 * av * ac * pr * ui;
  return changed ? roundUp(Math.min(1.08 * (impact + exploitability), 10)) : roundUp(Math.min(impact + exploitability, 10));
}

export function ratingFromScore(score) {
  if (score === null || score === undefined) return 'UNKNOWN';
  if (score >= 9) return 'CRITICAL';
  if (score >= 7) return 'HIGH';
  if (score >= 4) return 'MEDIUM';
  if (score > 0) return 'LOW';
  return 'UNKNOWN';
}

export function normalizeSeverity(label) {
  const s = String(label || '').toUpperCase();
  if (s === 'MODERATE') return 'MEDIUM';
  return SEVERITY_RANK[s] !== undefined ? s : 'UNKNOWN';
}

// Derive { severity, score, vector } from an OSV vulnerability record.
export function osvSeverity(vuln) {
  const entries = [...(vuln.severity || []), ...(vuln.affected || []).flatMap((a) => a.severity || [])];
  for (const e of entries) {
    if (e.type === 'CVSS_V3') {
      const score = cvss3Score(e.score);
      if (score !== null) return { severity: ratingFromScore(score), score, vector: e.score };
    }
  }
  const dbSeverity =
    vuln.database_specific?.severity ||
    (vuln.affected || []).map((a) => a.ecosystem_specific?.severity || a.database_specific?.severity).find(Boolean);
  const v4 = entries.find((e) => e.type === 'CVSS_V4');
  return { severity: normalizeSeverity(dbSeverity), score: null, vector: v4?.score || null };
}

export function maxSeverity(severities) {
  let best = null;
  for (const s of severities) if (best === null || SEVERITY_RANK[s] > SEVERITY_RANK[best]) best = s;
  return best;
}
