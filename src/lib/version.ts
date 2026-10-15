// Ecosystem-agnostic version comparison. Handles semver, PEP 440-ish,
// Maven-ish and Go ("v1.2.3") versions well enough to rank releases.

export type UpdateType = 'major' | 'minor' | 'patch';
type Token = number | string;

const PRE_RE = /^(a|alpha|b|beta|c|rc|cr|pre|preview|dev|snapshot|m|milestone|ea|canary|next|nightly)\d*$/i;

function tokenize(s: string): Token[] {
  return s
    .split(/[.\-_+~]|(?<=\d)(?=[a-z])|(?<=[a-z])(?=\d)/i)
    .filter((t) => t !== '')
    .map((t) => (/^\d+$/.test(t) ? Number(t) : t.toLowerCase()));
}

interface ParsedVersion {
  release: number[];
  pre: Token[];
  qualifier: Token[];
}

export function parseVersion(version: string | null | undefined): ParsedVersion {
  let v = String(version ?? '').trim().replace(/^v(?=\d)/i, '');
  const plus = v.indexOf('+');
  if (plus >= 0) {v = v.slice(0, plus);}
  const m = v.match(/^(\d+(?:\.\d+)*)(.*)$/);
  if (!m) {return { release: [], pre: tokenize(v), qualifier: [] };}
  const tail = tokenize(m[2]);
  // Tail tokens like "-jre" or ".RELEASE" are qualifiers, not prereleases.
  const isPre = tail.some((t) => typeof t === 'string' && PRE_RE.test(t));
  return { release: m[1].split('.').map(Number), pre: isPre ? tail : [], qualifier: isPre ? [] : tail };
}

export function isPrerelease(version: string): boolean {
  return parseVersion(version).pre.length > 0;
}

function compareTokens(a: Token | undefined, b: Token | undefined): number {
  if (a === undefined) {return b === undefined ? 0 : -1;}
  if (b === undefined) {return 1;}
  if (typeof a === 'number' && typeof b === 'number') {return a - b;}
  if (typeof a === 'number') {return 1;}
  if (typeof b === 'number') {return -1;}
  return a < b ? -1 : a > b ? 1 : 0;
}

export function compareVersions(a: string | null | undefined, b: string | null | undefined): number {
  const pa = parseVersion(a);
  const pb = parseVersion(b);
  for (let i = 0; i < Math.max(pa.release.length, pb.release.length); i++) {
    const d = (pa.release[i] ?? 0) - (pb.release[i] ?? 0);
    if (d) {return Math.sign(d);}
  }
  // A release ranks above any of its prereleases.
  if (pa.pre.length && !pb.pre.length) {return -1;}
  if (!pa.pre.length && pb.pre.length) {return 1;}
  const ta = pa.pre.length ? pa.pre : pa.qualifier;
  const tb = pb.pre.length ? pb.pre : pb.qualifier;
  for (let i = 0; i < Math.max(ta.length, tb.length); i++) {
    const d = compareTokens(ta[i], tb[i]);
    if (d) {return Math.sign(d);}
  }
  return 0;
}

/** Returns null when `current` is up to date, otherwise how far behind `latest` it is. */
export function updateType(current: string | null | undefined, latest: string | null | undefined): UpdateType | null {
  if (!current || !latest || compareVersions(current, latest) >= 0) {return null;}
  const c = parseVersion(current).release;
  const l = parseVersion(latest).release;
  if ((c[0] ?? 0) !== (l[0] ?? 0)) {return 'major';}
  if ((c[1] ?? 0) !== (l[1] ?? 0)) {return 'minor';}
  return 'patch';
}

export function maxVersion(versions: string[]): string | null {
  let best: string | null = null;
  for (const v of versions) {if (best === null || compareVersions(v, best) > 0) {best = v;}}
  return best;
}

export const UPDATE_RANK: Record<UpdateType, number> = { patch: 1, minor: 2, major: 3 };
