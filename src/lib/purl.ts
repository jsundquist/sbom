// Minimal Package URL (https://github.com/package-url/purl-spec) parsing.

export interface Purl {
  type: string;
  namespace: string | null;
  name: string;
  version: string | null;
  qualifiers: Record<string, string>;
}

export type PackageRef = Pick<Purl, 'type' | 'namespace' | 'name'>;

function safeDecode(s: string): string {
  try {
    return decodeURIComponent(s);
  } catch {
    return s;
  }
}

export function parsePurl(purl: unknown): Purl | null {
  if (typeof purl !== 'string' || !purl.startsWith('pkg:')) {
    return null;
  }
  let rest = purl.slice(4).replace(/^\/+/, '');
  const hashIdx = rest.indexOf('#');
  if (hashIdx >= 0) {
    rest = rest.slice(0, hashIdx);
  }
  const qualifiers: Record<string, string> = {};
  const qIdx = rest.indexOf('?');
  if (qIdx >= 0) {
    for (const pair of rest.slice(qIdx + 1).split('&')) {
      const [k, v = ''] = pair.split('=');
      if (k) {
        qualifiers[k.toLowerCase()] = safeDecode(v);
      }
    }
    rest = rest.slice(0, qIdx);
  }
  const slash = rest.indexOf('/');
  if (slash <= 0) {
    return null;
  }
  const type = rest.slice(0, slash).toLowerCase();
  let remainder = rest.slice(slash + 1);
  let version: string | null = null;
  const at = remainder.lastIndexOf('@');
  // An "@" in the first character is an unencoded npm scope, not a version.
  if (at > 0) {
    version = safeDecode(remainder.slice(at + 1)) || null;
    remainder = remainder.slice(0, at);
  }
  const segments = remainder.split('/').filter(Boolean).map(safeDecode);
  const name = segments.pop();
  if (!name) {
    return null;
  }
  return { type, namespace: segments.length ? segments.join('/') : null, name, version, qualifiers };
}

function normalizeName(type: string, name: string): string {
  if (type === 'pypi') {
    return name.toLowerCase().replace(/[-_.]+/g, '-');
  }
  if (['npm', 'nuget', 'gem', 'cargo'].includes(type)) {
    return name.toLowerCase();
  }
  return name;
}

/** Package name in the ecosystem's native format, e.g. "@babel/core" or "org.slf4j:slf4j-api". */
export function displayName({ type, namespace, name }: PackageRef): string {
  if (!namespace) {
    return name;
  }
  return type === 'maven' ? `${namespace}:${name}` : `${namespace}/${name}`;
}

/** Stable, version-independent package identifier, e.g. "npm:@babel/core". */
export function packageKey(p: PackageRef): string {
  const namespace = p.namespace && p.type === 'npm' ? p.namespace.toLowerCase() : p.namespace;
  return `${p.type}:${displayName({ type: p.type, namespace, name: normalizeName(p.type, p.name) })}`;
}

/** Canonical purl without version, qualifiers or subpath. */
export function basePurl(p: PackageRef): string {
  const parts = [p.type];
  if (p.namespace) {
    parts.push(...p.namespace.split('/').map(encodeURIComponent));
  }
  parts.push(encodeURIComponent(p.name));
  return `pkg:${parts.join('/')}`;
}
