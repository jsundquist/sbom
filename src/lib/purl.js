// Minimal Package URL (https://github.com/package-url/purl-spec) parsing.

export function parsePurl(purl) {
  if (typeof purl !== 'string' || !purl.startsWith('pkg:')) return null;
  let rest = purl.slice(4).replace(/^\/+/, '');
  const hashIdx = rest.indexOf('#');
  if (hashIdx >= 0) rest = rest.slice(0, hashIdx);
  let qualifiers = {};
  const qIdx = rest.indexOf('?');
  if (qIdx >= 0) {
    for (const pair of rest.slice(qIdx + 1).split('&')) {
      const [k, v = ''] = pair.split('=');
      if (k) qualifiers[k.toLowerCase()] = safeDecode(v);
    }
    rest = rest.slice(0, qIdx);
  }
  const slash = rest.indexOf('/');
  if (slash <= 0) return null;
  const type = rest.slice(0, slash).toLowerCase();
  let remainder = rest.slice(slash + 1);
  let version = null;
  const at = remainder.lastIndexOf('@');
  // An "@" in the first character is an unencoded npm scope, not a version.
  if (at > 0) {
    version = safeDecode(remainder.slice(at + 1)) || null;
    remainder = remainder.slice(0, at);
  }
  const segments = remainder.split('/').filter(Boolean).map(safeDecode);
  if (!segments.length) return null;
  const name = segments.pop();
  const namespace = segments.length ? segments.join('/') : null;
  return { type, namespace, name, version, qualifiers };
}

function safeDecode(s) {
  try {
    return decodeURIComponent(s);
  } catch {
    return s;
  }
}

function normalizeName(type, name) {
  if (type === 'pypi') return name.toLowerCase().replace(/[-_.]+/g, '-');
  if (type === 'npm' || type === 'nuget' || type === 'gem' || type === 'cargo') return name.toLowerCase();
  return name;
}

// Human readable package name in the ecosystem's native format.
export function displayName({ type, namespace, name }) {
  if (!namespace) return name;
  if (type === 'maven') return `${namespace}:${name}`;
  return `${namespace}/${name}`;
}

// Stable identifier for a package independent of version, e.g. "npm:@babel/core".
export function packageKey(parsed) {
  const n = normalizeName(parsed.type, parsed.name);
  const ns = parsed.namespace ? (parsed.type === 'npm' ? parsed.namespace.toLowerCase() : parsed.namespace) : null;
  return `${parsed.type}:${displayName({ type: parsed.type, namespace: ns, name: n })}`;
}

// Canonical purl without version, qualifiers or subpath.
export function basePurl(parsed) {
  const parts = [parsed.type];
  if (parsed.namespace) parts.push(...parsed.namespace.split('/').map(encodeURIComponent));
  parts.push(encodeURIComponent(parsed.name));
  return `pkg:${parts.join('/')}`;
}
