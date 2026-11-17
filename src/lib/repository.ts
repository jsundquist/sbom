/** Repository normaliser (CONTEXT.md, ADR 0004): every spelling of a git remote becomes `host/path`, e.g. `github.com/owner/repo`. */

const GITHUB = 'github.com';

/** `host/path` for a git remote or GitHub `owner/repo`, or null when the text is not a repository. */
export function normalizeRepository(input: string): string | null {
  let s = input.trim().replace(/^git\+/i, '');
  let host: string;
  let path: string;

  const scp = /^[^/@\s]+@([^:/\s]+):(?!\/\/)(.+)$/.exec(s);
  if (scp) {
    [, host, path] = scp;
  } else if (s.includes('://')) {
    try {
      const u = new URL(s);
      host = u.hostname;
      path = u.pathname;
    } catch {
      return null;
    }
  } else {
    s = s.replace(/^\/+/, '');
    const slash = s.indexOf('/');
    if (slash < 0) {
      return null;
    }
    const first = s.slice(0, slash);
    // GitHub owners cannot contain a dot, so a dotted first segment is a host. Otherwise this is GITHUB_REPOSITORY (`owner/repo`).
    if (first.includes('.')) {
      host = first;
      path = s.slice(slash);
    } else {
      host = GITHUB;
      path = s;
    }
  }

  host = host.toLowerCase().replace(/^www\./, '');
  const segments = path.split('/').filter(Boolean);
  if (!host || segments.length < 2) {
    return null;
  }
  const github = host === GITHUB;
  // GitHub repos are exactly owner/repo, so a pasted /tree/main or /issues link still resolves.
  const kept = github ? segments.slice(0, 2) : segments;
  kept[kept.length - 1] = kept[kept.length - 1].replace(/\.git$/i, '');
  if (kept.some((p) => !p)) {
    return null;
  }
  const normalised = `${host}/${kept.join('/')}`;
  // GitHub is case-insensitive; other hosts keep path case because some are case-sensitive.
  return github ? normalised.toLowerCase() : normalised;
}

/**
 * The shapes an un-normalised row could hold for a normalised repository. Rows are not backfilled (ADR 0004), so lookups match
 * these (case-insensitively) until the Project is re-uploaded.
 */
export function legacyRepositoryForms(normalised: string): string[] {
  const slash = normalised.indexOf('/');
  const host = normalised.slice(0, slash);
  const path = normalised.slice(slash + 1);
  const forms = [
    normalised,
    `${normalised}.git`,
    `https://${normalised}`,
    `https://${normalised}.git`,
    `http://${normalised}`,
    `git@${host}:${path}`,
    `git@${host}:${path}.git`,
    `ssh://git@${host}/${path}.git`,
  ];
  if (host === GITHUB) {
    forms.push(path, `${path}.git`);
  }
  return forms;
}
