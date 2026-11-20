import { z } from 'zod';
import { PROJECT_KINDS, type ProjectKind } from '@/lib/kinds';
import { normalizeRepository } from '@/lib/repository';
import { SEVERITIES, type Severity } from '@/lib/severity';

/** Parses a positive integer route parameter. */
export function parseIdOrNull(value: string): number | null {
  const n = Number(value);
  return Number.isInteger(n) && n > 0 ? n : null;
}

/** Trend window in days: default 90, clamped to 1..365. */
export function parseDays(value: string | null): number {
  const n = Number(value);
  return Number.isInteger(n) && n >= 1 ? Math.min(n, 365) : 90;
}

// List endpoint query params (L-002): plain strings in, Zod-validated filters out; a bad value is a message for a 400.
export const MAX_LIMIT = 1000;

export type Parsed<T> = { ok: true; value: T } | { ok: false; error: string };

export interface PageParams {
  /** Unset means unlimited, so existing callers keep getting everything. */
  limit?: number;
  offset: number;
}

export interface ProjectFilter {
  kind?: ProjectKind;
  tag?: string;
  /** Normalised remote; matched in SQL by `listProjects`, not by the in-memory filter. */
  repository?: string;
  stale?: boolean;
  q?: string;
}

export interface PackageFilter {
  ecosystem?: string;
  deprecated?: boolean;
  abandoned?: boolean;
  q?: string;
}

export interface VulnerabilityFilter {
  severity?: Severity;
  exploited?: boolean;
  project?: number;
  q?: string;
}

// An empty value (`?kind=`) counts as absent, so forms can submit blanks.
const blank = (v: unknown) => (typeof v === 'string' && v.trim() === '' ? undefined : v);
const opt = <T extends z.ZodTypeAny>(s: T) => z.preprocess(blank, s.optional());
const bool = opt(z.enum(['true', 'false']).transform((v) => v === 'true'));
const text = opt(z.string().trim().max(200));
const lower = opt(z.string().trim().toLowerCase().max(200));

const pageSchema = z.object({
  limit: opt(z.coerce.number().int().min(1).max(MAX_LIMIT)),
  offset: opt(z.coerce.number().int().min(0)),
});

const projectSchema = z.object({
  kind: opt(z.string().trim().toLowerCase().pipe(z.enum(PROJECT_KINDS))),
  tag: lower,
  stale: bool,
  q: text,
});

const packageSchema = z.object({ ecosystem: lower, deprecated: bool, abandoned: bool, q: text });

const vulnSchema = z.object({
  severity: opt(
    z
      .string()
      .trim()
      .toUpperCase()
      .pipe(z.enum(SEVERITIES as [Severity, ...Severity[]])),
  ),
  exploited: bool,
  project: opt(z.coerce.number().int().min(1)),
  q: text,
});

function parse<S extends z.ZodTypeAny>(schema: S, sp: URLSearchParams, keys: string[]): Parsed<z.infer<S>> {
  const r = schema.safeParse(Object.fromEntries(keys.flatMap((k) => (sp.has(k) ? [[k, sp.get(k)]] : []))));
  if (r.success) {
    return { ok: true, value: r.data };
  }
  const issue = r.error.issues[0];
  return { ok: false, error: `Invalid ${issue.path.join('.') || 'query'}: ${issue.message}` };
}

export function parsePage(sp: URLSearchParams): Parsed<PageParams> {
  const r = parse(pageSchema, sp, ['limit', 'offset']);
  return r.ok ? { ok: true, value: { limit: r.value.limit, offset: r.value.offset ?? 0 } } : r;
}

export function parseProjectFilter(sp: URLSearchParams): Parsed<ProjectFilter> {
  const r = parse(projectSchema, sp, ['kind', 'tag', 'stale', 'q']);
  if (!r.ok) {
    return r;
  }
  const raw = sp.get('repository')?.trim();
  const repository = raw ? normalizeRepository(raw) : undefined;
  if (repository === null) {
    return { ok: false, error: 'repository must be a git remote or owner/repo' };
  }
  return { ok: true, value: { ...r.value, repository } };
}

/** The overview's filter: only the Project attributes ADR 0004 makes bookmarkable; other project params are ignored. */
export type OverviewFilter = Pick<ProjectFilter, 'kind' | 'tag' | 'repository'>;

export function parseOverviewFilter(sp: URLSearchParams): Parsed<OverviewFilter> {
  const r = parseProjectFilter(sp);
  if (!r.ok) {
    return r;
  }
  const { kind, tag, repository } = r.value;
  return { ok: true, value: { ...(kind && { kind }), ...(tag && { tag }), ...(repository && { repository }) } };
}

export const parsePackageFilter = (sp: URLSearchParams): Parsed<PackageFilter> =>
  parse(packageSchema, sp, ['ecosystem', 'deprecated', 'abandoned', 'q']);

export const parseVulnerabilityFilter = (sp: URLSearchParams): Parsed<VulnerabilityFilter> =>
  parse(vulnSchema, sp, ['severity', 'exploited', 'project', 'q']);
