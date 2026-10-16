import { z } from 'zod';

/** Lowest poll interval the worker honors, so a misconfigured value cannot hammer OSV, deps.dev, CISA or FIRST. */
export const MIN_WORKER_POLL_SECONDS = 300;

const csv = z
  .string()
  .default('')
  .transform((s) =>
    s
      .split(',')
      .map((t) => t.trim())
      .filter(Boolean),
  );

const schema = z.object({
  DATABASE_URL: z.string().default('postgres://sbom:sbom@localhost:5432/sbom'),
  /** When set, uploads must send one of these as a bearer token. Empty = open uploads. */
  UPLOAD_TOKENS: csv,
  /** In production, uploads are rejected when UPLOAD_TOKENS is empty unless this is "true". */
  ALLOW_OPEN_UPLOADS: z
    .enum(['true', 'false'])
    .default('false')
    .transform((v) => v === 'true'),
  NODE_ENV: z.string().default('development'),
  MAX_UPLOAD_BYTES: z.coerce
    .number()
    .int()
    .positive()
    .default(50 * 1024 * 1024),
  /** Write requests (uploads, deletes) allowed per client per window; 0 disables the limit. */
  WRITE_RATE_LIMIT: z.coerce.number().int().nonnegative().default(60),
  WRITE_RATE_WINDOW_SECONDS: z.coerce.number().positive().default(60),
  /** Trust X-Forwarded-For / X-Real-IP for the client address; only enable behind a proxy that sets them. */
  TRUST_PROXY: z
    .enum(['true', 'false'])
    .default('false')
    .transform((v) => v === 'true'),
  SBOM_HISTORY_LIMIT: z.coerce.number().int().positive().default(20),
  /** Uploads wake the worker immediately; the poll only catches TTL expiry, so a few runs a day is enough. */
  WORKER_POLL_SECONDS: z.coerce
    .number()
    .positive()
    .default(6 * 3600)
    .transform((s) => Math.max(s, MIN_WORKER_POLL_SECONDS)),
  VULN_TTL_HOURS: z.coerce.number().positive().default(12),
  LATEST_TTL_HOURS: z.coerce.number().positive().default(24),
  KEV_TTL_HOURS: z.coerce.number().positive().default(24),
  KEV_URL: z.string().url().default('https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json'),
  EPSS_TTL_HOURS: z.coerce.number().positive().default(24),
  EPSS_API_URL: z.string().url().default('https://api.first.org/data/v1/epss'),
  OSV_API_URL: z.string().url().default('https://api.osv.dev'),
  DEPS_DEV_API_URL: z.string().url().default('https://api.deps.dev'),
});

export type Env = z.infer<typeof schema>;

let cached: Env | undefined;

export function env(): Env {
  cached ??= schema.parse(process.env);
  return cached;
}

export function parseEnv(source: Record<string, string | undefined>): Env {
  return schema.parse(source);
}

/** Clears the cached environment (tests). */
export function resetEnv() {
  cached = undefined;
}
