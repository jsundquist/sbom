import { z } from 'zod';

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
  MAX_UPLOAD_BYTES: z.coerce.number().int().positive().default(50 * 1024 * 1024),
  SBOM_HISTORY_LIMIT: z.coerce.number().int().positive().default(20),
  WORKER_POLL_SECONDS: z.coerce.number().positive().default(30),
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
