import { z } from 'zod';

// The only place mcp/ reads its environment (it cannot use src/lib/env.ts: nothing here imports from src/).
const schema = z.object({
  DASHBOARD_URL: z.url({ protocol: /^https?$/ }),
  DASHBOARD_READ_TOKEN: z.string().min(1),
  DASHBOARD_TIMEOUT_MS: z.coerce.number().int().positive().default(10_000),
});

export interface Config {
  baseUrl: string;
  token: string;
  timeoutMs: number;
}

export function loadConfig(source: Record<string, string | undefined> = process.env): Config {
  const parsed = schema.safeParse(source);
  if (!parsed.success) {
    // Names only, never values: the token must not reach stderr or an agent's context.
    const names = [...new Set(parsed.error.issues.map((i) => String(i.path[0])))].join(', ');
    throw new Error(`Invalid configuration: ${names}. Set DASHBOARD_URL and DASHBOARD_READ_TOKEN.`);
  }
  return {
    baseUrl: parsed.data.DASHBOARD_URL.replace(/\/+$/, ''),
    token: parsed.data.DASHBOARD_READ_TOKEN,
    timeoutMs: parsed.data.DASHBOARD_TIMEOUT_MS,
  };
}
