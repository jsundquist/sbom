import type { z } from 'zod';

export type FetchFn = typeof fetch;

export class HttpError extends Error {
  constructor(
    message: string,
    readonly status: number,
  ) {
    super(message);
  }
}

const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));

/** Fetches JSON with a timeout and retries on network errors, 429 and 5xx. Returns null on 404. */
export async function fetchJson<T>(
  fetchImpl: FetchFn,
  url: string,
  schema: z.ZodType<T>,
  { method = 'GET', body, timeoutMs = 20_000, retries = 2 }: { method?: string; body?: unknown; timeoutMs?: number; retries?: number } = {},
): Promise<T | null> {
  for (let attempt = 0; ; attempt++) {
    let res: Response;
    try {
      res = await fetchImpl(url, {
        method,
        headers: { accept: 'application/json', ...(body ? { 'content-type': 'application/json' } : {}) },
        body: body ? JSON.stringify(body) : undefined,
        signal: AbortSignal.timeout(timeoutMs),
      });
    } catch (err) {
      if (attempt < retries) {
        await sleep(500 * 2 ** attempt);
        continue;
      }
      throw err;
    }
    if (res.status === 404) {
      return null;
    }
    if ((res.status === 429 || res.status >= 500) && attempt < retries) {
      await sleep(1000 * 2 ** attempt);
      continue;
    }
    if (!res.ok) {
      const text = await res.text().catch(() => '');
      throw new HttpError(`${method} ${url} -> HTTP ${res.status} ${text.slice(0, 200)}`, res.status);
    }
    return schema.parse(await res.json());
  }
}

/** Maps over items with at most `limit` concurrent calls. */
export async function mapLimit<T, R>(items: T[], limit: number, fn: (item: T) => Promise<R>): Promise<R[]> {
  const results = new Array<R>(items.length);
  let next = 0;
  await Promise.all(
    Array.from({ length: Math.min(limit, items.length) }, async () => {
      while (next < items.length) {
        const i = next++;
        results[i] = await fn(items[i]);
      }
    }),
  );
  return results;
}
