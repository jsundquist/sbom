import type { z } from 'zod';
import type { Config } from './config.js';

export type FetchFn = typeof fetch;

export class DashboardError extends Error {
  constructor(
    message: string,
    readonly status?: number,
  ) {
    super(message);
    this.name = 'DashboardError';
  }
}

/** GET-only client for /api/v1: bearer read token (ADR 0002), a timeout, and every body checked by a Zod schema. */
export class DashboardClient {
  constructor(
    private readonly config: Config,
    private readonly fetchFn: FetchFn = fetch,
  ) {}

  async get<S extends z.ZodType>(path: string, schema: S): Promise<z.infer<S>> {
    let res: Response;
    try {
      res = await this.fetchFn(`${this.config.baseUrl}${path}`, {
        method: 'GET',
        headers: { Authorization: `Bearer ${this.config.token}`, Accept: 'application/json' },
        signal: AbortSignal.timeout(this.config.timeoutMs),
      });
    } catch (e) {
      const timedOut = e instanceof Error && (e.name === 'TimeoutError' || e.name === 'AbortError');
      // The underlying error can carry hosts and addresses; the agent gets a fixed message.
      throw new DashboardError(timedOut ? `Dashboard timed out after ${this.config.timeoutMs} ms` : 'Dashboard unreachable');
    }
    if (!res.ok) {
      // Status only: the body is not forwarded to the agent.
      throw new DashboardError(`Dashboard answered HTTP ${res.status}`, res.status);
    }
    let body: unknown;
    try {
      body = await res.json();
    } catch {
      throw new DashboardError('Dashboard answered with a body that is not JSON', res.status);
    }
    const parsed = schema.safeParse(body);
    if (!parsed.success) {
      throw new DashboardError('Dashboard response did not match the expected shape', res.status);
    }
    return parsed.data;
  }
}
