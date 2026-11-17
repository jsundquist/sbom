import { describe, expect, it } from 'vitest';
import { z } from 'zod';
import { DashboardClient, DashboardError, type FetchFn } from '../src/client.js';

const config = { baseUrl: 'https://sbom.test', token: 'tok', timeoutMs: 50 };
const schema = z.object({ n: z.number() });
const json = (body: unknown, status = 200) => new Response(JSON.stringify(body), { status });

describe('DashboardClient', () => {
  it('sends a bearer GET to the base URL and returns the parsed body', async () => {
    const seen: { url: string; init?: RequestInit }[] = [];
    const fetchFn: FetchFn = async (url, init) => {
      seen.push({ url: String(url), init });
      return json({ n: 3 });
    };
    expect(await new DashboardClient(config, fetchFn).get('/api/v1/x', schema)).toEqual({ n: 3 });
    expect(seen[0].url).toBe('https://sbom.test/api/v1/x');
    expect(seen[0].init?.method).toBe('GET');
    expect(new Headers(seen[0].init?.headers).get('authorization')).toBe('Bearer tok');
  });

  it('rejects a body that does not match the schema', async () => {
    const client = new DashboardClient(config, async () => json({ n: 'three' }));
    await expect(client.get('/x', schema)).rejects.toThrow(/expected shape/);
  });

  it('reports the HTTP status but not the body', async () => {
    const client = new DashboardClient(config, async () => json({ error: 'secret detail' }, 401));
    const err = await client.get('/x', schema).catch((e: unknown) => e);
    expect(err).toBeInstanceOf(DashboardError);
    expect((err as DashboardError).status).toBe(401);
    expect(String(err)).not.toContain('secret detail');
  });

  it('aborts a request that outlives the timeout', async () => {
    const hang: FetchFn = (_url, init) =>
      new Promise((_resolve, reject) => {
        init?.signal?.addEventListener('abort', () => reject(init.signal?.reason));
      });
    await expect(new DashboardClient(config, hang).get('/x', schema)).rejects.toThrow(/timed out/);
  });

  it('wraps network failures without leaking the cause', async () => {
    const client = new DashboardClient(config, async () => {
      throw new TypeError('connect ECONNREFUSED 10.0.0.1');
    });
    await expect(client.get('/x', schema)).rejects.toThrow(/unreachable/);
  });
});
