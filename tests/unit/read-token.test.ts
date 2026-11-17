import { afterEach, describe, expect, test, vi } from 'vitest';
import { NextRequest } from 'next/server';
import { encode } from 'next-auth/jwt';
import { resetEnv } from '@/lib/env';
import { proxy } from '@/proxy';
import { requireOwner } from '@/server/auth';
import { checkRateLimit, resetRateLimits } from '@/server/api';
import { GET as authGet } from '@/app/api/auth/[...nextauth]/route';

vi.mock('next-auth', () => ({ default: () => new Response('{}', { status: 200 }) }));

const SECRET = 'test-secret-test-secret-test-secret';
const OWNER = '4242';
const BASE = 'http://dash.test';
const READ = 'read-token-one';

afterEach(() => {
  vi.unstubAllEnvs();
  resetEnv();
  resetRateLimits();
});

function configure(extra: Record<string, string> = {}) {
  vi.stubEnv('NEXTAUTH_SECRET', SECRET);
  vi.stubEnv('NEXTAUTH_URL', BASE);
  vi.stubEnv('GITHUB_CLIENT_ID', 'cid');
  vi.stubEnv('GITHUB_CLIENT_SECRET', 'csecret');
  vi.stubEnv('OWNER_GITHUB_ID', OWNER);
  vi.stubEnv('READ_TOKENS', `${READ}, read-token-two`);
  for (const [k, v] of Object.entries(extra)) {
    vi.stubEnv(k, v);
  }
  resetEnv();
}

const bearer = (t: string) => ({ authorization: `Bearer ${t}` });
const nreq = (path: string, init: { method?: string; headers?: Record<string, string> } = {}) => new NextRequest(`${BASE}${path}`, init);
const passed = (res: Response) => res.headers.get('x-middleware-next') === '1';

describe('requireOwner with READ_TOKENS', () => {
  const get = (headers: Record<string, string>, path = '/api/v1/projects', method = 'GET') =>
    requireOwner(new Request(`${BASE}${path}`, { method, headers }));

  test('a valid read token reads GET /api/v1/*, either configured token', async () => {
    configure();
    expect(await get(bearer(READ))).toBeNull();
    expect(await get(bearer('read-token-two'))).toBeNull();
  });

  test('a wrong token is 401', async () => {
    configure();
    expect((await get(bearer('nope')))?.status).toBe(401);
  });

  test('a token of a different length or a prefix of a real one is rejected', async () => {
    configure();
    expect((await get(bearer(READ.slice(0, -1))))?.status).toBe(401);
    expect((await get(bearer(`${READ}x`)))?.status).toBe(401);
  });

  test('no READ_TOKENS: a bearer is ignored and the session gate answers', async () => {
    configure({ READ_TOKENS: '' });
    expect((await get(bearer(READ)))?.status).toBe(401);
  });

  test('a read token never authorises a non-GET method or a path outside /api/v1/', async () => {
    configure();
    expect((await get(bearer(READ), '/api/v1/projects', 'POST'))?.status).toBe(401);
    expect((await get(bearer(READ), '/api/v1/projects/1', 'DELETE'))?.status).toBe(401);
    expect((await get(bearer(READ), '/api/v1x/projects'))?.status).toBe(401);
    expect((await get(bearer(READ), '/'))?.status).toBe(401);
  });

  test('fail-closed like the session gate: production with no auth config and no tokens is 503', async () => {
    vi.stubEnv('NODE_ENV', 'production');
    resetEnv();
    expect((await get(bearer(READ)))?.status).toBe(503);
  });

  test('a session cookie still works, and Authorization never stands in for it', async () => {
    configure();
    const jwt = await encode({ token: { sub: OWNER }, secret: SECRET, maxAge: 3600 });
    expect(await get({ cookie: `next-auth.session-token=${jwt}` })).toBeNull();
    // A session JWE in Authorization is neither a read token nor a session.
    expect((await get(bearer(jwt)))?.status).toBe(401);
  });

  test('failed attempts spend the auth bucket, checked before comparing, so guessing is throttled', async () => {
    configure({ AUTH_RATE_LIMIT: '2' });
    expect((await get(bearer('bad1')))?.status).toBe(401);
    expect((await get(bearer('bad2')))?.status).toBe(401);
    expect((await get(bearer('bad3')))?.status).toBe(429);
    // Throttled even for the right token while the window is spent.
    expect((await get(bearer(READ)))?.status).toBe(429);
  });

  test('failures do not touch the write bucket, and good requests do not spend the auth bucket', async () => {
    configure({ AUTH_RATE_LIMIT: '1', WRITE_RATE_LIMIT: '1' });
    expect(await get(bearer(READ))).toBeNull();
    expect(await get(bearer(READ))).toBeNull();
    expect((await get(bearer('bad')))?.status).toBe(401);
    expect(checkRateLimit(new Request(BASE), Date.now(), 'write')).toBeNull();
  });
});

describe('proxy with READ_TOKENS', () => {
  test('GET /api/v1/* with a valid bearer passes through', async () => {
    configure();
    expect(passed(await proxy(nreq('/api/v1/projects', { headers: bearer(READ) })))).toBe(true);
    expect(passed(await proxy(nreq('/api/v1/projects/', { headers: bearer(READ) })))).toBe(true);
  });

  test('a wrong bearer is a JSON 401', async () => {
    configure();
    const res = await proxy(nreq('/api/v1/projects', { headers: bearer('nope') }));
    expect(res.status).toBe(401);
  });

  test('wrong bearers are throttled in the auth bucket', async () => {
    configure({ AUTH_RATE_LIMIT: '1' });
    expect((await proxy(nreq('/api/v1/projects', { headers: bearer('a') }))).status).toBe(401);
    expect((await proxy(nreq('/api/v1/projects', { headers: bearer('b') }))).status).toBe(429);
  });

  test('a read token on a page is ignored: the page is redirected like any signed-out visit', async () => {
    configure();
    for (const path of ['/projects', '/vulnerabilities']) {
      const res = await proxy(nreq(path, { headers: bearer(READ) }));
      expect(passed(res)).toBe(false);
      expect(res.status).toBe(307);
    }
    expect((await proxy(nreq('/_next/data/x/projects.json', { headers: bearer(READ) }))).status).toBe(401);
  });

  test('a read token with a non-GET method gains nothing', async () => {
    configure();
    for (const method of ['POST', 'PUT', 'PATCH', 'DELETE']) {
      const res = await proxy(nreq('/api/v1/projects/1', { method, headers: bearer(READ) }));
      // The upload and delete routes keep their own bearer checks; everything else is the session gate.
      if (method === 'DELETE') {
        expect(passed(res)).toBe(true);
      } else {
        expect(res.status).toBe(401);
      }
    }
  });

  test('Authorization is never a session, even a real session JWT', async () => {
    configure();
    const jwt = await encode({ token: { sub: OWNER }, secret: SECRET, maxAge: 3600 });
    expect((await proxy(nreq('/api/v1/projects', { headers: bearer(jwt) }))).status).toBe(401);
  });

  test('/api/auth/* is not a read-token path: its calls spend the auth bucket', async () => {
    configure({ AUTH_RATE_LIMIT: '1' });
    const call = () =>
      authGet(
        nreq('/api/auth/session', { headers: bearer(READ) }) as never,
        { params: Promise.resolve({ nextauth: ['session'] }) } as never,
      );
    expect((await call()).status).toBe(200);
    expect((await call()).status).toBe(429);
  });

  test('no READ_TOKENS: bearer on GET /api/v1/* is 401 as before', async () => {
    configure({ READ_TOKENS: '' });
    expect((await proxy(nreq('/api/v1/projects', { headers: bearer(READ) }))).status).toBe(401);
  });
});
