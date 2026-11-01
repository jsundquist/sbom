import { afterEach, describe, expect, test, vi } from 'vitest';
import { NextRequest } from 'next/server';
import { encode } from 'next-auth/jwt';
import { resetEnv } from '@/lib/env';
import { proxy } from '@/proxy';
import { GET as authGet } from '@/app/api/auth/[...nextauth]/route';
import { checkUploadToken, resetRateLimits } from '@/server/api';

// The real handler needs a Next request scope (cookies()); the limiter runs before it, which is what is under test.
vi.mock('next-auth', () => ({ default: () => new Response('{}', { status: 200 }) }));

const SECRET = 'test-secret-test-secret-test-secret';
const OWNER = '4242';
const BASE = 'http://dash.test';

afterEach(() => {
  vi.unstubAllEnvs();
  resetEnv();
});

function configure() {
  vi.stubEnv('NEXTAUTH_SECRET', SECRET);
  vi.stubEnv('NEXTAUTH_URL', BASE);
  vi.stubEnv('GITHUB_CLIENT_ID', 'cid');
  vi.stubEnv('GITHUB_CLIENT_SECRET', 'csecret');
  vi.stubEnv('OWNER_GITHUB_ID', OWNER);
  resetEnv();
}

async function cookieFor(sub: string) {
  const jwt = await encode({ token: { sub }, secret: SECRET, maxAge: 3600 });
  return `next-auth.session-token=${jwt}`;
}

function req(path: string, init: { method?: string; headers?: Record<string, string> } = {}) {
  return new NextRequest(`${BASE}${path}`, init);
}

/** NextResponse.next() marks a pass-through with this header. */
const passedThrough = (res: Response) => res.headers.get('x-middleware-next') === '1';

describe('proxy: gated API', () => {
  test('signed-out GET /api/v1/projects gets a JSON 401', async () => {
    configure();
    const res = await proxy(req('/api/v1/projects'));
    expect(res.status).toBe(401);
    expect(await res.json()).toEqual({ error: 'Sign in required' });
  });

  test('signed-in non-owner gets a JSON 403', async () => {
    configure();
    const res = await proxy(req('/api/v1/projects', { headers: { cookie: await cookieFor('1') } }));
    expect(res.status).toBe(403);
  });

  test('owner passes through', async () => {
    configure();
    const res = await proxy(req('/api/v1/projects', { headers: { cookie: await cookieFor(OWNER) } }));
    expect(passedThrough(res)).toBe(true);
  });

  test('a garbage cookie or malformed bearer header is a 401, not a throw', async () => {
    configure();
    const res = await proxy(
      req('/api/v1/projects', { headers: { cookie: 'next-auth.session-token=junk', authorization: 'Bearer %E0%A4%A' } }),
    );
    expect(res.status).toBe(401);
  });

  test('unknown /api paths are gated too, so route existence does not leak', async () => {
    configure();
    expect((await proxy(req('/api/v1/nope'))).status).toBe(401);
    expect((await proxy(req('/api/other'))).status).toBe(401);
  });
});

describe('proxy: pages', () => {
  // The AccessGate renders in place on every page URL and there is no sign-in route, so the only safe landing
  // spot is "/" itself: it must pass through (no loop) and every other non-owner page request is sent there.
  test('"/" passes through for signed-out and non-owner so the page can render its gate (no redirect loop)', async () => {
    configure();
    expect(passedThrough(await proxy(req('/')))).toBe(true);
    expect(passedThrough(await proxy(req('/', { headers: { cookie: await cookieFor('1') } })))).toBe(true);
  });

  test.each(['/projects', '/projects/7', '/packages', '/vulnerabilities', '/no/such/page'])(
    'signed-out %s redirects to "/" without revealing whether it exists',
    async (path) => {
      configure();
      const res = await proxy(req(`${path}?q=secret`));
      expect(res.status).toBe(307);
      expect(new URL(res.headers.get('location') ?? '').pathname).toBe('/');
      expect(new URL(res.headers.get('location') ?? '').search).toBe('');
    },
  );

  test('non-owner is redirected to "/" from a page, and the redirect target does not redirect again', async () => {
    configure();
    const headers = { cookie: await cookieFor('1') };
    const first = await proxy(req('/projects/7', { headers }));
    expect(first.status).toBe(307);
    const target = new URL(first.headers.get('location') ?? '');
    expect(passedThrough(await proxy(req(target.pathname, { headers })))).toBe(true);
  });

  test('owner reaches pages, including unknown ones (the app renders its own 404)', async () => {
    configure();
    const headers = { cookie: await cookieFor(OWNER) };
    expect(passedThrough(await proxy(req('/projects/7', { headers })))).toBe(true);
    expect(passedThrough(await proxy(req('/no/such/page', { headers })))).toBe(true);
  });

  test('a trailing slash does not dodge the gate', async () => {
    configure();
    expect((await proxy(req('/api/v1/projects/'))).status).toBe(401);
    expect((await proxy(req('/projects/'))).status).toBe(307);
  });
});

describe('proxy: unconfigured auth', () => {
  test('dev/test stays open by default', async () => {
    expect(passedThrough(await proxy(req('/api/v1/projects')))).toBe(true);
    expect(passedThrough(await proxy(req('/projects')))).toBe(true);
  });

  test('production without config answers 503 to gated API and page requests', async () => {
    vi.stubEnv('NODE_ENV', 'production');
    resetEnv();
    const api = await proxy(req('/api/v1/projects'));
    expect(api.status).toBe(503);
    expect((await api.json()).error).toMatch(/disabled/i);
    expect((await proxy(req('/'))).status).toBe(503);
    expect((await proxy(req('/projects'))).status).toBe(503);
    expect((await proxy(req('/api/v1/nope'))).status).toBe(503);
  });

  test('production without config still passes the open and bearer paths', async () => {
    vi.stubEnv('NODE_ENV', 'production');
    resetEnv();
    expect(passedThrough(await proxy(req('/api/healthz')))).toBe(true);
    expect(passedThrough(await proxy(req('/api/livez')))).toBe(true);
    expect(passedThrough(await proxy(req('/api/v1/sboms', { method: 'POST' })))).toBe(true);
  });

  test('ALLOW_OPEN_READS=true opts out in production', async () => {
    vi.stubEnv('NODE_ENV', 'production');
    vi.stubEnv('ALLOW_OPEN_READS', 'true');
    resetEnv();
    expect(passedThrough(await proxy(req('/api/v1/projects')))).toBe(true);
    expect(passedThrough(await proxy(req('/projects')))).toBe(true);
  });
});

describe('auth routes rate limit', () => {
  test('the next-auth handler is limited, and the proxy does not spend that budget', async () => {
    configure();
    vi.stubEnv('AUTH_RATE_LIMIT', '2');
    resetEnv();
    resetRateLimits();
    for (let i = 0; i < 5; i++) {
      expect(passedThrough(await proxy(req('/api/auth/providers')))).toBe(true);
    }
    const call = () => authGet(req('/api/auth/providers'), { params: Promise.resolve({ nextauth: ['providers'] }) });
    expect((await call()).status).toBe(200);
    expect((await call()).status).toBe(200);
    const limited = await call();
    expect(limited.status).toBe(429);
    expect(limited.headers.get('retry-after')).toBeTruthy();
    resetRateLimits();
  });
});

describe('auth rate limit bucket', () => {
  test('hammering /api/auth/* never makes uploads or deletes return 429', async () => {
    configure();
    vi.stubEnv('WRITE_RATE_LIMIT', '2');
    vi.stubEnv('AUTH_RATE_LIMIT', '100');
    resetEnv();
    resetRateLimits();
    const call = () => authGet(req('/api/auth/csrf'), { params: Promise.resolve({ nextauth: ['csrf'] }) });
    for (let i = 0; i < 150; i++) {
      await call();
    }
    expect((await call()).status).toBe(429);
    expect(checkUploadToken(new Request(`${BASE}/api/v1/sboms`, { method: 'POST' }))).toBeNull();
    resetRateLimits();
  });
});

describe('proxy: open paths (no session needed)', () => {
  test.each([
    ['GET', '/api/auth/session'],
    ['POST', '/api/auth/signin/github'],
    ['GET', '/api/healthz'],
    ['GET', '/api/livez'],
    ['GET', '/_next/static/chunks/app.js'],
    ['GET', '/_next/image'],
    ['GET', '/icon.svg'],
    ['POST', '/api/v1/sboms'],
    ['DELETE', '/api/v1/projects/12'],
  ])('%s %s passes through when signed out', async (method, path) => {
    configure();
    expect(passedThrough(await proxy(req(path, { method })))).toBe(true);
  });

  test.each([
    ['GET', '/api/v1/sboms'],
    ['GET', '/api/v1/projects/12'],
    ['PUT', '/api/v1/sboms'],
    ['POST', '/api/v1/projects/12'],
    ['DELETE', '/api/v1/projects'],
    ['DELETE', '/api/v1/projects/12/dependencies'],
    ['DELETE', '/api/v1/sboms/1'],
    ['GET', '/api/healthz/extra'],
    ['GET', '/api/livez/extra'],
    ['GET', '/api/authx'],
    ['GET', '/_next/data/build/index.json'],
    ['GET', '/icon.svg.map'],
  ])('%s %s is still gated even with a bearer header', async (method, path) => {
    configure();
    const res = await proxy(req(path, { method, headers: { authorization: 'Bearer anything' } }));
    expect(res.status).toBe(401);
  });
});
