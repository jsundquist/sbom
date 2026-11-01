import { afterEach, beforeEach, describe, expect, test, vi } from 'vitest';
import { encode } from 'next-auth/jwt';
import { resetEnv } from '@/lib/env';
import { authOptions, githubUserinfo, requireOwner } from '@/server/auth';

const SECRET = 'test-secret-test-secret-test-secret';
const OWNER = '4242';
const CONFIG = {
  NEXTAUTH_SECRET: SECRET,
  NEXTAUTH_URL: 'http://dash.test',
  GITHUB_CLIENT_ID: 'cid',
  GITHUB_CLIENT_SECRET: 'csecret',
  OWNER_GITHUB_ID: OWNER,
};

function configure(extra: Record<string, string> = {}) {
  for (const [k, v] of Object.entries({ ...CONFIG, ...extra })) {
    vi.stubEnv(k, v);
  }
  resetEnv();
}

async function reqWith(sub?: string, cookieName = 'next-auth.session-token') {
  const headers: Record<string, string> = {};
  if (sub !== undefined) {
    const jwt = await encode({ token: { sub }, secret: SECRET, maxAge: 3600 });
    headers.cookie = `${cookieName}=${jwt}`;
  }
  return new Request('http://dash.test/api/v1/summary', { headers });
}

afterEach(() => {
  vi.unstubAllEnvs();
  resetEnv();
});

describe('requireOwner with auth configured', () => {
  beforeEach(() => configure());

  test('no session -> 401', async () => {
    expect((await requireOwner(await reqWith()))?.status).toBe(401);
  });

  test('garbage cookie -> 401', async () => {
    const req = new Request('http://dash.test/x', { headers: { cookie: 'next-auth.session-token=nope' } });
    expect((await requireOwner(req))?.status).toBe(401);
  });

  test('cookie signed with another secret -> 401', async () => {
    const jwt = await encode({ token: { sub: OWNER }, secret: 'another-secret-another-secret-12345' });
    const req = new Request('http://dash.test/x', { headers: { cookie: `next-auth.session-token=${jwt}` } });
    expect((await requireOwner(req))?.status).toBe(401);
  });

  test('non-owner -> 403', async () => {
    expect((await requireOwner(await reqWith('999')))?.status).toBe(403);
  });

  test('owner -> allowed', async () => {
    expect(await requireOwner(await reqWith(OWNER))).toBeNull();
  });

  test('owner id is re-checked against current config on every request', async () => {
    const req = await reqWith(OWNER);
    expect(await requireOwner(req)).toBeNull();
    configure({ OWNER_GITHUB_ID: '7' });
    expect((await requireOwner(req))?.status).toBe(403);
  });

  test('an Authorization: Bearer session token is ignored; sessions travel only in the cookie', async () => {
    const jwt = await encode({ token: { sub: OWNER }, secret: SECRET, maxAge: 3600 });
    const req = new Request('http://dash.test/x', { headers: { authorization: `Bearer ${jwt}` } });
    expect((await requireOwner(req))?.status).toBe(401);
  });

  test('https NEXTAUTH_URL reads the __Secure- cookie only', async () => {
    configure({ NEXTAUTH_URL: 'https://dash.test' });
    expect((await requireOwner(await reqWith(OWNER)))?.status).toBe(401);
    expect(await requireOwner(await reqWith(OWNER, '__Secure-next-auth.session-token'))).toBeNull();
  });
});

describe('requireOwner without full auth config', () => {
  test('dev/test is open by default', async () => {
    vi.stubEnv('NODE_ENV', 'test');
    resetEnv();
    expect(await requireOwner(await reqWith())).toBeNull();
  });

  test.each(['OWNER_GITHUB_ID', 'NEXTAUTH_SECRET', 'NEXTAUTH_URL', 'GITHUB_CLIENT_ID', 'GITHUB_CLIENT_SECRET'])(
    'production missing %s -> 503, even with a valid owner cookie',
    async (missing) => {
      configure({ NODE_ENV: 'production', [missing]: '' });
      expect((await requireOwner(await reqWith(OWNER)))?.status).toBe(503);
    },
  );

  test.each([
    ['one-character secret', { NEXTAUTH_SECRET: 'x' }],
    ['31-character secret', { NEXTAUTH_SECRET: 'x'.repeat(31) }],
    ['URL that is not http(s)', { NEXTAUTH_URL: 'ftp://dash.test' }],
    ['URL that is not a URL', { NEXTAUTH_URL: 'dash.test' }],
  ])('production with a %s -> 503, even with a cookie forged using that secret', async (_name, extra) => {
    configure({ NODE_ENV: 'production', ...extra });
    const secret = 'NEXTAUTH_SECRET' in extra ? extra.NEXTAUTH_SECRET : SECRET;
    const jwt = await encode({ token: { sub: OWNER }, secret, maxAge: 3600 });
    const req = new Request('http://dash.test/x', { headers: { cookie: `next-auth.session-token=${jwt}` } });
    expect((await requireOwner(req))?.status).toBe(503);
  });

  test('a 32-character secret is accepted', async () => {
    configure({ NEXTAUTH_SECRET: 'y'.repeat(32) });
    expect((await requireOwner(await reqWith()))?.status).toBe(401);
  });

  test('production with ALLOW_OPEN_READS=true is open', async () => {
    vi.stubEnv('NODE_ENV', 'production');
    vi.stubEnv('ALLOW_OPEN_READS', 'true');
    resetEnv();
    expect(await requireOwner(await reqWith())).toBeNull();
  });
});

describe('authOptions', () => {
  beforeEach(() => configure());

  test('session and jwt both expire after 7 days, stateless', () => {
    const o = authOptions();
    expect(o.session).toMatchObject({ strategy: 'jwt', maxAge: 604800 });
    expect(o.jwt?.maxAge).toBe(604800);
    expect(o.secret).toBe(SECRET);
  });

  test('NEXTAUTH_URL is assigned from env() and AUTH_TRUST_HOST is never set', () => {
    delete process.env.AUTH_TRUST_HOST;
    authOptions();
    expect(process.env.NEXTAUTH_URL).toBe('http://dash.test');
    expect(process.env.AUTH_TRUST_HOST).toBeUndefined();
  });

  test('signIn lets any GitHub account with an id through (non-owners get the Access denied page), nothing else', async () => {
    const signIn = authOptions().callbacks!.signIn!;
    const call = (provider: string, id: unknown) => signIn({ account: { provider } as never, profile: { id } as never, user: {} as never });
    expect(await call('github', 4242)).toBe(true);
    expect(await call('github', 4243)).toBe(true);
    expect(await call('github', undefined)).toBe(false);
    expect(await call('github', '')).toBe(false);
    expect(await call('other', 4242)).toBe(false);
  });

  test('jwt callback keeps the GitHub login on sign-in so the denied page can show it', async () => {
    const jwt = authOptions().callbacks!.jwt!;
    const out = await jwt({
      token: { sub: '9' },
      profile: { id: 9, login: 'mallory' } as never,
      account: { provider: 'github' } as never,
      user: {} as never,
    });
    expect(out.login).toBe('mallory');
    const first = await jwt({
      token: {},
      profile: { id: 4242, login: 'x' } as never,
      account: { provider: 'github' } as never,
      user: {} as never,
    });
    expect(first.sub).toBe('4242');
    const later = await jwt({ token: { sub: '9', login: 'mallory' }, user: {} as never, account: null });
    expect(later.login).toBe('mallory');
  });
});

describe('GitHub egress', () => {
  test('userinfo goes through the injected fetch with the access token', async () => {
    const calls: { url: string; auth: string | null }[] = [];
    const fake = (async (url: string | URL | Request, init?: RequestInit) => {
      calls.push({ url: String(url), auth: new Headers(init?.headers).get('authorization') });
      return new Response(JSON.stringify({ id: 4242, login: 'me' }), { headers: { 'content-type': 'application/json' } });
    }) as typeof fetch;
    const profile = await githubUserinfo(fake, 'tok');
    expect(profile).toEqual({ id: 4242, login: 'me' });
    expect(calls).toEqual([{ url: 'https://api.github.com/user', auth: 'Bearer tok' }]);
  });

  test('userinfo failure throws', async () => {
    const fake = (async () => new Response('no', { status: 401 })) as typeof fetch;
    await expect(githubUserinfo(fake, 'tok')).rejects.toThrow();
  });
});
