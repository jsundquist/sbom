import { headers } from 'next/headers';
import { NextRequest, NextResponse } from 'next/server';
import type { NextAuthOptions } from 'next-auth';
import { getToken } from 'next-auth/jwt';
import GithubProvider from 'next-auth/providers/github';
import { env } from '@/lib/env';

const SESSION_SECONDS = 7 * 24 * 3600;
const GITHUB_API = 'https://api.github.com';
const GITHUB_OAUTH = 'https://github.com/login/oauth';

/** Same shape as the worker's FetchFn; redeclared because server/ may not import worker/. */
export type FetchFn = typeof fetch;

const deny = (status: number, error: string) => NextResponse.json({ error }, { status });

/** True when every setting needed for owner-only sign-in is present. */
export function authConfigured(): boolean {
  const e = env();
  return Boolean(e.OWNER_GITHUB_ID && e.NEXTAUTH_SECRET && e.NEXTAUTH_URL && e.GITHUB_CLIENT_ID && e.GITHUB_CLIENT_SECRET);
}

/** Empty owner id means nobody. Compared as strings; GitHub ids are int64 numbers in the API. */
export function isOwner(id: unknown): boolean {
  const owner = env().OWNER_GITHUB_ID;
  return owner !== '' && id !== undefined && id !== null && String(id) === owner;
}

/**
 * Egress exception (ADR 0001): the only outbound HTTP from the web app. Fetches the signed-in GitHub profile
 * through the injectable fetch so tests never hit the network.
 */
export async function githubUserinfo(fetchFn: FetchFn, accessToken: string): Promise<Record<string, unknown>> {
  const res = await fetchFn(`${GITHUB_API}/user`, {
    headers: { authorization: `Bearer ${accessToken}`, accept: 'application/vnd.github+json', 'user-agent': 'sbom-dashboard' },
    signal: AbortSignal.timeout(10_000),
  });
  if (!res.ok) {
    throw new Error(`GitHub /user returned ${res.status}`);
  }
  return (await res.json()) as Record<string, unknown>;
}

async function githubToken(fetchFn: FetchFn, code: string, redirectUri: string | undefined) {
  const e = env();
  const res = await fetchFn(`${GITHUB_OAUTH}/access_token`, {
    method: 'POST',
    headers: { accept: 'application/json', 'content-type': 'application/json', 'user-agent': 'sbom-dashboard' },
    body: JSON.stringify({ client_id: e.GITHUB_CLIENT_ID, client_secret: e.GITHUB_CLIENT_SECRET, code, redirect_uri: redirectUri }),
    signal: AbortSignal.timeout(10_000),
  });
  if (!res.ok) {
    throw new Error(`GitHub token exchange returned ${res.status}`);
  }
  return (await res.json()) as { access_token?: string; token_type?: string; scope?: string; error?: string };
}

/**
 * next-auth v4 options. v4 reads the public URL only from process.env, so the one deliberate
 * process.env write lives here (assigned from env()); AUTH_TRUST_HOST is never set so Host headers are not trusted.
 * Both session.maxAge and jwt.maxAge are set because jwt.maxAge otherwise defaults to 30 days.
 */
export function authOptions(fetchFn: FetchFn = fetch): NextAuthOptions {
  const e = env();
  if (e.NEXTAUTH_URL) {
    process.env.NEXTAUTH_URL = e.NEXTAUTH_URL;
  }
  return {
    secret: e.NEXTAUTH_SECRET,
    session: { strategy: 'jwt', maxAge: SESSION_SECONDS },
    jwt: { maxAge: SESSION_SECONDS },
    providers: [
      GithubProvider({
        clientId: e.GITHUB_CLIENT_ID,
        clientSecret: e.GITHUB_CLIENT_SECRET,
        token: {
          url: `${GITHUB_OAUTH}/access_token`,
          async request({ params, provider }) {
            const code = typeof params.code === 'string' ? params.code : '';
            const redirect = typeof provider.callbackUrl === 'string' ? provider.callbackUrl : undefined;
            const body = await githubToken(fetchFn, code, redirect);
            if (!body.access_token) {
              throw new Error(`GitHub token exchange failed: ${body.error ?? 'no access token'}`);
            }
            return { tokens: { access_token: body.access_token, token_type: body.token_type ?? 'bearer', scope: body.scope } };
          },
        },
        userinfo: {
          url: `${GITHUB_API}/user`,
          async request({ tokens }) {
            return githubUserinfo(fetchFn, String(tokens.access_token));
          },
        },
      }),
    ],
    callbacks: {
      // Any GitHub account may sign in so a non-owner gets the Access denied page with their login; the owner
      // check happens on every request (ownerState). Nothing is stored beyond the JWT cookie.
      signIn: ({ account, profile }) => {
        const id = (profile as { id?: unknown } | undefined)?.id;
        return account?.provider === 'github' && id !== undefined && id !== null && String(id) !== '';
      },
      jwt: ({ token, profile }) => {
        const login = (profile as { login?: unknown } | undefined)?.login;
        if (typeof login === 'string') {
          token.login = login;
        }
        return token;
      },
    },
  };
}

export type OwnerState =
  { state: 'open' } | { state: 'unavailable' } | { state: 'signed-out' } | { state: 'denied'; login?: string } | { state: 'owner' };

/**
 * The one owner decision shared by API routes and pages. Auth fully configured: signed-out, non-owner (id re-checked
 * against current config each request) or owner. Not configured: open in dev/test, unavailable in production unless
 * ALLOW_OPEN_READS=true.
 */
export async function ownerState(req: Request): Promise<OwnerState> {
  const e = env();
  if (!authConfigured()) {
    return e.NODE_ENV === 'production' && !e.ALLOW_OPEN_READS ? { state: 'unavailable' } : { state: 'open' };
  }
  // NextRequest parses the Cookie header into req.cookies, which getToken reads.
  const token = await getToken({
    req: new NextRequest(req),
    secret: e.NEXTAUTH_SECRET,
    secureCookie: e.NEXTAUTH_URL.startsWith('https://'),
  }).catch(() => null);
  if (!token?.sub) {
    return { state: 'signed-out' };
  }
  if (!isOwner(token.sub)) {
    return { state: 'denied', login: typeof token.login === 'string' ? token.login : undefined };
  }
  return { state: 'owner' };
}

/** Guard for every GET handler. Returns an error response (401, 403, or 503 when unavailable), or null when the caller may read. */
export async function requireOwner(req: Request): Promise<NextResponse | null> {
  const s = await ownerState(req);
  switch (s.state) {
    case 'unavailable':
      return deny(503, 'Reads are disabled: configure owner sign-in (or ALLOW_OPEN_READS=true for local use)');
    case 'signed-out':
      return deny(401, 'Sign in required');
    case 'denied':
      return deny(403, 'Access denied');
    default:
      return null;
  }
}

/** What a gated page renders instead of its content. Plain data so components can import the type only. */
export type PageGate = { kind: 'sign-in' } | { kind: 'denied'; login?: string } | { kind: 'unavailable' };

/** Page counterpart of requireOwner(): null when the viewer may see the page, else the gate to render. Call first. */
export async function requireOwnerPage(): Promise<PageGate | null> {
  const s = await ownerState(new Request('http://page.local/', { headers: await headers() }));
  switch (s.state) {
    case 'unavailable':
      return { kind: 'unavailable' };
    case 'signed-out':
      return { kind: 'sign-in' };
    case 'denied':
      return { kind: 'denied', login: s.login };
    default:
      return null;
  }
}
