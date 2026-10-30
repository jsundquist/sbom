import { afterEach, beforeEach, describe, expect, test, vi } from 'vitest';
import { NextRequest } from 'next/server';
import { encode } from 'next-auth/jwt';
import { setDb } from '@/db';
import { resetEnv } from '@/lib/env';
import { GET as listProjects } from '@/app/api/v1/projects/route';
import { GET as getProject } from '@/app/api/v1/projects/[id]/route';
import { GET as getDeps } from '@/app/api/v1/projects/[id]/dependencies/route';
import { GET as listPackages } from '@/app/api/v1/packages/route';
import { GET as getPackage } from '@/app/api/v1/packages/[key]/route';
import { GET as listVulns } from '@/app/api/v1/vulnerabilities/route';
import { GET as getVuln } from '@/app/api/v1/vulnerabilities/[id]/route';
import { GET as getSummary } from '@/app/api/v1/summary/route';
import { GET as getSbom } from '@/app/api/v1/sboms/[id]/route';
import { GET as healthz } from '@/app/api/healthz/route';
import { createTestDb } from './helpers';

const SECRET = 'test-secret-test-secret-test-secret';
const OWNER = '4242';
const BASE = 'http://dash.test';
let close: () => Promise<void>;

beforeEach(async () => {
  const t = await createTestDb();
  close = t.close;
  setDb(t.db);
});
afterEach(async () => {
  vi.unstubAllEnvs();
  resetEnv();
  await close();
});

function configure() {
  vi.stubEnv('NEXTAUTH_SECRET', SECRET);
  vi.stubEnv('NEXTAUTH_URL', BASE);
  vi.stubEnv('GITHUB_CLIENT_ID', 'cid');
  vi.stubEnv('GITHUB_CLIENT_SECRET', 'csecret');
  vi.stubEnv('OWNER_GITHUB_ID', OWNER);
  resetEnv();
}

async function session(sub: string) {
  const jwt = await encode({ token: { sub }, secret: SECRET, maxAge: 3600 });
  return { cookie: `next-auth.session-token=${jwt}` };
}

const p = <T>(v: T) => ({ params: Promise.resolve(v) });
const ROUTES: [string, (req: Request) => Promise<Response>][] = [
  ['projects', (r) => listProjects(r)],
  ['projects/:id', (r) => getProject(r, p({ id: '1' }))],
  ['projects/:id/dependencies', (r) => getDeps(r, p({ id: '1' }))],
  ['packages', (r) => listPackages(r)],
  ['packages/:key', (r) => getPackage(r, p({ key: 'npm:lodash' }))],
  ['vulnerabilities', (r) => listVulns(r)],
  ['vulnerabilities/:id', (r) => getVuln(r, p({ id: 'GHSA-x' }))],
  ['summary', (r) => getSummary(r)],
  ['sboms/:id', (r) => getSbom(r, p({ id: '1' }))],
];

describe.each(ROUTES)('GET /api/v1/%s', (_name, call) => {
  const req = (headers: Record<string, string> = {}) => new Request(`${BASE}/api/v1/x`, { headers });

  test('open by default in dev/test', async () => {
    expect((await call(req())).status).not.toBe(401);
    expect((await call(req())).status).not.toBe(503);
  });

  test('with auth configured: no session 401, non-owner 403, owner passes the guard', async () => {
    configure();
    expect((await call(req())).status).toBe(401);
    expect((await call(req(await session('999')))).status).toBe(403);
    const owner = await call(req(await session(OWNER)));
    expect([401, 403, 503]).not.toContain(owner.status);
  });

  test('production without auth config: 503; ALLOW_OPEN_READS=true opens it', async () => {
    vi.stubEnv('NODE_ENV', 'production');
    resetEnv();
    expect((await call(req())).status).toBe(503);
    vi.stubEnv('ALLOW_OPEN_READS', 'true');
    resetEnv();
    expect([401, 403, 503]).not.toContain((await call(req())).status);
  });
});

test('summary returns data for the owner', async () => {
  configure();
  const res = await getSummary(new Request(`${BASE}/api/v1/summary`, { headers: await session(OWNER) }));
  expect(res.status).toBe(200);
});

// Next hands route handlers a NextRequest; wrapping one in another NextRequest threw at runtime.
test('summary accepts a NextRequest from the owner', async () => {
  configure();
  const res = await getSummary(new NextRequest(`${BASE}/api/v1/summary`, { headers: await session(OWNER) }));
  expect(res.status).toBe(200);
});

test('healthz stays open with auth configured', async () => {
  configure();
  expect((await healthz()).status).toBe(200);
});
