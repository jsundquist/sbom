import fs from 'node:fs';
import path from 'node:path';
import { createElement } from 'react';
import { renderToStaticMarkup } from 'react-dom/server';
import { afterEach, beforeEach, describe, expect, test, vi } from 'vitest';
import { encode } from 'next-auth/jwt';
import { setDb } from '@/db';
import { resetEnv } from '@/lib/env';
import { requireOwnerPage } from '@/server/auth';
import { AccessGate } from '@/components/AccessGate';
import { createTestDb } from './helpers';

const headerStore = vi.hoisted(() => ({ current: new Headers() }));
vi.mock('next/headers', () => ({ headers: async () => headerStore.current }));

import Overview from '@/app/page';
import Projects from '@/app/projects/page';
import Project from '@/app/projects/[id]/page';
import Packages from '@/app/packages/page';
import Package from '@/app/packages/[key]/page';
import Vulns from '@/app/vulnerabilities/page';
import Vuln from '@/app/vulnerabilities/[id]/page';

const SECRET = 'test-secret-test-secret-test-secret';
const OWNER = '4242';
let close: () => Promise<void>;

beforeEach(async () => {
  const t = await createTestDb();
  close = t.close;
  setDb(t.db);
  headerStore.current = new Headers();
});
afterEach(async () => {
  vi.unstubAllEnvs();
  resetEnv();
  await close();
});

function configure() {
  vi.stubEnv('NEXTAUTH_SECRET', SECRET);
  vi.stubEnv('NEXTAUTH_URL', 'http://dash.test');
  vi.stubEnv('GITHUB_CLIENT_ID', 'cid');
  vi.stubEnv('GITHUB_CLIENT_SECRET', 'csecret');
  vi.stubEnv('OWNER_GITHUB_ID', OWNER);
  resetEnv();
}

async function signInAs(sub: string, login?: string) {
  const jwt = await encode({ token: { sub, login }, secret: SECRET, maxAge: 3600 });
  headerStore.current = new Headers({ cookie: `next-auth.session-token=${jwt}` });
}

describe('requireOwnerPage', () => {
  test('open by default in dev/test', async () => {
    expect(await requireOwnerPage()).toBeNull();
  });

  test('configured: signed-out, non-owner (with login), owner', async () => {
    configure();
    expect(await requireOwnerPage()).toEqual({ kind: 'sign-in' });
    await signInAs('999', 'mallory');
    expect(await requireOwnerPage()).toEqual({ kind: 'denied', login: 'mallory' });
    await signInAs(OWNER, 'me');
    expect(await requireOwnerPage()).toBeNull();
  });

  test('production without auth config is unavailable; ALLOW_OPEN_READS opens it', async () => {
    vi.stubEnv('NODE_ENV', 'production');
    resetEnv();
    expect(await requireOwnerPage()).toEqual({ kind: 'unavailable' });
    vi.stubEnv('ALLOW_OPEN_READS', 'true');
    resetEnv();
    expect(await requireOwnerPage()).toBeNull();
  });
});

const p = <T>(v: T) => Promise.resolve(v);
const PAGES: [string, () => Promise<unknown>][] = [
  ['/', () => Overview()],
  ['/projects', () => Projects()],
  ['/projects/[id]', () => Project({ params: p({ id: '1' }), searchParams: p({}) })],
  ['/packages', () => Packages()],
  ['/packages/[key]', () => Package({ params: p({ key: 'npm:x' }) })],
  ['/vulnerabilities', () => Vulns()],
  ['/vulnerabilities/[id]', () => Vuln({ params: p({ id: 'GHSA-x' }) })],
];

describe.each(PAGES)('page %s', (_name, render) => {
  const gateOf = (el: unknown) => {
    const e = el as { type?: unknown; props?: { gate?: unknown } };
    return e.type === AccessGate ? e.props?.gate : undefined;
  };

  test('signed-out renders the sign-in gate, not data', async () => {
    configure();
    expect(gateOf(await render())).toEqual({ kind: 'sign-in' });
  });

  test('non-owner renders the denied gate with their login', async () => {
    configure();
    await signInAs('999', 'mallory');
    expect(gateOf(await render())).toEqual({ kind: 'denied', login: 'mallory' });
  });
});

describe('AccessGate', () => {
  const html = (gate: Parameters<typeof AccessGate>[0]['gate']) => renderToStaticMarkup(createElement(AccessGate, { gate }));

  test('sign-in: one GitHub button, no links, no hint of app contents', () => {
    const out = html({ kind: 'sign-in' });
    expect(out).toContain('Sign in with GitHub');
    expect(out.match(/<button/g)).toHaveLength(1);
    expect(out).not.toContain('<a ');
    expect(out).not.toMatch(/SBOM|vulnerab|package|application/i);
  });

  test('denied: shows the login and a sign-out link, no sign-in button', () => {
    const out = html({ kind: 'denied', login: 'mallory' });
    expect(out).toContain('Access denied');
    expect(out).toContain('mallory');
    expect(out).toContain('href="/api/auth/signout"');
    expect(out).not.toContain('<button');
  });

  test('unavailable: explains reads are disabled', () => {
    expect(html({ kind: 'unavailable' })).toContain('disabled');
  });
});

describe('guard coverage', () => {
  const root = path.resolve(import.meta.dirname, '../../src/app');
  const files = (name: string, dir = root): string[] =>
    fs.readdirSync(dir, { withFileTypes: true }).flatMap((d) => {
      const full = path.join(dir, d.name);
      if (d.isDirectory()) {
        return files(name, full);
      }
      return d.name === name ? [full] : [];
    });
  const rel = (f: string) => path.relative(root, f).split(path.sep).join('/');

  // Routes that are deliberately not owner-gated, each with the reason.
  const ALLOW: Record<string, string> = {
    'api/auth/[...nextauth]/route.ts': 'next-auth endpoints',
    'api/healthz/route.ts': 'liveness probe',
    'api/v1/sboms/route.ts': 'bearer-token upload (POST only)',
  };

  test('finds the expected number of pages and routes (guards against a broken walk)', () => {
    expect(files('page.tsx').length).toBeGreaterThanOrEqual(7);
    expect(files('route.ts').length).toBeGreaterThanOrEqual(12);
  });

  test.each(files('page.tsx').map(rel))('page %s calls requireOwnerPage()', (f) => {
    expect(fs.readFileSync(path.join(root, f), 'utf8')).toMatch(/await requireOwnerPage\(\)/);
  });

  test.each(files('route.ts').map(rel))('route %s calls requireOwner() or is allow-listed', (f) => {
    if (ALLOW[f]) {
      return;
    }
    expect(fs.readFileSync(path.join(root, f), 'utf8')).toMatch(/await requireOwner\(/);
  });

  test('the bearer-only upload route exports no GET; DELETE /projects/[id] sits beside a guarded GET', () => {
    const upload = fs.readFileSync(path.join(root, 'api/v1/sboms/route.ts'), 'utf8');
    expect(upload).not.toMatch(/export (async )?function GET|export \{[^}]*\bGET\b/);
    const proj = fs.readFileSync(path.join(root, 'api/v1/projects/[id]/route.ts'), 'utf8');
    expect(proj).toMatch(/export async function DELETE/);
    expect(proj).toMatch(/await requireOwner\(/);
  });

  test('allow-list has no stale entries', () => {
    const all = files('route.ts').map(rel);
    for (const k of Object.keys(ALLOW)) {
      expect(all).toContain(k);
    }
  });
});
