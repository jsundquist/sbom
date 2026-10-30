import fs from 'node:fs';
import { expect, test, type BrowserContext } from '@playwright/test';
import { encode } from 'next-auth/jwt';
import { AUTH_E2E_OWNER_ID, AUTH_E2E_SECRET, AUTH_E2E_URL } from '../../playwright.config';

// Runs only in the "authed" project: the server has owner sign-in enabled and nothing here contacts GitHub.
// NEXTAUTH_URL is http, so the session cookie has no __Secure- prefix.
async function signInAs(context: BrowserContext, sub: string, login: string) {
  const value = await encode({ token: { sub, login }, secret: AUTH_E2E_SECRET, maxAge: 3600 });
  await context.addCookies([{ name: 'next-auth.session-token', value, url: AUTH_E2E_URL }]);
}

test('signed-out visitors see only the sign-in view and get 401 from the API', async ({ page, request }) => {
  await page.goto('/');
  await expect(page.getByRole('button', { name: 'Sign in with GitHub' })).toBeVisible();
  await expect(page.getByRole('heading', { name: 'Overview' })).toHaveCount(0);
  await expect(page.getByText('payments-api')).toHaveCount(0);

  expect((await request.get('/api/v1/summary')).status()).toBe(401);
});

test('a signed-in non-owner sees Access denied with their login and gets 403 from the API', async ({ page, context }) => {
  await signInAs(context, '999', 'mallory');
  await page.goto('/');
  await expect(page.getByRole('heading', { name: 'Access denied' })).toBeVisible();
  await expect(page.getByText('mallory')).toBeVisible();
  await expect(page.getByText('payments-api')).toHaveCount(0);

  expect((await context.request.get('/api/v1/summary')).status()).toBe(403);
});

test('the owner sees the dashboard and gets 200 from the API', async ({ page, context }) => {
  await signInAs(context, AUTH_E2E_OWNER_ID, 'owner');
  await page.goto('/');
  await expect(page.getByRole('heading', { name: 'Overview' })).toBeVisible();
  await expect(page.getByRole('button', { name: 'Sign in with GitHub' })).toHaveCount(0);

  expect((await context.request.get('/api/v1/summary')).status()).toBe(200);
});

test('uploads keep bearer-token auth without a session, and healthz is open', async ({ request }) => {
  const document = JSON.parse(fs.readFileSync('tests/fixtures/spdx.json', 'utf8'));
  const denied = await request.post('/api/v1/sboms?project=authed-upload&version=1.0.0', { data: document });
  expect(denied.status()).toBe(401);

  const ok = await request.post('/api/v1/sboms?project=authed-upload&version=1.0.0', {
    data: document,
    headers: { authorization: 'Bearer e2e-token' },
  });
  expect(ok.status()).toBe(201);

  expect((await request.get('/api/healthz')).status()).toBe(200);
});
