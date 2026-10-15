import fs from 'node:fs';
import { expect, test } from '@playwright/test';

test('overview summarizes applications, vulnerabilities and outdated packages', async ({ page }) => {
  await page.goto('/');
  await expect(page.getByRole('heading', { name: 'Overview' })).toBeVisible();
  await expect(page.getByText('Applications', { exact: true }).first()).toBeVisible();
  await expect(page.getByRole('heading', { name: 'Vulnerabilities by severity' })).toBeVisible();
  await expect(page.getByRole('heading', { name: 'Most exposed applications' })).toBeVisible();
  // payments-api has the critical Log4j CVE, so it sorts first.
  const firstRow = page.getByRole('grid', { name: 'Applications' }).getByRole('row').nth(1);
  await expect(firstRow).toContainText('payments-api');
  await expect(firstRow).toContainText('Critical 1');
});

test('application page lists packages and filters to vulnerable ones', async ({ page }) => {
  await page.goto('/projects');
  await page.getByRole('link', { name: 'web-storefront' }).click();
  await expect(page.getByRole('heading', { name: 'web-storefront' })).toBeVisible();
  const grid = page.getByRole('grid', { name: 'Packages' });
  await expect(grid.getByRole('row')).toHaveCount(8); // header + 7 packages

  await page.getByRole('button', { name: /^Vulnerable/ }).click();
  await expect(grid.getByRole('row')).toHaveCount(3);
  await expect(grid).toContainText('lodash');
  await expect(grid).toContainText('axios');

  await page.getByRole('button', { name: /^Outdated/ }).click();
  await expect(grid).toContainText('major update');
});

test('package page shows which applications use each version', async ({ page }) => {
  await page.goto('/packages');
  await page.getByRole('button', { name: /^Used by 2\+ apps/ }).click();
  await page.getByRole('link', { name: 'lodash', exact: true }).click();
  await expect(page.getByRole('heading', { name: 'lodash' })).toBeVisible();
  const versions = page.getByRole('grid', { name: 'Versions in use' });
  await expect(versions).toContainText('4.17.15');
  await expect(versions).toContainText('web-storefront');
  await expect(versions).toContainText('inventory-service');
  await expect(page.getByRole('grid', { name: 'Vulnerabilities' })).toContainText('CVE-2020-8203');
});

test('vulnerability detail links affected packages and applications', async ({ page }) => {
  await page.goto('/vulnerabilities');
  await page.getByRole('link', { name: 'CVE-2021-44228' }).click();
  await expect(page.getByRole('heading', { name: 'CVE-2021-44228' })).toBeVisible();
  await expect(page.getByText('Critical 10.0')).toBeVisible();
  await expect(page.getByText('Upgrade to 2.15.0 or later')).toBeVisible();
  await expect(page.getByText('Exploited', { exact: true }).first()).toBeVisible();
  await expect(page.getByText(/100% chance of exploitation/)).toBeVisible();
  await page.getByRole('link', { name: 'payments-api' }).click();
  await expect(page.getByRole('heading', { name: 'payments-api' })).toBeVisible();
});

test('SBOMs uploaded through the API appear in the dashboard', async ({ page, request }) => {
  const document = JSON.parse(fs.readFileSync('tests/fixtures/spdx.json', 'utf8'));
  const denied = await request.post('/api/v1/sboms?project=e2e-upload', { data: document });
  expect(denied.status()).toBe(401);

  const res = await request.post('/api/v1/sboms?project=e2e-upload&version=9.9.9', {
    data: document,
    headers: { authorization: 'Bearer e2e-token', 'x-sbom-repository': 'acme/e2e' },
  });
  expect(res.status()).toBe(201);
  const { url } = await res.json();

  await page.goto(url);
  await expect(page.getByRole('heading', { name: 'e2e-upload' })).toBeVisible();
  await expect(page.getByText('acme/e2e · version 9.9.9')).toBeVisible();
  await expect(page.getByRole('grid', { name: 'Packages' })).toContainText('requests');
});
