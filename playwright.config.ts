import { defineConfig, devices } from '@playwright/test';

// E2E tests run against a production build (`npm run build` first) and a dedicated database,
// which global-setup wipes, migrates and seeds with offline demo data.
const PORT = Number(process.env.E2E_PORT ?? 3100);
export const E2E_DATABASE_URL = process.env.E2E_DATABASE_URL ?? 'postgres://sbom:sbom@localhost:5432/sbom_e2e';

// Second server with owner sign-in enabled, on its own port. NEXTAUTH_URL is http so the session cookie has no
// __Secure- prefix; the GitHub credentials are dummies and nothing in the "authed" project contacts GitHub.
const AUTH_PORT = Number(process.env.E2E_AUTH_PORT ?? 3101);
export const AUTH_E2E_URL = `http://localhost:${AUTH_PORT}`;
export const AUTH_E2E_SECRET = 'e2e-nextauth-secret-e2e-nextauth-secret';
export const AUTH_E2E_OWNER_ID = '4242';

export default defineConfig({
  testDir: 'tests/e2e',
  globalSetup: './tests/e2e/global-setup.ts',
  fullyParallel: false,
  workers: 1,
  retries: process.env.CI ? 1 : 0,
  reporter: process.env.CI ? [['github'], ['html', { open: 'never' }]] : 'list',
  use: {
    baseURL: `http://localhost:${PORT}`,
    trace: 'retain-on-failure',
    // Lets environments with a preinstalled Chromium skip `playwright install`.
    launchOptions: process.env.PLAYWRIGHT_CHROMIUM_PATH ? { executablePath: process.env.PLAYWRIGHT_CHROMIUM_PATH } : {},
  },
  projects: [
    // Auth off: the unchanged dashboard journeys.
    { name: 'chromium', testIgnore: /auth\.spec\.ts/, use: { ...devices['Desktop Chrome'] } },
    { name: 'authed', testMatch: /auth\.spec\.ts/, use: { ...devices['Desktop Chrome'], baseURL: AUTH_E2E_URL } },
  ],
  webServer: [
    {
      command: `npx next start -p ${PORT}`,
      url: `http://localhost:${PORT}/api/healthz`,
      reuseExistingServer: false,
      // `next start` is production, where unconfigured auth fails closed; this server tests the open dashboard.
      env: { DATABASE_URL: E2E_DATABASE_URL, UPLOAD_TOKENS: 'e2e-token', ALLOW_OPEN_READS: 'true' },
    },
    {
      command: `npx next start -p ${AUTH_PORT}`,
      url: `${AUTH_E2E_URL}/api/healthz`,
      reuseExistingServer: false,
      env: {
        DATABASE_URL: E2E_DATABASE_URL,
        UPLOAD_TOKENS: 'e2e-token',
        OWNER_GITHUB_ID: AUTH_E2E_OWNER_ID,
        NEXTAUTH_SECRET: AUTH_E2E_SECRET,
        NEXTAUTH_URL: AUTH_E2E_URL,
        GITHUB_CLIENT_ID: 'dummy-client-id',
        GITHUB_CLIENT_SECRET: 'dummy-client-secret',
      },
    },
  ],
});
