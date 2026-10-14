import { defineConfig, devices } from '@playwright/test';

// E2E tests run against a production build (`npm run build` first) and a dedicated database,
// which global-setup wipes, migrates and seeds with offline demo data.
const PORT = Number(process.env.E2E_PORT ?? 3100);
export const E2E_DATABASE_URL = process.env.E2E_DATABASE_URL ?? 'postgres://sbom:sbom@localhost:5432/sbom_e2e';

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
  projects: [{ name: 'chromium', use: { ...devices['Desktop Chrome'] } }],
  webServer: {
    command: `npx next start -p ${PORT}`,
    url: `http://localhost:${PORT}/api/healthz`,
    reuseExistingServer: false,
    env: { DATABASE_URL: E2E_DATABASE_URL, UPLOAD_TOKENS: 'e2e-token' },
  },
});
