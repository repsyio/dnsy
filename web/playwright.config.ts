import { defineConfig, devices } from '@playwright/test';

// Browser end-to-end tests. `just e2e-ui` builds the dnsy binary with the embedded UI; the
// global setup starts one shared instance (fake upstream, admin/operator/viewer users) and tests
// that change global state start their own. Chromium only; see docs/book/src/contributing.md.
export default defineConfig({
  testDir: 'e2e',
  outputDir: 'test-results',
  globalSetup: './e2e/global-setup.ts',
  fullyParallel: true,
  forbidOnly: !!process.env['CI'],
  retries: 0,
  workers: process.env['CI'] ? 2 : undefined,
  reporter: [['list'], ['html', { open: 'never', outputFolder: 'playwright-report' }]],
  timeout: 30_000,
  expect: { timeout: 7_000 },
  use: {
    trace: 'retain-on-failure',
    screenshot: 'only-on-failure',
    video: 'off',
    actionTimeout: 10_000,
  },
  projects: [{ name: 'chromium', use: { ...devices['Desktop Chrome'] } }],
});
