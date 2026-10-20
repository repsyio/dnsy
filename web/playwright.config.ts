import { defineConfig } from '@playwright/test';

// End-to-end browser tests run against a built UI served by a running dnsy (see `just e2e`).
export default defineConfig({
  testDir: 'e2e',
  use: { baseURL: process.env['DNSY_URL'] ?? 'http://127.0.0.1:5380' },
});
