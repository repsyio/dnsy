// Take the documentation screenshots from a running demo (scripts/demo/run.sh).
//
//   node scripts/demo/capture.mjs <out-dir> [base-url]
//
// Needs Playwright with Chromium (`cd web && pnpm install && pnpm exec playwright install chromium`).
// Writes raw PNGs at 1280px wide; scripts/demo/optimize.py shrinks them for the repository.
import { createRequire } from 'node:module';
import { mkdirSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const here = dirname(fileURLToPath(import.meta.url));
const require = createRequire(join(here, '../../web/package.json'));
const { chromium } = require('@playwright/test');

const out = resolve(process.argv[2] ?? 'screenshots');
const base = process.argv[3] ?? 'http://127.0.0.1:15380';
mkdirSync(out, { recursive: true });

const browser = await chromium.launch();
const context = await browser.newContext({
  viewport: { width: 1280, height: 800 },
  deviceScaleFactor: 1,
});
const page = await context.newPage();
const shot = (name) => page.screenshot({ path: join(out, `${name}.png`) });

// Login page: give the blob a few seconds to morph and let red pulses cross it.
await page.goto(`${base}/login`);
await page.getByLabel('Username').waitFor();
await page.waitForTimeout(4000);
await shot('login');

await page.getByLabel('Username').fill('admin');
await page.getByLabel('Password').fill('demo-password-1234');
await page.getByRole('button', { name: /sign in/i }).click();
await page.waitForURL('**/dashboard');
await page.locator('[data-tile="queries"]').waitFor();
await page.getByRole('button', { name: '1h', exact: true }).click();
await page.waitForTimeout(1500);
await shot('dashboard');

await page.goto(`${base}/zones`);
await page.getByRole('table', { name: 'Zones' }).waitFor();
await shot('zones');

await page.goto(`${base}/zones/example.com.`);
await page.getByRole('table').first().waitFor();
await page.waitForTimeout(500);
await shot('zone-editor');

await page.getByRole('tab', { name: 'DNSSEC' }).click();
await page.getByRole('tabpanel', { name: 'DNSSEC' }).getByRole('heading', { name: 'Keys' }).waitFor();
await page.waitForTimeout(500);
await shot('dnssec');

await page.goto(`${base}/query-log`);
await page.getByRole('table').first().waitFor();
await page.waitForTimeout(800);
await shot('query-log');

await page.goto(`${base}/filtering`);
await page.waitForTimeout(1000);
await shot('filtering');

// Empty state: an empty zone list. Loading state: a zone list held back.
await page.route('**/api/v1/zones', (route) => route.fulfill({ json: [] }));
await page.goto(`${base}/zones`);
await page.getByText('No zones yet.').waitFor();
await page.waitForTimeout(500);
await shot('mascot-empty');
await page.unroute('**/api/v1/zones');

let release;
const gate = new Promise((r) => (release = r));
await page.route('**/api/v1/zones', async (route) => {
  await gate;
  await route.continue();
});
await page.goto(`${base}/zones`);
await page.getByText('Loading zones...').waitFor();
await page.waitForTimeout(500);
await shot('mascot-loading');
release();

await browser.close();
