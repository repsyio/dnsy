import AxeBuilder from '@axe-core/playwright';
import { type Page } from '@playwright/test';
import { expect, test, uid } from './fixtures';

async function serious(page: Page) {
  const results = await new AxeBuilder({ page })
    .withTags(['wcag2a', 'wcag2aa', 'wcag21a', 'wcag21aa'])
    .analyze();
  return results.violations
    .filter((v) => v.impact === 'serious' || v.impact === 'critical')
    .map(
      (v) =>
        `${v.id} (${v.impact}): ${v.nodes
          .map((n) => n.target.join(' '))
          .slice(0, 3)
          .join(' | ')}`,
    );
}

const PAGES: [string, string][] = [
  ['/dashboard', 'Dashboard'],
  ['/zones', 'Zones'],
  ['/filtering', 'Filtering'],
  ['/upstreams', 'Upstreams'],
  ['/query-log', 'Query log'],
  ['/users', 'Users'],
  ['/acl', 'ACL and rate limits'],
  ['/client-certs', 'Client certificates'],
  ['/cache', 'Cache'],
  ['/dnssec', 'DNSSEC validation'],
  ['/settings', 'Settings'],
  ['/tokens', 'API tokens'],
  ['/profile', 'Profile'],
];

for (const [path, h1] of PAGES) {
  test(`${path} has no serious accessibility violations`, async ({ page }) => {
    await page.goto(path);
    await expect(page.getByRole('heading', { level: 1, name: h1 })).toBeVisible();
    await expect(page.locator('[aria-busy="true"]')).toHaveCount(0);
    expect(await serious(page)).toEqual([]);
  });
}

test.describe('signed out', () => {
  test.use({ storageState: { cookies: [], origins: [] } });

  test('the login page has no serious violations (3D scene)', async ({ page }) => {
    await page.goto('/login');
    await expect(page.getByRole('button', { name: 'Sign in' })).toBeVisible();
    expect(await serious(page)).toEqual([]);
  });

  test('the login page has no serious violations (static fallback, setup mode)', async ({
    page,
  }) => {
    await page.emulateMedia({ reducedMotion: 'reduce' });
    await page.goto('/login');
    await page.getByRole('button', { name: 'First run? Set up the admin account' }).click();
    await expect(page.getByLabel('Setup code')).toBeVisible();
    expect(await serious(page)).toEqual([]);
  });
});

test('zone editor, record form, dialogs and the DNSSEC tab have no serious violations', async ({
  page,
  api,
}) => {
  const name = `a${uid()}.test.`;
  await api.ok('post', '/zones', {
    name,
    default_ttl: 300,
    soa: {
      mname: `ns1.${name}`,
      rname: `h.${name}`,
      refresh: 3600,
      retry: 600,
      expire: 1209600,
      minimum: 300,
    },
    records: [
      { name: '@', type: 'NS', value: `ns1.${name}` },
      { name: 'www', type: 'A', value: '192.0.2.4' },
    ],
  });
  await page.goto(`/zones/${name}`);
  await expect(page.getByRole('row', { name: /www/ })).toBeVisible();
  expect(await serious(page)).toEqual([]);

  await page.getByRole('button', { name: 'Add record' }).first().click();
  await expect(page.getByRole('form', { name: 'New record' })).toBeVisible();
  expect(await serious(page)).toEqual([]);
  await page.getByRole('button', { name: 'Cancel' }).click();

  await page.getByRole('button', { name: 'Delete A record www' }).click();
  await expect(page.getByRole('dialog', { name: 'Delete record' })).toBeVisible();
  expect(await serious(page)).toEqual([]);
  await page.keyboard.press('Escape');

  await page.getByRole('tab', { name: 'DNSSEC' }).click();
  await expect(page.getByRole('heading', { name: 'Sign this zone' })).toBeVisible();
  expect(await serious(page)).toEqual([]);
});

test('the not-found page has no serious violations', async ({ page }) => {
  await page.goto('/nothing/here');
  await expect(page.getByRole('heading', { level: 1, name: '404' })).toBeVisible();
  expect(await serious(page)).toEqual([]);
});
