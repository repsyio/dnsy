import { expect, heading, roleState, test } from './fixtures';

const PAGES: [path: string, h1: string][] = [
  ['/dashboard', 'Dashboard'],
  ['/zones', 'Zones'],
  ['/filtering', 'Filtering'],
  ['/upstreams', 'Upstreams'],
  ['/query-log', 'Query log'],
  ['/users', 'Users'],
  ['/acl', 'ACL and rate limits'],
  ['/response-ip', 'Response IP policy'],
  ['/client-certs', 'Client certificates'],
  ['/cache', 'Cache'],
  ['/dnssec', 'DNSSEC validation'],
  ['/settings', 'Settings'],
  ['/tokens', 'API tokens'],
  ['/profile', 'Profile'],
];

test('every sidebar entry opens its page and marks itself current', async ({ page }) => {
  await page.goto('/dashboard');
  const nav = page.getByRole('navigation', { name: 'Main' });
  for (const [path, h1] of PAGES) {
    await nav.locator(`a[href="${path}"]`).click();
    await expect(page).toHaveURL(new RegExp(`${path}$`));
    await expect(heading(page, h1)).toBeVisible();
    await expect(nav.locator(`a[href="${path}"]`)).toHaveAttribute('aria-current', 'page');
    await expect(page).toHaveTitle(/\S/);
  }
});

test('the root redirects to the dashboard', async ({ page }) => {
  await page.goto('/');
  await expect(page).toHaveURL(/\/dashboard$/);
});

test('an unknown path shows the not-found page inside the shell', async ({ page }) => {
  await page.goto('/no/such/page');
  await expect(heading(page, '404')).toBeVisible();
  await expect(page.getByText('Nox could not find that page.')).toBeVisible();
  await expect(page.getByRole('img', { name: 'Nox could not find the page' })).toBeVisible();
  await page.getByRole('link', { name: 'Back to dashboard' }).click();
  await expect(heading(page, 'Dashboard')).toBeVisible();
  await expect(page.getByRole('navigation', { name: 'Main' })).toBeVisible();
});

test('the dev gallery is not shipped in the production build', async ({ page }) => {
  await page.goto('/dev/mascot');
  await expect(heading(page, '404')).toBeVisible();
});

test('an unknown zone shows the not-found mascot', async ({ page }) => {
  await page.goto('/zones/missing.invalid.');
  await expect(page.getByText('No such zone.')).toBeVisible();
});

test.describe('viewer', () => {
  test.use({ storageState: roleState('viewer') });

  test('does not see the Users entry and is bounced from /users', async ({ page }) => {
    await page.goto('/dashboard');
    await expect(
      page.getByRole('navigation', { name: 'Main' }).getByRole('link', { name: 'Users' }),
    ).toHaveCount(0);
    await page.goto('/users');
    await expect(heading(page, 'Users')).toHaveCount(0);
  });
});

test.describe('keyboard', () => {
  test('tab reaches the sidebar links and Enter follows one', async ({ page }) => {
    await page.goto('/dashboard');
    const zones = page
      .getByRole('navigation', { name: 'Main' })
      .getByRole('link', { name: 'Zones', exact: true });
    await zones.focus();
    await expect(zones).toBeFocused();
    await page.keyboard.press('Enter');
    await expect(heading(page, 'Zones')).toBeVisible();
  });

  test('dialogs trap focus and Escape closes them', async ({ page }) => {
    await page.goto('/zones');
    const open = page.getByRole('button', { name: 'Create zone' }).first();
    await open.click();
    const dialog = page.getByRole('dialog', { name: 'Create zone' });
    await expect(dialog).toBeVisible();
    for (let i = 0; i < 25; i++) {
      await page.keyboard.press('Tab');
      expect(await dialog.evaluate((d) => d.contains(document.activeElement))).toBe(true);
    }
    await page.keyboard.press('Escape');
    await expect(dialog).toBeHidden();
    await expect(open).toBeFocused();
  });
});
