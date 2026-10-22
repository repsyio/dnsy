import { expect, heading, test } from './fixtures';

const PAGES = [
  '/dashboard',
  '/zones',
  '/filtering',
  '/upstreams',
  '/query-log',
  '/users',
  '/acl',
  '/response-ip',
  '/client-certs',
  '/cache',
  '/dnssec',
  '/settings',
  '/tokens',
  '/profile',
];

for (const width of [360, 1280]) {
  test.describe(`${width}px`, () => {
    test.use({ viewport: { width, height: 800 } });

    test('no page overflows horizontally', async ({ page }) => {
      for (const path of PAGES) {
        await page.goto(path);
        await expect(page.getByRole('heading', { level: 1 })).toBeVisible();
        const overflow = await page.evaluate(
          () => document.documentElement.scrollWidth - document.documentElement.clientWidth,
        );
        expect(overflow, `${path} overflows by ${overflow}px`).toBeLessThanOrEqual(0);
      }
    });
  });
}

for (const width of [360, 768, 1280]) {
  test.describe(`login at ${width}px`, () => {
    test.use({ viewport: { width, height: 800 }, storageState: { cookies: [], origins: [] } });

    test('the login page does not overflow and the form stays in view', async ({ page }) => {
      await page.goto('/login');
      await expect(page.getByRole('button', { name: 'Sign in' })).toBeInViewport();
      await expect(page.getByLabel('Username')).toBeInViewport();
      const overflow = await page.evaluate(
        () => document.documentElement.scrollWidth - document.documentElement.clientWidth,
      );
      expect(overflow, `/login overflows by ${overflow}px`).toBeLessThanOrEqual(0);
    });
  });
}

test.describe('off-canvas sidebar at 360px', () => {
  test.use({ viewport: { width: 360, height: 800 } });

  test('the menu button opens the drawer, a link closes it, Escape returns focus', async ({
    page,
  }) => {
    await page.goto('/dashboard');
    const nav = page.locator('#main-nav');
    await expect(nav).toBeHidden();
    const button = page.getByRole('button', { name: 'Menu', exact: true });
    await expect(button).toHaveAttribute('aria-expanded', 'false');
    await button.click();
    await expect(nav).toBeVisible();
    await expect(button).toHaveAttribute('aria-expanded', 'true');
    await page.keyboard.press('Escape');
    await expect(nav).toBeHidden();
    await expect(button).toBeFocused();
    await button.click();
    await nav.getByRole('link', { name: 'Zones', exact: true }).click();
    await expect(heading(page, 'Zones')).toBeVisible();
    await expect(nav).toBeHidden();
  });
});

test.describe('desktop', () => {
  test.use({ viewport: { width: 1280, height: 800 } });
  test('the sidebar is always visible and there is no menu button', async ({ page }) => {
    await page.goto('/dashboard');
    await expect(page.locator('#main-nav')).toBeVisible();
    await expect(page.getByRole('button', { name: 'Menu', exact: true })).toBeHidden();
  });
});
