import { expect, signIn, test } from './fixtures';

test.use({ storageState: { cookies: [], origins: [] } });

test('with WebGL available the 3D scene canvas is shown and the static grid is not', async ({
  page,
}) => {
  await page.goto('/login');
  await expect(page.locator('canvas')).toBeVisible();
  await expect(page.getByTestId('static-grid')).toHaveCount(0);
});

test.describe('reduced motion', () => {
  test.use({ reducedMotion: 'reduce' });

  test('the static grid replaces the scene and sign-in still works', async ({ page }) => {
    await page.goto('/login');
    await expect(page.getByTestId('static-grid')).toBeVisible();
    await expect(page.locator('canvas')).toBeHidden();
    await signIn(page, 'admin');
    await expect(page).toHaveURL(/\/dashboard$/);
  });
});

test.describe('no WebGL', () => {
  test('the static grid replaces the scene and sign-in still works', async ({ page }) => {
    await page.addInitScript(() => {
      const original = HTMLCanvasElement.prototype.getContext;
      HTMLCanvasElement.prototype.getContext = function (
        this: HTMLCanvasElement,
        kind: string,
        ...rest: unknown[]
      ) {
        if (kind === 'webgl' || kind === 'webgl2' || kind === 'experimental-webgl') return null;
        return (original as (...a: unknown[]) => unknown).call(this, kind, ...rest);
      } as typeof original;
    });
    await page.goto('/login');
    await expect(page.getByTestId('static-grid')).toBeVisible();
    await expect(page.locator('canvas')).toBeHidden();
    await signIn(page, 'admin');
    await expect(page).toHaveURL(/\/dashboard$/);
  });
});
