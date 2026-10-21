import { type Page } from '@playwright/test';
import { expect, signIn, test } from './fixtures';

test.use({ storageState: { cookies: [], origins: [] } });

/** Count reddish pixels (the pulses) on the login canvas. */
async function redPixels(page: Page): Promise<number> {
  return page.locator('canvas').evaluate((c: HTMLCanvasElement) => {
    const data = c.getContext('2d')!.getImageData(0, 0, c.width, c.height).data;
    let n = 0;
    for (let i = 0; i < data.length; i += 4) {
      if ((data[i] ?? 0) > 150 && (data[i + 1] ?? 0) < 90 && (data[i + 3] ?? 0) > 60) n++;
    }
    return n;
  });
}

/** Count any drawn pixels on the login canvas. */
async function drawnPixels(page: Page): Promise<number> {
  return page.locator('canvas').evaluate((c: HTMLCanvasElement) => {
    const data = c.getContext('2d')!.getImageData(0, 0, c.width, c.height).data;
    let n = 0;
    for (let i = 3; i < data.length; i += 4) if ((data[i] ?? 0) > 0) n++;
    return n;
  });
}

test.describe('desktop', () => {
  test.use({ viewport: { width: 1280, height: 800 } });

  test('two columns: the form on the left, the decorative blob canvas on the right', async ({
    page,
  }) => {
    await page.goto('/login');
    const form = page.locator('form');
    const art = page.getByTestId('login-art');
    await expect(form).toBeVisible();
    await expect(page.locator('canvas')).toBeVisible();
    await expect(art).toHaveAttribute('aria-hidden', 'true');
    const f = (await page.locator('main').boundingBox())!;
    const a = (await art.boundingBox())!;
    expect(f.width).toBeCloseTo(380, 0);
    expect(a.x).toBeGreaterThanOrEqual(f.x + f.width);
    expect(a.height).toBeCloseTo(800, 0);
    // the wireframe is drawn and red pulses pass through it
    await expect.poll(() => drawnPixels(page)).toBeGreaterThan(1000);
    await expect.poll(() => redPixels(page), { timeout: 15_000 }).toBeGreaterThan(5);
  });
});

test.describe('phone', () => {
  test.use({ viewport: { width: 360, height: 740 } });

  test('one column: the blob fills the background at half opacity behind a solid panel', async ({
    page,
  }) => {
    await page.goto('/login');
    const art = page.getByTestId('login-art');
    await expect(page.locator('canvas')).toBeVisible();
    await expect(art).toHaveCSS('opacity', '0.5');
    await expect(art).toHaveCSS('position', 'fixed');
    const a = (await art.boundingBox())!;
    expect(a.width).toBeCloseTo(360, 0);
    const form = page.locator('form');
    const bg = await form.evaluate((el) => getComputedStyle(el).backgroundColor);
    expect(bg).not.toMatch(/rgba\(.*, 0\)|transparent/);
    await signIn(page, 'admin');
    await expect(page).toHaveURL(/\/dashboard$/);
  });
});

test.describe('reduced motion', () => {
  test.use({ reducedMotion: 'reduce' });

  test('one still frame without pulses, and sign-in still works', async ({ page }) => {
    await page.goto('/login');
    await expect(page.locator('canvas')).toBeVisible();
    await expect.poll(() => drawnPixels(page)).toBeGreaterThan(1000);
    const first = await page.locator('canvas').evaluate((c: HTMLCanvasElement) => c.toDataURL());
    await page.waitForTimeout(500);
    const later = await page.locator('canvas').evaluate((c: HTMLCanvasElement) => c.toDataURL());
    expect(later).toBe(first);
    expect(await redPixels(page)).toBe(0);
    await signIn(page, 'admin');
    await expect(page).toHaveURL(/\/dashboard$/);
  });
});

test.describe('no canvas', () => {
  test('sign-in works when the 2D context is unavailable', async ({ page }) => {
    await page.addInitScript(() => {
      (HTMLCanvasElement.prototype as unknown as { getContext: () => null }).getContext = () =>
        null;
    });
    await page.goto('/login');
    await signIn(page, 'admin');
    await expect(page).toHaveURL(/\/dashboard$/);
  });
});
