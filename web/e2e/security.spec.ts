import { expect, test } from './fixtures';

test.use({ storageState: { cookies: [], origins: [] } });

test('the UI is served with a strict CSP and security headers', async ({ request, server }) => {
  const res = await request.get(`${server.baseURL}/login`);
  expect(res.status()).toBe(200);
  const csp = res.headers()['content-security-policy'] ?? '';
  expect(csp).toContain("default-src 'self'");
  expect(csp).not.toMatch(/script-src[^;]*'unsafe-inline'/);
  expect(csp).not.toContain("'unsafe-eval'");
  expect(res.headers()['x-content-type-options']).toBe('nosniff');
});

// The guard is an auto fixture; this test must fail because of it, which `test.fail()` asserts.
test('the CSP guard fails a test whose page violates the policy', async ({ page }) => {
  test.fail();
  await page.goto('/login');
  await page.evaluate(() => {
    const s = document.createElement('script');
    s.textContent = 'window.__injected = 1';
    document.head.appendChild(s);
  });
  // The violation is logged asynchronously; wait for the console message to land.
  await page.waitForFunction(() => true);
  await page.evaluate(() => new Promise((r) => setTimeout(r, 300)));
});
