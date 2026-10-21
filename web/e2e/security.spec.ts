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
  // Inject the script and wait for the browser's own violation event, not a fixed delay, so a
  // loaded machine cannot let the test end before the violation is reported.
  await page.evaluate(
    () =>
      new Promise<void>((resolve) => {
        document.addEventListener('securitypolicyviolation', () => resolve(), { once: true });
        const s = document.createElement('script');
        s.textContent = 'window.__injected = 1';
        document.head.appendChild(s);
      }),
  );
  // The guard reads the console message that accompanies the event; give it time to land.
  await page.evaluate(() => new Promise((r) => setTimeout(r, 500)));
});
