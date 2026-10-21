import { expect, sessionFor, signIn, test, uid, PASSWORD, heading } from './fixtures';

test('a created token shows its secret once, works as a bearer token and can be revoked', async ({
  page,
  freshServer,
  request,
}) => {
  const s = await freshServer();
  await sessionFor(page, s.baseURL);
  await page.goto(`${s.baseURL}/tokens`);
  await expect(page.getByText('No tokens yet.')).toBeVisible();

  const name = `ci-${uid()}`;
  await page.getByLabel('Name', { exact: true }).fill(name);
  await page.getByLabel('api:read').check();
  await page.getByRole('button', { name: 'Create token' }).click();

  const dialog = page.getByRole('dialog', { name: 'Token created' });
  const secret = await dialog.getByLabel(`Secret for ${name}`).inputValue();
  expect(secret.length).toBeGreaterThan(20);
  await dialog.getByRole('button', { name: 'I have saved it' }).click();
  await expect(dialog).toBeHidden();

  // Never again: not in the page, not after a reload.
  await expect(page.locator('body')).not.toContainText(secret);
  await page.reload();
  await expect(page.getByRole('row', { name: new RegExp(name) })).toContainText('active');
  expect(await page.content()).not.toContain(secret);

  const me = await request.get(`${s.baseURL}/api/v1/auth/me`, {
    headers: { Authorization: `Bearer ${secret}` },
  });
  expect(me.status()).toBe(200);
  expect(s.logs()).not.toContain(secret);

  await page.getByRole('button', { name: `Revoke token ${name}` }).click();
  await page.getByRole('dialog').getByRole('button', { name: 'Revoke' }).click();
  await expect(page.getByRole('row', { name: new RegExp(name) })).toContainText('revoked');
  const after = await request.get(`${s.baseURL}/api/v1/auth/me`, {
    headers: { Authorization: `Bearer ${secret}` },
  });
  expect(after.status()).toBe(401);
});

test('a token needs a name and at least one scope', async ({ page }) => {
  await page.goto('/tokens');
  await page.getByRole('button', { name: 'Create token' }).click();
  await expect(page.getByRole('alert').first()).toBeVisible();
  await expect(page.getByRole('dialog')).toHaveCount(0);
});

test('the DoH URL template can be copied', async ({ page, context }) => {
  await context.grantPermissions(['clipboard-read', 'clipboard-write']);
  await page.goto('/tokens');
  await page.getByRole('button', { name: 'Copy URL' }).click();
  await expect(page.getByRole('status').filter({ hasText: /copied/i })).toBeVisible();
});

test.describe('password change', () => {
  test('validation errors, then success ends other sessions and the new password works', async ({
    page,
    browser,
    freshServer,
  }) => {
    const s = await freshServer();
    s.createUser('pw', 'operator');
    await signIn(page, 'pw');
    // The sign-in above targets the shared server; sign in against the private one instead.
    await page.context().clearCookies();
    await page.goto(`${s.baseURL}/login`);
    await page.getByLabel('Username').fill('pw');
    await page.getByLabel('Password').fill(PASSWORD);
    await page.getByRole('button', { name: 'Sign in' }).click();
    await expect(heading(page, 'Dashboard')).toBeVisible();

    const other = await browser.newContext({ baseURL: s.baseURL });
    const second = await other.newPage();
    await second.goto('/login');
    await second.getByLabel('Username').fill('pw');
    await second.getByLabel('Password').fill(PASSWORD);
    await second.getByRole('button', { name: 'Sign in' }).click();
    await expect(heading(second, 'Dashboard')).toBeVisible();

    await page.goto(`${s.baseURL}/profile`);
    await page.getByLabel('Current password').fill('wrong-current');
    await page.getByLabel('New password', { exact: true }).fill('brand-new-password-77');
    await page.getByLabel('Confirm new password').fill('different-confirmation');
    await page.getByRole('button', { name: 'Change password' }).click();
    await expect(page.getByRole('alert')).toBeVisible();

    await page.getByLabel('Confirm new password').fill('brand-new-password-77');
    await page.getByRole('button', { name: 'Change password' }).click();
    await expect(page.getByRole('alert')).toBeVisible(); // current password is wrong

    await page.getByLabel('Current password').fill(PASSWORD);
    await page.getByRole('button', { name: 'Change password' }).click();
    await expect(page.getByRole('status').filter({ hasText: 'Password changed' })).toBeVisible();
    // This session stays; the other one is gone.
    await page.getByRole('link', { name: 'Dashboard' }).click();
    await expect(heading(page, 'Dashboard')).toBeVisible();
    await second.reload();
    await expect(second).toHaveURL(/\/login/);
    await other.close();

    // Old password is refused, new one works.
    await page.context().clearCookies();
    await page.goto(`${s.baseURL}/login`);
    await page.getByLabel('Username').fill('pw');
    await page.getByLabel('Password').fill(PASSWORD);
    await page.getByRole('button', { name: 'Sign in' }).click();
    await expect(page.getByRole('alert')).toBeVisible();
    await page.getByLabel('Password').fill('brand-new-password-77');
    await page.getByRole('button', { name: 'Sign in' }).click();
    await expect(heading(page, 'Dashboard')).toBeVisible();
  });

  test('the profile shows the account details', async ({ page }) => {
    await page.goto('/profile');
    const account = page.getByRole('region', { name: 'Account' });
    await expect(account).toContainText('admin');
    await expect(account).toContainText('session');
  });
});
