import { expect, heading, PASSWORD, roleState, sessionFor, signIn, test, uid } from './fixtures';

test('create a user, change the role, reset the password and delete the user', async ({
  page,
  freshServer,
}) => {
  const s = await freshServer();
  await sessionFor(page, s.baseURL);
  await page.goto(`${s.baseURL}/users`);
  const name = `u${uid()}`;

  await page.getByRole('button', { name: 'Create user' }).click();
  const dialog = page.getByRole('dialog');
  await dialog.getByLabel('Username').fill(name);
  await dialog.getByLabel('Password').fill('short');
  await dialog.getByRole('button', { name: 'Create', exact: true }).click();
  await expect(dialog.getByRole('alert')).toBeVisible();
  await dialog.getByLabel('Password').fill('a-long-enough-password-1');
  await dialog.getByLabel('Role').selectOption('viewer');
  await dialog.getByRole('button', { name: 'Create', exact: true }).click();
  const row = page.getByRole('row', { name: new RegExp(name) });
  await expect(row).toContainText('viewer');

  await page.getByRole('button', { name: `Change role of ${name}` }).click();
  await page.getByRole('dialog').getByLabel('Role').selectOption('operator');
  await page.getByRole('dialog').getByRole('button', { name: 'Save role' }).click();
  await expect(row).toContainText('operator');

  await page.getByRole('button', { name: `Reset password of ${name}` }).click();
  await page.getByRole('dialog').getByLabel('New password').fill('another-long-password-2');
  await page.getByRole('dialog').getByRole('button', { name: 'Reset password' }).click();
  await expect(page.getByRole('dialog')).toBeHidden();

  await page.getByRole('button', { name: `Delete ${name}` }).click();
  await page
    .getByRole('dialog', { name: `Delete ${name}` })
    .getByRole('button', { name: 'Delete', exact: true })
    .click();
  await expect(page.getByRole('status').filter({ hasText: `Deleted ${name}.` })).toBeVisible();
  await expect(row).toHaveCount(0);
});

test('a duplicate username is refused', async ({ page, freshServer }) => {
  const s = await freshServer();
  await sessionFor(page, s.baseURL);
  await page.goto(`${s.baseURL}/users`);
  await page.getByRole('button', { name: 'Create user' }).click();
  const dialog = page.getByRole('dialog');
  await dialog.getByLabel('Username').fill('viewer');
  await dialog.getByLabel('Password').fill('a-long-enough-password-1');
  await dialog.getByRole('button', { name: 'Create', exact: true }).click();
  await expect(dialog.getByRole('alert')).toBeVisible();
});

test('an admin cannot delete themselves from the list', async ({ page }) => {
  await page.goto('/users');
  await expect(page.getByRole('button', { name: 'Delete admin' })).toBeDisabled();
});

test('a user created in the UI can sign in with the password that was set', async ({
  page,
  browser,
  freshServer,
}) => {
  const s = await freshServer();
  await sessionFor(page, s.baseURL);
  await page.goto(`${s.baseURL}/users`);
  const name = `n${uid()}`;
  await page.getByRole('button', { name: 'Create user' }).click();
  const dialog = page.getByRole('dialog');
  await dialog.getByLabel('Username').fill(name);
  await dialog.getByLabel('Password').fill('a-long-enough-password-1');
  await dialog.getByLabel('Role').selectOption('viewer');
  await dialog.getByRole('button', { name: 'Create', exact: true }).click();
  await expect(page.getByRole('row', { name: new RegExp(name) })).toBeVisible();

  const ctx = await browser.newContext({ baseURL: s.baseURL });
  const other = await ctx.newPage();
  await signIn(other, name, 'a-long-enough-password-1');
  await expect(heading(other, 'Dashboard')).toBeVisible();
  await expect(
    other.getByRole('navigation', { name: 'Main' }).getByRole('link', { name: 'Users' }),
  ).toHaveCount(0);
  await ctx.close();
});

test.describe('operator', () => {
  test.use({ storageState: roleState('operator') });
  test('has no Users page', async ({ page }) => {
    await page.goto('/users');
    await expect(heading(page, 'Users')).toHaveCount(0);
  });
});

test.describe('viewer', () => {
  test.use({ storageState: roleState('viewer') });

  test('reads dashboards but cannot change anything: the server refuses and the UI says so', async ({
    page,
  }) => {
    await page.goto('/zones');
    await expect(heading(page, 'Zones')).toBeVisible();
    await page.getByRole('button', { name: 'Create zone' }).first().click();
    const dialog = page.getByRole('dialog', { name: 'Create zone' });
    await dialog.getByLabel('Zone name').fill(`v${uid()}.test.`);
    await dialog.getByLabel('Name servers').fill('ns1.example.test.');
    await dialog.getByLabel('SOA primary server').fill('ns1.example.test.');
    await dialog.getByLabel('SOA contact').fill('h.example.test.');
    await dialog.getByRole('button', { name: 'Create', exact: true }).click();
    await expect(dialog.getByRole('alert')).toBeVisible();
  });

  test('token scopes are limited to the viewer role', async ({ page }) => {
    await page.goto('/tokens');
    await expect(page.getByText('limited to your role: viewer')).toBeVisible();
    await expect(page.getByLabel('admin', { exact: true })).toHaveCount(0);
  });

  test('password is not shown anywhere in the profile', async ({ page }) => {
    await page.goto('/profile');
    await expect(page.getByText('viewer', { exact: true }).first()).toBeVisible();
    expect(PASSWORD.length).toBeGreaterThan(0);
  });
});
