import { expect, heading, PASSWORD, signIn, test, uid } from './fixtures';
import { Api } from './support/api';
import { cli } from './support/server';

// These tests sign in themselves, so they start without a session.
test.use({ storageState: { cookies: [], origins: [] } });

test.describe('login', () => {
  test('renders the scene canvas and signs in', async ({ page, server }) => {
    await page.goto('/login');
    await expect(page.locator('canvas')).toBeAttached();
    await expect(page.getByRole('heading', { name: 'DNSY' })).toBeVisible();
    await signIn(page, 'admin');
    await expect(page).toHaveURL(/\/dashboard$/);
    await expect(heading(page, 'Dashboard')).toBeVisible();
    await expect(page.getByText('admin (admin)')).toBeVisible();
    expect(server.baseURL).toContain('127.0.0.1');
  });

  test('a wrong password shows an error and keeps the form', async ({ page, freshServer }) => {
    const s = await freshServer();
    await page.goto(`${s.baseURL}/login`);
    await page.getByLabel('Username').fill('admin');
    await page.getByLabel('Password').fill('not-the-password');
    await page.getByRole('button', { name: 'Sign in' }).click();
    await expect(page.getByRole('alert')).toHaveText('authentication required');
    await expect(page).toHaveURL(/\/login$/);
  });

  test('five failures throttle the account with a countdown, even for the right password', async ({
    page,
    freshServer,
  }) => {
    const s = await freshServer();
    await page.goto(`${s.baseURL}/login`);
    await page.getByLabel('Username').fill('admin');
    const password = page.getByLabel('Password');
    for (let i = 0; i < 5; i++) {
      await password.fill('wrong-password');
      await page.getByRole('button', { name: 'Sign in' }).click();
      await expect(page.getByRole('alert')).toBeVisible();
    }
    await password.fill('wrong-password');
    await page.getByRole('button', { name: 'Sign in' }).click();
    await expect(page.getByRole('status').filter({ hasText: 'Too many attempts' })).toContainText(
      /Try again in \d+s/,
    );
    await expect(page.getByRole('button', { name: 'Sign in' })).toBeDisabled();
    await password.fill(PASSWORD);
    await expect(page.getByRole('button', { name: 'Sign in' })).toBeDisabled();
  });

  test('a protected page redirects to login and returns after signing in', async ({ page }) => {
    await page.goto('/zones');
    await expect(page).toHaveURL(/\/login\?redirect=%2Fzones$/);
    await page.getByLabel('Username').fill('admin');
    await page.getByLabel('Password').fill(PASSWORD);
    await page.getByRole('button', { name: 'Sign in' }).click();
    await expect(page).toHaveURL(/\/zones$/);
    await expect(heading(page, 'Zones')).toBeVisible();
  });

  test('an open redirect target is ignored', async ({ page }) => {
    await page.goto('/login?redirect=//evil.example/x');
    await page.getByLabel('Username').fill('admin');
    await page.getByLabel('Password').fill(PASSWORD);
    await page.getByRole('button', { name: 'Sign in' }).click();
    await expect(page).toHaveURL(/\/dashboard$/);
  });
});

test.describe('first-admin bootstrap', () => {
  test('creates the admin with the printed one-time code', async ({ page, freshServer }) => {
    const s = await freshServer({ users: false });
    const code = await s.bootstrapCode();
    await page.goto(`${s.baseURL}/login`);
    await page.getByRole('button', { name: 'First run? Set up the admin account' }).click();
    await page.getByLabel('Setup code').fill(code);
    await page.getByLabel('Username').fill('root');
    await page.getByLabel('Password').fill(PASSWORD);
    await page.getByRole('button', { name: 'Create admin' }).click();
    await expect(page).toHaveURL(/\/dashboard$/);
    await expect(page.getByText('root (admin)')).toBeVisible();
    expect(s.logs()).not.toContain(PASSWORD);
  });

  test('a wrong code and a short password are rejected', async ({ page, freshServer }) => {
    const s = await freshServer({ users: false });
    await page.goto(`${s.baseURL}/login`);
    await page.getByRole('button', { name: 'First run? Set up the admin account' }).click();
    await page.getByLabel('Setup code').fill('definitely-wrong');
    await page.getByLabel('Username').fill('root');
    await page.getByLabel('Password').fill('short');
    await page.getByRole('button', { name: 'Create admin' }).click();
    await expect(page.getByRole('alert')).toBeVisible();
    await page.getByLabel('Password').fill(PASSWORD);
    await page.getByRole('button', { name: 'Create admin' }).click();
    await expect(page.getByRole('alert')).toBeVisible();
    await expect(page).toHaveURL(/\/login$/);
  });

  test('the code works once; afterwards setup says an admin exists', async ({
    page,
    freshServer,
  }) => {
    const s = await freshServer({ users: false });
    const code = await s.bootstrapCode();
    const first = await fetch(`${s.baseURL}/api/v1/auth/bootstrap`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ code, username: 'root', password: PASSWORD }),
    });
    expect(first.status).toBeLessThan(300);
    await page.goto(`${s.baseURL}/login`);
    await page.getByRole('button', { name: 'First run? Set up the admin account' }).click();
    await page.getByLabel('Setup code').fill(code);
    await page.getByLabel('Username').fill('other');
    await page.getByLabel('Password').fill(PASSWORD);
    await page.getByRole('button', { name: 'Create admin' }).click();
    await expect(page.getByRole('alert')).toContainText('An admin already exists');
  });
});

test.describe('session', () => {
  test('sign out ends the session and the guard redirects again', async ({ page, server }) => {
    const user = `s${uid()}`;
    cli(server.configPath, ['user', 'create', user, '--role', 'viewer'], {
      DNSY_PASSWORD: PASSWORD,
    });
    await signIn(page, user);
    await expect(heading(page, 'Dashboard')).toBeVisible();
    await page.getByRole('button', { name: 'Sign out' }).click();
    await expect(page).toHaveURL(/\/login$/);
    await page.goto('/zones');
    await expect(page).toHaveURL(/\/login\?redirect=/);
  });

  test('an expired or revoked session bounces the next action to login', async ({
    page,
    server,
  }) => {
    const user = `e${uid()}`;
    cli(server.configPath, ['user', 'create', user, '--role', 'admin'], {
      DNSY_PASSWORD: PASSWORD,
    });
    await signIn(page, user);
    await expect(heading(page, 'Dashboard')).toBeVisible();
    await page.context().clearCookies({ name: 'dnsy_session' });
    await page.getByRole('link', { name: 'Zones', exact: true }).click();
    await expect(page).toHaveURL(/\/login$/);
  });

  test('state-changing requests need the CSRF token', async ({ server }) => {
    const api = await Api.login(server.baseURL, 'viewer');
    const wrong = await api.send('post', '/auth/logout', {}, { 'X-CSRF-Token': 'wrong' });
    expect(wrong.status()).toBe(403);
    const ok = await api.send('post', '/auth/logout', {});
    expect(ok.status()).toBeLessThan(300);
    await api.dispose();
  });
});
