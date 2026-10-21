import { expect, heading, sessionFor, test } from './fixtures';

test('loading: the mascot shows while the zone list is pending', async ({ page }) => {
  let release!: () => void;
  const gate = new Promise<void>((r) => (release = r));
  await page.route('**/api/v1/zones', async (route) => {
    await gate;
    await route.continue();
  });
  await page.goto('/zones');
  await expect(page.getByRole('img', { name: 'Nox is loading' })).toBeVisible();
  await expect(page.getByText('Loading zones...')).toBeVisible();
  release();
  await expect(page.getByText('Loading zones...')).toBeHidden();
  await expect(heading(page, 'Zones')).toBeVisible();
});

test('empty: an empty zone list shows the empty mascot with a create action', async ({ page }) => {
  await page.route('**/api/v1/zones', (route) => route.fulfill({ json: [] }));
  await page.goto('/zones');
  await expect(page.getByRole('img', { name: 'Nox found nothing here' })).toBeVisible();
  await expect(page.getByText('No zones yet.')).toBeVisible();
  await page
    .getByRole('figure', { name: 'No zones yet.' })
    .getByRole('button', { name: 'Create zone' })
    .click();
  await expect(page.getByRole('dialog', { name: 'Create zone' })).toBeVisible();
});

test('error: a failing API shows the error mascot and Retry recovers', async ({ page }) => {
  await page.route('**/api/v1/zones', (route) =>
    route.fulfill({
      status: 500,
      contentType: 'application/problem+json',
      body: JSON.stringify({
        type: 'about:blank',
        title: 'Internal',
        status: 500,
        detail: 'simulated failure',
      }),
    }),
  );
  await page.goto('/zones');
  await expect(page.getByRole('img', { name: 'Nox reports an error' })).toBeVisible();
  await expect(page.getByRole('alert').filter({ hasText: 'simulated failure' })).toBeVisible();
  await page.unroute('**/api/v1/zones');
  await page.getByRole('button', { name: 'Retry' }).click();
  await expect(page.getByRole('img', { name: 'Nox reports an error' })).toHaveCount(0);
  await expect(
    page.getByRole('table', { name: 'Zones' }).or(page.getByText('No zones yet.')),
  ).toBeVisible();
});

test('error: the dashboard offers Retry after a failed load', async ({ page }) => {
  await page.route('**/api/v1/stats/summary*', (route) => route.abort());
  await page.goto('/dashboard');
  await expect(page.getByTestId('error')).toContainText('Could not load the dashboard.');
  await page.unroute('**/api/v1/stats/summary*');
  await page.getByRole('button', { name: 'Retry' }).click();
  await expect(page.locator('[data-tile="queries"]')).toBeVisible();
});

test('offline: going offline shows the banner and coming back removes it', async ({
  page,
  context,
}) => {
  await page.goto('/dashboard');
  await expect(heading(page, 'Dashboard')).toBeVisible();
  await context.setOffline(true);
  await expect(page.getByRole('img', { name: 'Nox is offline' })).toBeVisible();
  await expect(page.getByText('You are offline. Changes will not load')).toBeVisible();
  await context.setOffline(false);
  await expect(page.getByRole('img', { name: 'Nox is offline' })).toHaveCount(0);
});

test('not-found: an unknown zone and an unknown route use the not-found mascot', async ({
  page,
}) => {
  await page.goto('/zones/nope.invalid.');
  await expect(page.getByRole('img', { name: 'Nox could not find the page' })).toBeVisible();
  await page.goto('/definitely/not/here');
  await expect(page.getByRole('img', { name: 'Nox could not find the page' })).toBeVisible();
});

test('success: saving a record shows the success mascot', async ({ page, freshServer }) => {
  // Zone edits show the success mascot; use a private server so nothing is shared.
  const s = await freshServer();
  const api = await sessionFor(page, s.baseURL);
  await api.ok('post', '/zones', {
    name: 'ok.test.',
    default_ttl: 300,
    soa: {
      mname: 'ns1.ok.test.',
      rname: 'h.ok.test.',
      refresh: 3600,
      retry: 600,
      expire: 1209600,
      minimum: 300,
    },
    records: [{ name: '@', type: 'NS', value: 'ns1.ok.test.' }],
  });
  await page.goto(`${s.baseURL}/zones/ok.test.`);
  await page.getByRole('button', { name: 'Add record' }).first().click();
  const form = page.getByRole('form', { name: 'New record' });
  await form.getByLabel('Name').fill('www');
  await form.getByLabel('Type').selectOption('A');
  await form.getByLabel('Value').fill('192.0.2.5');
  await form.getByRole('button', { name: 'Save' }).click();
  await expect(page.getByRole('img', { name: 'Nox reports success' })).toBeVisible();
});
