import { query } from './support/dns';
import { expect, heading, roleState, sessionFor, test } from './fixtures';

test('filters narrow the log; the drawer shows the record; reset restores it', async ({
  page,
  freshServer,
}) => {
  const s = await freshServer();
  const api = await sessionFor(page, s.baseURL);
  await api.ok('post', '/rules', { kind: 'block', domain: 'tracker.example' });
  await query(s.dnsPort, 'alpha.example.test');
  await query(s.dnsPort, 'beta.example.test');
  await query(s.dnsPort, 'tracker.example');
  await query(s.dnsPort, 'nx.example.test');

  await page.goto(`${s.baseURL}/query-log`);
  const rows = page.getByRole('table').getByRole('row');
  await expect(async () => {
    await page.getByRole('button', { name: 'Reset' }).click();
    await expect(rows).toHaveCount(5, { timeout: 1500 }); // header + 4
  }).toPass();

  await page.getByLabel('Domain contains').fill('alpha');
  await page.getByRole('button', { name: 'Apply' }).click();
  await expect(rows).toHaveCount(2);
  await expect(page.getByRole('button', { name: 'Details for alpha.example.test' })).toBeVisible();

  await page.getByRole('button', { name: 'Reset' }).click();
  await page.getByLabel('Outcome').selectOption('blocked');
  await page.getByRole('button', { name: 'Apply' }).click();
  await expect(rows).toHaveCount(2);
  await expect(rows.nth(1)).toContainText('tracker.example');
  await expect(rows.nth(1)).toContainText('Blocked');

  await page.getByRole('button', { name: 'Reset' }).click();
  await page.getByLabel('Response code').selectOption('NXDOMAIN');
  await page.getByRole('button', { name: 'Apply' }).click();
  await expect(rows).toHaveCount(2);
  await expect(rows.nth(1)).toContainText('nx.example.test');

  await page.getByRole('button', { name: 'Details for nx.example.test' }).click();
  const drawer = page.getByRole('dialog', { name: 'nx.example.test' });
  await expect(drawer).toContainText('NXDOMAIN');
  await expect(drawer).toContainText('127.0.0.1');
  await page.keyboard.press('Escape');
  await expect(drawer).toBeHidden();
});

test('a filter with no match shows the empty mascot', async ({ page }) => {
  await page.goto('/query-log');
  await page.getByLabel('Domain contains').fill(`nothing-${Date.now()}.invalid`);
  await page.getByRole('button', { name: 'Apply' }).click();
  await expect(page.getByText('No queries match these filters.')).toBeVisible();
});

test('live tail shows new queries as they arrive and pause holds them back', async ({
  page,
  freshServer,
}) => {
  const s = await freshServer();
  await sessionFor(page, s.baseURL);
  await page.goto(`${s.baseURL}/query-log`);
  await expect(page.getByText('No queries match these filters.')).toBeVisible();
  const tail = page.getByRole('button', { name: /Live tail/ });
  await tail.click();
  await expect(tail).toHaveText('Live tail on');
  await expect(page.getByRole('status').filter({ hasText: 'Live' })).toBeVisible();

  await expect(async () => {
    await query(s.dnsPort, 'live-one.example.test');
    await expect(
      page.getByRole('button', { name: 'Details for live-one.example.test' }).first(),
    ).toBeVisible({ timeout: 1500 });
  }).toPass();

  await page.getByRole('button', { name: 'Pause' }).click();
  await query(s.dnsPort, 'held-back.example.test');
  await expect(page.getByText(/Paused: \d+ new quer/)).toBeVisible();
  await expect(
    page.getByRole('button', { name: 'Details for held-back.example.test' }),
  ).toHaveCount(0);
  await page.getByRole('button', { name: 'Resume' }).click();
  await expect(
    page.getByRole('button', { name: 'Details for held-back.example.test' }),
  ).toBeVisible();
  await tail.click();
  await expect(tail).toHaveText('Live tail off');
});

test.describe('viewer', () => {
  test.use({ storageState: roleState('viewer') });

  test('can read the log but live tail is disabled', async ({ page }) => {
    await page.goto('/query-log');
    await expect(heading(page, 'Query log')).toBeVisible();
    await expect(page.getByRole('button', { name: /Live tail/ })).toBeDisabled();
  });
});
