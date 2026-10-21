import { query } from './support/dns';
import { expect, sessionFor, test } from './fixtures';

test('tiles count the DNS queries that were sent, including cache hits and blocks', async ({
  page,
  freshServer,
}) => {
  const s = await freshServer();
  const api = await sessionFor(page, s.baseURL);
  await api.ok('post', '/rules', { kind: 'block', domain: 'ads.example' });

  expect((await query(s.dnsPort, 'www.example.test')).ips).toEqual(['192.0.2.7']);
  await query(s.dnsPort, 'www.example.test');
  await query(s.dnsPort, 'www.example.test');
  expect((await query(s.dnsPort, 'ads.example')).ips).toEqual(['0.0.0.0']);

  await page.goto(`${s.baseURL}/dashboard`);
  await expect(async () => {
    await page.reload();
    await expect(page.locator('[data-tile="queries"]')).toContainText('4', { timeout: 2000 });
  }).toPass();
  await expect(page.locator('[data-tile="blocked"]')).toContainText('1 queries');
  await expect(page.locator('[data-tile="cache-hit"]')).not.toHaveText(/^\s*Cache hit ratio\s*-/);
  await expect(page.locator('[data-tile="dnssec-bogus"]')).toContainText('0');
  await expect(page.getByRole('heading', { name: 'Top domains' })).toBeVisible();
  await expect(page.getByText('www.example.test').first()).toBeVisible();
  await expect(page.getByTestId('chart')).toBeVisible();
  await page.getByTestId('toggle-table').click();
  await expect(page.getByTestId('chart-table')).toBeVisible();
});

test('a fresh server shows the empty state; pause and range controls work', async ({
  page,
  freshServer,
}) => {
  const s = await freshServer();
  await sessionFor(page, s.baseURL);
  await page.goto(`${s.baseURL}/dashboard`);
  await expect(page.getByTestId('empty')).toContainText('No queries in this range yet.');
  await page.getByTestId('pause').click();
  await expect(page.getByTestId('pause')).toHaveText('Resume');
  const week = page.getByRole('button', { name: '7d', exact: true });
  await week.click();
  await expect(week).toHaveAttribute('aria-pressed', 'true');
});
